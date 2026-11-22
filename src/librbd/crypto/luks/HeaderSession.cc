// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#include "HeaderSession.h"

#include <algorithm>
#include "include/compat.h"
#include "common/dout.h"
#include "common/errno.h"
#include "librbd/ImageCtx.h"
#include "librbd/Utils.h"
#include "librbd/crypto/luks/Magic.h"
#include "librbd/crypto/luks/ReadHeaderRequest.h"
#include "librbd/io/AioCompletion.h"
#include "librbd/io/ImageDispatchSpec.h"

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::crypto::luks::HeaderSession: " \
                           << this << " " << __func__ << ": "

namespace librbd {
namespace crypto {
namespace luks {

namespace {

// granularity of the write-back diff, as in UpdateHeaderRequest
const uint64_t DIFF_CHUNK_SIZE = 4096;

} // anonymous namespace

using librbd::util::create_context_callback;

template <typename I>
HeaderSession<I>::HeaderSession(I* image_ctx)
  : m_image_ctx(image_ctx),
    m_area(image_ctx->encryption_format ? io::ImageArea::CRYPTO_HEADER :
                                          io::ImageArea::DATA),
    m_header(image_ctx->cct) {
}

template <typename I>
void HeaderSession<I>::open(int* fd, Context* on_finish) {
  m_fd = fd;
  m_on_finish = on_finish;

  auto ctx = create_context_callback<
          HeaderSession<I>, &HeaderSession<I>::handle_read_header>(this);
  auto req = ReadHeaderRequest<I>::create(
          m_image_ctx, m_area, RBD_ENCRYPTION_FORMAT_LUKS,
          true /* the caller may change any part of the keyslot area */,
          &m_header, nullptr, &m_orig_bl, &m_clone_magic, nullptr, ctx);
  req->send();
}

template <typename I>
void HeaderSession<I>::handle_read_header(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    finish(r);
    return;
  }

  m_data_offset = m_header.get_data_offset();
  r = m_header.dup_fd();
  if (r < 0) {
    finish(r);
    return;
  }

  *m_fd = r;
  finish(0);
}

template <typename I>
void HeaderSession<I>::commit(Context* on_finish) {
  m_on_finish = on_finish;

  if (m_image_ctx->snap_id != CEPH_NOSNAP || m_image_ctx->read_only) {
    lderr(m_image_ctx->cct) << "image is read-only" << dendl;
    finish(-EROFS);
    return;
  }

  // the encryption may have been loaded on this handle since open()
  m_area = m_image_ctx->encryption_format ? io::ImageArea::CRYPTO_HEADER :
                                            io::ImageArea::DATA;

  auto r = compute_writes();
  if (r < 0) {
    finish(r);
    return;
  }

  if (m_pending_writes.empty()) {
    ldout(m_image_ctx->cct, 20) << "header unchanged" << dendl;
    finish(0);
    return;
  }

  m_write_index = 0;
  write_next();
}

template <typename I>
int HeaderSession<I>::compute_writes() {
  auto cct = m_image_ctx->cct;
  m_pending_writes.clear();

  // the caller changed the file through its own libcryptsetup context.
  // Only the header area is written back, so a header that moved the data
  // offset or a tool that wrote beyond it is refused.
  auto r = m_header.reload();
  if (r < 0) {
    lderr(cct) << "the staged header does not load" << dendl;
    return -EINVAL;
  }
  if (m_header.get_data_offset() != m_data_offset) {
    lderr(cct) << "the data offset changed from " << m_data_offset << " to "
               << m_header.get_data_offset() << dendl;
    return -EINVAL;
  }
  r = m_header.has_data_from(m_data_offset);
  if (r < 0) {
    return r;
  } else if (r > 0) {
    lderr(cct) << "the staged file was changed beyond the header area"
               << dendl;
    return -EINVAL;
  }

  ceph_assert(m_orig_bl.length() >= m_data_offset);
  m_new_bl.clear();
  r = m_header.read(&m_new_bl, 0, m_data_offset);
  if (r < 0) {
    return r;
  } else if (static_cast<uint64_t>(r) != m_data_offset) {
    lderr(cct) << "short read of the staged header: " << r << dendl;
    return -EIO;
  }

  if (m_clone_magic) {
    r = Magic::replace_magic(cct, m_new_bl);
    if (r < 0) {
      lderr(cct) << "error restoring rbd clone magic: " << cpp_strerror(r)
                 << dendl;
      return r;
    }
  }

  const char* orig = m_orig_bl.c_str();
  const char* updated = m_new_bl.c_str();
  for (uint64_t offset = 0; offset < m_data_offset;
       offset += DIFF_CHUNK_SIZE) {
    auto chunk = std::min(DIFF_CHUNK_SIZE, m_data_offset - offset);
    if (memcmp(orig + offset, updated + offset, chunk) == 0) {
      continue;
    }

    if (m_pending_writes.empty() ||
        m_pending_writes.back().first + m_pending_writes.back().second.length()
          != offset) {
      m_pending_writes.emplace_back(offset, ceph::bufferlist{});
    }
    m_pending_writes.back().second.append(updated + offset, chunk);
  }

  ldout(cct, 20) << m_pending_writes.size() << " changed range(s)" << dendl;
  return 0;
}

template <typename I>
void HeaderSession<I>::write_next() {
  ceph_assert(m_write_index < m_pending_writes.size());
  auto& [offset, bl] = m_pending_writes[m_write_index];
  ldout(m_image_ctx->cct, 20) << "offset=" << offset << " length="
                              << bl.length() << dendl;

  auto ctx = create_context_callback<
          HeaderSession<I>, &HeaderSession<I>::handle_write>(this);
  // not started here: the core layer marks the write as in flight, so a
  // write that waits for the exclusive lock does not block a lock release
  auto aio_comp = io::AioCompletion::create(ctx);
  aio_comp->init_time(librbd::util::get_image_ctx(m_image_ctx),
                      io::AIO_TYPE_WRITE);

  ceph::bufferlist write_bl = bl;
  ZTracer::Trace trace;
  auto req = io::ImageDispatchSpec::create_write(
          *m_image_ctx, io::IMAGE_DISPATCH_LAYER_API_START, aio_comp,
          {{offset, write_bl.length()}}, m_area, std::move(write_bl), 0,
          trace);
  req->send();
}

template <typename I>
void HeaderSession<I>::handle_write(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    lderr(m_image_ctx->cct) << "error writing header to image: "
                            << cpp_strerror(r) << dendl;
    finish(r);
    return;
  }

  if (++m_write_index < m_pending_writes.size()) {
    write_next();
    return;
  }

  flush();
}

template <typename I>
void HeaderSession<I>::flush() {
  auto ctx = create_context_callback<
          HeaderSession<I>, &HeaderSession<I>::handle_flush>(this);
  auto aio_comp = io::AioCompletion::create_and_start(
          ctx, librbd::util::get_image_ctx(m_image_ctx), io::AIO_TYPE_FLUSH);
  auto req = io::ImageDispatchSpec::create_flush(
          *m_image_ctx, io::IMAGE_DISPATCH_LAYER_INTERNAL_START, aio_comp,
          io::FLUSH_SOURCE_INTERNAL, {});
  req->send();
}

template <typename I>
void HeaderSession<I>::handle_flush(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    lderr(m_image_ctx->cct) << "unable to flush image: " << cpp_strerror(r)
                            << dendl;
    finish(r);
    return;
  }

  // a later commit of this session diffs against what the image holds now
  m_orig_bl = std::move(m_new_bl);
  m_new_bl.clear();
  finish(0);
}

template <typename I>
void HeaderSession<I>::finish(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  auto on_finish = m_on_finish;
  m_on_finish = nullptr;
  on_finish->complete(r);
}

} // namespace luks
} // namespace crypto
} // namespace librbd

template class librbd::crypto::luks::HeaderSession<librbd::ImageCtx>;
