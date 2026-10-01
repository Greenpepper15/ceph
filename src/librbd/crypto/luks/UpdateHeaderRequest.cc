// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#include "UpdateHeaderRequest.h"

#include <algorithm>
#include "include/compat.h"
#include "common/dout.h"
#include "common/errno.h"
#include "librbd/ImageCtx.h"
#include "librbd/Utils.h"
#include "librbd/crypto/luks/Magic.h"
#include "librbd/io/AioCompletion.h"
#include "librbd/io/ImageDispatchSpec.h"

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::crypto::luks::UpdateHeaderRequest: " \
                           << this << " " << __func__ << ": "

namespace librbd {
namespace crypto {
namespace luks {

namespace {

// granularity of the write-back diff: the LUKS2 block size, a multiple of
// the LUKS1 block size of 512 bytes
const uint64_t DIFF_CHUNK_SIZE = 4096;

} // anonymous namespace

using librbd::util::create_context_callback;

template <typename I>
UpdateHeaderRequest<I>::UpdateHeaderRequest(
        I* image_ctx, KeyslotOp op, int keyslot,
        Context* on_finish) : m_image_ctx(image_ctx),
                              m_op(op),
                              m_keyslot(keyslot),
                              m_on_finish(on_finish),
                              m_area(image_ctx->encryption_format ?
                                       io::ImageArea::CRYPTO_HEADER :
                                       io::ImageArea::DATA),
                              m_header(image_ctx->cct) {
}

template <typename I>
void UpdateHeaderRequest<I>::send() {
  if (m_image_ctx->snap_id != CEPH_NOSNAP || m_image_ctx->read_only) {
    lderr(m_image_ctx->cct) << "image is read-only" << dendl;
    finish(-EROFS);
    return;
  }

  auto ctx = create_context_callback<
          UpdateHeaderRequest<I>,
          &UpdateHeaderRequest<I>::handle_read_header>(this);
  auto req = ReadHeaderRequest<I>::create(
          m_image_ctx, m_area, RBD_ENCRYPTION_FORMAT_LUKS,
          true /* the operation and the diff need the whole keyslot area */,
          &m_header, nullptr, &m_orig_bl, &m_clone_magic, nullptr, ctx);
  req->send();
}

template <typename I>
void UpdateHeaderRequest<I>::handle_read_header(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    finish(r);
    return;
  }

  modify();
}

template <typename I>
void UpdateHeaderRequest<I>::modify() {
  int r = -EINVAL;
  switch (m_op) {
  case KeyslotOp::ADD:
    r = add_keyslot();
    break;
  case KeyslotOp::REMOVE:
    r = remove_keyslot();
    break;
  }
  if (r < 0) {
    finish(r);
    return;
  }

  r = compute_writes();
  if (r < 0) {
    finish(r);
    return;
  }

  if (m_pending_writes.empty()) {
    ldout(m_image_ctx->cct, 20) << "header unchanged" << dendl;
    finish(0);
    return;
  }

  write_next();
}

template <typename I>
int UpdateHeaderRequest<I>::add_keyslot() {
  auto cct = m_image_ctx->cct;
  if (m_keyslot == CRYPT_ANY_SLOT) {
    if (!has_free_keyslot()) {
      lderr(cct) << "no free keyslot" << dendl;
      return -ENOSPC;
    }
  } else {
    switch (m_header.get_keyslot_status(m_keyslot)) {
    case CRYPT_SLOT_INVALID:
      lderr(cct) << "invalid keyslot " << m_keyslot << dendl;
      return -EINVAL;
    case CRYPT_SLOT_INACTIVE:
      break;
    default:
      lderr(cct) << "keyslot " << m_keyslot << " is in use" << dendl;
      return -EEXIST;
    }
  }

  // the caller's KDF settings, or a copy of those of the lowest keyslot in
  // use, instead of benchmarking this host
  struct crypt_pbkdf_type pbkdf = {};
  int r;
  if (m_kdf) {
    pbkdf.type = m_kdf->kdf.c_str();
    pbkdf.hash = m_kdf->hash.empty() ? nullptr : m_kdf->hash.c_str();
    pbkdf.iterations = m_kdf->iterations;
    pbkdf.max_memory_kb = m_kdf->memory_kb;
    pbkdf.parallel_threads = m_kdf->threads;
  } else {
    auto active = lowest_active_keyslot();
    if (active < 0) {
      lderr(cct) << "no keyslot in use to copy the KDF settings from, "
                 << "KDF settings required" << dendl;
      return -EINVAL;
    }
    r = m_header.get_keyslot_pbkdf(active, &pbkdf);
    if (r < 0) {
      return r;
    }
  }
  pbkdf.flags = CRYPT_PBKDF_NO_BENCHMARK;
  r = m_header.set_pbkdf(&pbkdf);
  if (r < 0) {
    return r;
  }

  // libcryptsetup checks the key against the data's digest before it
  // stores anything
  r = m_header.add_keyslot_by_volume_key(
          m_keyslot, m_volume_key.data(), m_volume_key.size(),
          m_passphrase.data(), m_passphrase.size());
  if (r < 0) {
    return r;
  }

  *m_result_keyslot = r;
  return 0;
}

template <typename I>
int UpdateHeaderRequest<I>::remove_keyslot() {
  auto cct = m_image_ctx->cct;
  switch (m_header.get_keyslot_status(m_keyslot)) {
  case CRYPT_SLOT_INVALID:
    lderr(cct) << "invalid keyslot " << m_keyslot << dendl;
    return -EINVAL;
  case CRYPT_SLOT_INACTIVE:
    lderr(cct) << "keyslot " << m_keyslot << " is not in use" << dendl;
    return -ENOENT;
  case CRYPT_SLOT_ACTIVE_LAST:
    lderr(cct) << "refusing to remove the last keyslot bound to the data"
               << dendl;
    return -EBUSY;
  default:
    break;
  }

  // the key material is overwritten with random data in the anonymous
  // file, and the write-back carries that
  return m_header.destroy_keyslot(m_keyslot);
}

template <typename I>
bool UpdateHeaderRequest<I>::has_free_keyslot() {
  auto max = m_header.get_keyslot_max();
  for (int slot = 0; slot < max; ++slot) {
    if (m_header.get_keyslot_status(slot) == CRYPT_SLOT_INACTIVE) {
      return true;
    }
  }
  return false;
}

template <typename I>
int UpdateHeaderRequest<I>::lowest_active_keyslot() {
  auto max = m_header.get_keyslot_max();
  for (int slot = 0; slot < max; ++slot) {
    auto status = m_header.get_keyslot_status(slot);
    if (status == CRYPT_SLOT_ACTIVE || status == CRYPT_SLOT_ACTIVE_LAST) {
      return slot;
    }
  }
  return -1;
}

template <typename I>
int UpdateHeaderRequest<I>::compute_writes() {
  auto length = m_header.get_data_offset();
  ceph_assert(m_orig_bl.length() >= length);

  ceph::bufferlist new_bl;
  auto r = m_header.read(&new_bl, 0, length);
  if (r < 0) {
    return r;
  } else if (static_cast<uint64_t>(r) != length) {
    lderr(m_image_ctx->cct) << "short read of modified header: " << r << dendl;
    return -EIO;
  }

  if (m_clone_magic) {
    r = Magic::replace_magic(m_image_ctx->cct, new_bl);
    if (r < 0) {
      lderr(m_image_ctx->cct) << "error restoring rbd clone magic: "
                              << cpp_strerror(r) << dendl;
      return r;
    }
  }

  const char* orig = m_orig_bl.c_str();
  const char* updated = new_bl.c_str();
  for (uint64_t offset = 0; offset < length; offset += DIFF_CHUNK_SIZE) {
    auto chunk = std::min(DIFF_CHUNK_SIZE, length - offset);
    if (memcmp(orig + offset, updated + offset, chunk) == 0) {
      continue;
    }

    if (!m_pending_writes.empty() &&
        m_pending_writes.back().first + m_pending_writes.back().second.length()
          == offset) {
      m_pending_writes.back().second.append(updated + offset, chunk);
    } else {
      m_pending_writes.emplace_back(offset, ceph::bufferlist{});
      m_pending_writes.back().second.append(updated + offset, chunk);
    }
  }

  ldout(m_image_ctx->cct, 20) << m_pending_writes.size()
                              << " changed range(s)" << dendl;
  return 0;
}

template <typename I>
void UpdateHeaderRequest<I>::write_next() {
  ceph_assert(m_write_index < m_pending_writes.size());
  auto& [offset, bl] = m_pending_writes[m_write_index];
  ldout(m_image_ctx->cct, 20) << "offset=" << offset << " length="
                              << bl.length() << dendl;

  auto ctx = create_context_callback<
          UpdateHeaderRequest<I>, &UpdateHeaderRequest<I>::handle_write>(this);
  auto aio_comp = io::AioCompletion::create_and_start(
          ctx, librbd::util::get_image_ctx(m_image_ctx), io::AIO_TYPE_WRITE);

  ceph::bufferlist write_bl = bl;
  ZTracer::Trace trace;
  auto req = io::ImageDispatchSpec::create_write(
          *m_image_ctx, io::IMAGE_DISPATCH_LAYER_API_START, aio_comp,
          {{offset, write_bl.length()}}, m_area, std::move(write_bl), 0,
          trace);
  req->send();
}

template <typename I>
void UpdateHeaderRequest<I>::handle_write(int r) {
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
void UpdateHeaderRequest<I>::flush() {
  auto ctx = create_context_callback<
          UpdateHeaderRequest<I>, &UpdateHeaderRequest<I>::handle_flush>(this);
  auto aio_comp = io::AioCompletion::create_and_start(
          ctx, librbd::util::get_image_ctx(m_image_ctx), io::AIO_TYPE_FLUSH);
  auto req = io::ImageDispatchSpec::create_flush(
          *m_image_ctx, io::IMAGE_DISPATCH_LAYER_INTERNAL_START, aio_comp,
          io::FLUSH_SOURCE_INTERNAL, {});
  req->send();
}

template <typename I>
void UpdateHeaderRequest<I>::handle_flush(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    lderr(m_image_ctx->cct) << "unable to flush image: " << cpp_strerror(r)
                            << dendl;
  }

  finish(r);
}

template <typename I>
void UpdateHeaderRequest<I>::finish(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  m_on_finish->complete(r);
  delete this;
}

} // namespace luks
} // namespace crypto
} // namespace librbd

template class librbd::crypto::luks::UpdateHeaderRequest<librbd::ImageCtx>;
