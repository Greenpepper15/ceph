// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#include "HeaderRestoreRequest.h"

#include "common/dout.h"
#include "common/errno.h"
#include "librbd/ImageCtx.h"
#include "librbd/Utils.h"
#include "librbd/crypto/luks/Magic.h"
#include "librbd/io/AioCompletion.h"
#include "librbd/io/ImageDispatchSpec.h"
#include "librbd/io/ReadResult.h"

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::crypto::luks::HeaderRestoreRequest: " \
                           << this << " " << __func__ << ": "

namespace librbd {
namespace crypto {
namespace luks {

using librbd::util::create_context_callback;

template <typename I>
HeaderRestoreRequest<I>::HeaderRestoreRequest(
        I* image_ctx, std::string_view dump,
        Context* on_finish) : m_image_ctx(image_ctx),
                              m_dump(dump),
                              m_on_finish(on_finish),
                              m_area(image_ctx->encryption_format ?
                                       io::ImageArea::CRYPTO_HEADER :
                                       io::ImageArea::DATA),
                              m_header(image_ctx->cct),
                              m_backup(image_ctx->cct) {
}

template <typename I>
void HeaderRestoreRequest<I>::send() {
  if (m_image_ctx->snap_id != CEPH_NOSNAP || m_image_ctx->read_only) {
    lderr(m_image_ctx->cct) << "image is read-only" << dendl;
    finish(-EROFS);
    return;
  }
  if (m_dump.empty()) {
    lderr(m_image_ctx->cct) << "empty dump" << dendl;
    finish(-EINVAL);
    return;
  }

  m_image_ctx->image_lock.lock_shared();
  uint64_t image_size = m_image_ctx->get_image_size(CEPH_NOSNAP);
  m_image_ctx->image_lock.unlock_shared();
  if (m_dump.size() > image_size) {
    lderr(m_image_ctx->cct) << "dump of " << m_dump.size()
                            << " bytes does not fit the image" << dendl;
    finish(-EINVAL);
    return;
  }

  ldout(m_image_ctx->cct, 20) << "length=" << m_dump.size() << " area="
                              << m_area << dendl;
  auto ctx = create_context_callback<
          HeaderRestoreRequest<I>,
          &HeaderRestoreRequest<I>::handle_read_image>(this);
  auto aio_comp = io::AioCompletion::create_and_start(
          ctx, librbd::util::get_image_ctx(m_image_ctx), io::AIO_TYPE_READ);
  ZTracer::Trace trace;
  auto req = io::ImageDispatchSpec::create_read(
          *m_image_ctx, io::IMAGE_DISPATCH_LAYER_API_START, aio_comp,
          {{0, m_dump.size()}}, m_area, io::ReadResult{&m_bl},
          m_image_ctx->get_data_io_context(), 0, 0, trace);
  req->send();
}

template <typename I>
void HeaderRestoreRequest<I>::handle_read_image(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    lderr(m_image_ctx->cct) << "error reading from image: " << cpp_strerror(r)
                            << dendl;
    finish(r);
    return;
  }

  r = restore();
  if (r < 0) {
    finish(r);
    return;
  }

  ldout(m_image_ctx->cct, 20) << "writing " << m_bl.length() << " bytes"
                              << dendl;
  auto ctx = create_context_callback<
          HeaderRestoreRequest<I>,
          &HeaderRestoreRequest<I>::handle_write>(this);
  auto aio_comp = io::AioCompletion::create_and_start(
          ctx, librbd::util::get_image_ctx(m_image_ctx), io::AIO_TYPE_WRITE);
  ZTracer::Trace trace;
  auto req = io::ImageDispatchSpec::create_write(
          *m_image_ctx, io::IMAGE_DISPATCH_LAYER_API_START, aio_comp,
          {{0, m_bl.length()}}, m_area, std::move(m_bl), 0, trace);
  req->send();
}

template <typename I>
int HeaderRestoreRequest<I>::restore() {
  auto cct = m_image_ctx->cct;

  // the dump into its own anonymous file, which libcryptsetup reads as the
  // backup file
  ceph::bufferlist dump_bl;
  dump_bl.append(m_dump.data(), m_dump.size());
  auto r = m_backup.init();
  if (r < 0) {
    return r;
  }
  r = m_backup.write(dump_bl);
  if (r < 0) {
    return r;
  }

  // the magic to put back afterwards: what the stored bytes carried while
  // their magic is intact, and format's rule, a parent means the clone
  // magic, once it is not
  bool stored_luks = Magic::is_luks(m_bl) > 0;
  bool stored_clone = Magic::is_rbd_clone(m_bl) > 0;
  bool apply_clone_magic =
          stored_clone || (!stored_luks && m_image_ctx->parent != nullptr);

  // the image's current bytes into the staged file, whatever state they
  // are in, with the clone magic normalized so that libcryptsetup can
  // compare a header that still loads; a header too damaged for that is
  // staged as it is, and libcryptsetup replaces it without conditions
  if (stored_clone) {
    r = Magic::replace_magic(cct, m_bl);
    if (r < 0) {
      ldout(cct, 5) << "rbd clone magic not replaced in the stored header: "
                    << cpp_strerror(r) << dendl;
    }
  }
  r = m_header.init();
  if (r < 0) {
    return r;
  }
  r = m_header.write(m_bl);
  if (r < 0) {
    return r;
  }

  r = m_header.restore(m_backup.get_path().c_str());
  if (r < 0) {
    return r;
  }

  // the restored bytes, with the clone magic re-applied where it belongs
  ceph::bufferlist restored;
  r = m_header.read(&restored, 0, m_dump.size());
  if (r < 0) {
    return r;
  } else if (static_cast<size_t>(r) != m_dump.size()) {
    lderr(cct) << "short read of the restored header: " << r << dendl;
    return -EIO;
  }
  if (apply_clone_magic) {
    r = Magic::replace_magic(cct, restored);
    if (r < 0) {
      lderr(cct) << "error restoring rbd clone magic: " << cpp_strerror(r)
                 << dendl;
      return r;
    }
  }

  m_bl = std::move(restored);
  return 0;
}

template <typename I>
void HeaderRestoreRequest<I>::handle_write(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    lderr(m_image_ctx->cct) << "error writing header to image: "
                            << cpp_strerror(r) << dendl;
    finish(r);
    return;
  }

  auto ctx = create_context_callback<
          HeaderRestoreRequest<I>,
          &HeaderRestoreRequest<I>::handle_flush>(this);
  auto aio_comp = io::AioCompletion::create_and_start(
          ctx, librbd::util::get_image_ctx(m_image_ctx), io::AIO_TYPE_FLUSH);
  auto req = io::ImageDispatchSpec::create_flush(
          *m_image_ctx, io::IMAGE_DISPATCH_LAYER_INTERNAL_START, aio_comp,
          io::FLUSH_SOURCE_INTERNAL, {});
  req->send();
}

template <typename I>
void HeaderRestoreRequest<I>::handle_flush(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    lderr(m_image_ctx->cct) << "unable to flush image: " << cpp_strerror(r)
                            << dendl;
  }

  finish(r);
}

template <typename I>
void HeaderRestoreRequest<I>::finish(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  m_on_finish->complete(r);
  delete this;
}

} // namespace luks
} // namespace crypto
} // namespace librbd

template class librbd::crypto::luks::HeaderRestoreRequest<librbd::ImageCtx>;
