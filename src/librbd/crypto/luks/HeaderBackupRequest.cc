// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#include "HeaderBackupRequest.h"

#include "common/dout.h"
#include "common/errno.h"
#include "librbd/ImageCtx.h"
#include "librbd/Utils.h"
#include "librbd/crypto/luks/ReadHeaderRequest.h"

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::crypto::luks::HeaderBackupRequest: " \
                           << this << " " << __func__ << ": "

namespace librbd {
namespace crypto {
namespace luks {

using librbd::util::create_context_callback;

template <typename I>
HeaderBackupRequest<I>::HeaderBackupRequest(
        I* image_ctx, size_t max_size, std::string* dump, size_t* dump_size,
        Context* on_finish) : m_image_ctx(image_ctx),
                              m_max_size(max_size),
                              m_dump(dump),
                              m_dump_size(dump_size),
                              m_on_finish(on_finish),
                              m_area(image_ctx->encryption_format ?
                                       io::ImageArea::CRYPTO_HEADER :
                                       io::ImageArea::DATA),
                              m_header(image_ctx->cct) {
}

template <typename I>
void HeaderBackupRequest<I>::send() {
  auto ctx = create_context_callback<
          HeaderBackupRequest<I>,
          &HeaderBackupRequest<I>::handle_read_header>(this);
  auto req = ReadHeaderRequest<I>::create(
          m_image_ctx, m_area, RBD_ENCRYPTION_FORMAT_LUKS,
          true /* the dump is the whole header area */, &m_header, nullptr,
          nullptr, nullptr, nullptr, ctx);
  req->send();
}

template <typename I>
void HeaderBackupRequest<I>::handle_read_header(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    finish(r);
    return;
  }

  auto size = m_header.get_data_offset();
  *m_dump_size = size;
  if (size > m_max_size) {
    finish(-ERANGE);
    return;
  }

  // libcryptsetup's own backup needs a file it creates itself, so the
  // dump is copied out of the anonymous file instead; it starts with the
  // header libcryptsetup loaded, which its restore reads back
  ceph::bufferlist bl;
  r = m_header.read(&bl, 0, size);
  if (r < 0) {
    finish(r);
    return;
  } else if (static_cast<uint64_t>(r) != size) {
    lderr(m_image_ctx->cct) << "short read of the header: " << r << dendl;
    finish(-EIO);
    return;
  }

  m_dump->assign(bl.c_str(), bl.length());
  finish(0);
}

template <typename I>
void HeaderBackupRequest<I>::finish(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  m_on_finish->complete(r);
  delete this;
}

} // namespace luks
} // namespace crypto
} // namespace librbd

template class librbd::crypto::luks::HeaderBackupRequest<librbd::ImageCtx>;
