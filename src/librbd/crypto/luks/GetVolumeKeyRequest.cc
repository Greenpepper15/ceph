// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#include "GetVolumeKeyRequest.h"

#include "include/compat.h"
#include "common/dout.h"
#include "common/errno.h"
#include "librbd/ImageCtx.h"
#include "librbd/Utils.h"
#include "librbd/crypto/luks/ReadHeaderRequest.h"

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::crypto::luks::GetVolumeKeyRequest: " \
                           << this << " " << __func__ << ": "

namespace librbd {
namespace crypto {
namespace luks {

using librbd::util::create_context_callback;

template <typename I>
GetVolumeKeyRequest<I>::GetVolumeKeyRequest(
        I* image_ctx, std::string_view passphrase, size_t max_size,
        std::string* volume_key, size_t* key_size, int* keyslot,
        Context* on_finish) : m_image_ctx(image_ctx),
                              m_passphrase(passphrase),
                              m_max_size(max_size),
                              m_volume_key(volume_key),
                              m_key_size(key_size),
                              m_keyslot(keyslot),
                              m_on_finish(on_finish),
                              m_area(image_ctx->encryption_format ?
                                       io::ImageArea::CRYPTO_HEADER :
                                       io::ImageArea::DATA),
                              m_header(image_ctx->cct) {
}

template <typename I>
void GetVolumeKeyRequest<I>::send() {
  auto ctx = create_context_callback<
          GetVolumeKeyRequest<I>,
          &GetVolumeKeyRequest<I>::handle_read_header>(this);
  auto req = ReadHeaderRequest<I>::create(
          m_image_ctx, m_area, RBD_ENCRYPTION_FORMAT_LUKS,
          false /* keyslots are read lazily, in unlock() */, &m_header,
          &m_offset, nullptr, nullptr, nullptr, ctx);
  req->send();
}

template <typename I>
void GetVolumeKeyRequest<I>::handle_read_header(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    finish(r);
    return;
  }

  auto key_size = m_header.get_volume_key_size();
  if (key_size <= 0) {
    lderr(m_image_ctx->cct) << "unexpected volume key size " << key_size
                            << dendl;
    finish(-EINVAL);
    return;
  }
  *m_key_size = key_size;
  if (static_cast<size_t>(key_size) > m_max_size) {
    finish(-ERANGE);
    return;
  }

  m_image_ctx->image_lock.lock_shared();
  uint64_t image_size = m_image_ctx->get_image_size(m_image_ctx->snap_id);
  m_image_ctx->image_lock.unlock_shared();
  if (m_header.get_data_offset() > image_size) {
    lderr(m_image_ctx->cct) << "image is too small, data offset "
                            << m_header.get_data_offset() << dendl;
    finish(-EINVAL);
    return;
  }

  unlock();
}

template <typename I>
void GetVolumeKeyRequest<I>::unlock() {
  // the key lands in the caller's string, which the API layer zeroes
  // once it is copied out
  m_volume_key->assign(*m_key_size, '\0');
  size_t size = m_volume_key->size();
  auto r = m_header.unlock_keyslot(CRYPT_ANY_SLOT, m_passphrase.data(),
                                   m_passphrase.size(), m_volume_key->data(),
                                   &size);
  if (r < 0) {
    ceph_memzero_s(m_volume_key->data(), m_volume_key->size(),
                   m_volume_key->size());
    m_volume_key->clear();

    auto data_offset = m_header.get_data_offset();
    if (m_offset < data_offset) {
      // perhaps the keyslot that opens lies beyond what was read: feed
      // the rest of the keyslot area and try once more, as image open does
      ldout(m_image_ctx->cct, 20) << "no keyslot opened with " << m_offset
                                  << " bytes fed, reading on to "
                                  << data_offset << dendl;
      auto ctx = create_context_callback<
              GetVolumeKeyRequest<I>,
              &GetVolumeKeyRequest<I>::handle_read_keyslots>(this);
      ReadHeaderRequest<I>::create_extend(m_image_ctx, m_area, &m_header,
                                          &m_offset, data_offset, ctx)->send();
      return;
    }

    if (r == -EPERM) {
      lderr(m_image_ctx->cct) << "passphrase unlocks no keyslot" << dendl;
    } else {
      lderr(m_image_ctx->cct) << "error unlocking a keyslot: "
                              << cpp_strerror(r) << dendl;
    }
    finish(r);
    return;
  }

  m_volume_key->resize(size);
  *m_keyslot = r;
  finish(0);
}

template <typename I>
void GetVolumeKeyRequest<I>::handle_read_keyslots(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    finish(r);
    return;
  }

  unlock();
}

template <typename I>
void GetVolumeKeyRequest<I>::finish(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  m_on_finish->complete(r);
  delete this;
}

} // namespace luks
} // namespace crypto
} // namespace librbd

template class librbd::crypto::luks::GetVolumeKeyRequest<librbd::ImageCtx>;
