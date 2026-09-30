// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#include "LoadRequest.h"

#include "common/dout.h"
#include "common/errno.h"
#include "librbd/Utils.h"
#include "librbd/crypto/Utils.h"

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::crypto::luks::LoadRequest: " << this \
                           << " " << __func__ << ": "

namespace librbd {
namespace crypto {
namespace luks {

using librbd::util::create_context_callback;

template <typename I>
LoadRequest<I>::LoadRequest(
        I* image_ctx, encryption_format_t format, std::string_view passphrase,
        std::unique_ptr<CryptoInterface>* result_crypto,
        std::string* detected_format_name,
        Context* on_finish) : m_image_ctx(image_ctx),
                              m_format(format),
                              m_passphrase(passphrase),
                              m_on_finish(on_finish),
                              m_result_crypto(result_crypto),
                              m_detected_format_name(detected_format_name),
                              m_initial_read_size(DEFAULT_INITIAL_READ_SIZE),
                              m_header(image_ctx->cct), m_offset(0) {
}

template <typename I>
void LoadRequest<I>::set_initial_read_size(uint64_t read_size) {
  m_initial_read_size = read_size;
}

template <typename I>
void LoadRequest<I>::send() {
  auto ctx = create_context_callback<
          LoadRequest<I>, &LoadRequest<I>::handle_read_header>(this);
  auto req = ReadHeaderRequest<I>::create(
          m_image_ctx, io::ImageArea::DATA, m_format,
          false /* keyslots are read lazily, in read_volume_key() */,
          &m_header, &m_offset, nullptr, nullptr, m_detected_format_name,
          ctx);
  req->set_initial_read_size(m_initial_read_size);
  req->send();
}

template <typename I>
void LoadRequest<I>::handle_read_header(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    finish(r);
    return;
  }

  // gets actual LUKS version (only used for logging)
  ceph_assert(*m_detected_format_name == "LUKS");
  *m_detected_format_name = m_header.get_format_name();

  auto cipher = m_header.get_cipher();
  if (strcmp(cipher, "aes") != 0) {
    lderr(m_image_ctx->cct) << "unsupported cipher: " << cipher << dendl;
    finish(-ENOTSUP);
    return;
  }

  auto cipher_mode = m_header.get_cipher_mode();
  if (strcmp(cipher_mode, "xts-plain64") != 0) {
    lderr(m_image_ctx->cct) << "unsupported cipher mode: " << cipher_mode
                            << dendl;
    finish(-ENOTSUP);
    return;
  }

  m_image_ctx->image_lock.lock_shared();
  uint64_t image_size = m_image_ctx->get_image_size(CEPH_NOSNAP);
  m_image_ctx->image_lock.unlock_shared();

  if (m_header.get_data_offset() > image_size) {
    lderr(m_image_ctx->cct) << "image is too small, data offset "
                            << m_header.get_data_offset() << dendl;
    finish(-EINVAL);
    return;
  }

  uint64_t stripe_period = m_image_ctx->get_stripe_period();
  if (m_header.get_data_offset() % stripe_period != 0) {
    lderr(m_image_ctx->cct) << "incompatible stripe pattern, data offset "
                            << m_header.get_data_offset() << dendl;
    finish(-EINVAL);
    return;
  }

  read_volume_key();
  return;
}

template <typename I>
void LoadRequest<I>::handle_read_keyslots(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    finish(r);
    return;
  }

  read_volume_key();
}

template <typename I>
void LoadRequest<I>::read_volume_key() {
  char volume_key[64];
  size_t volume_key_size = sizeof(volume_key);

  auto r = m_header.read_volume_key(
          m_passphrase.data(), m_passphrase.size(),
          reinterpret_cast<char*>(volume_key), &volume_key_size);
  if (r != 0) {
    auto keyslots_end_offset = m_header.get_data_offset();
    if (m_offset < keyslots_end_offset) {
      // perhaps we did not feed the necessary keyslot, retry
      auto ctx = create_context_callback<
              LoadRequest<I>, &LoadRequest<I>::handle_read_keyslots>(this);
      ReadHeaderRequest<I>::create_extend(
              m_image_ctx, io::ImageArea::DATA, &m_header, &m_offset,
              keyslots_end_offset, ctx)->send();
      return;
    }

    finish(r);
    return;
  }

  r = util::build_crypto(
          m_image_ctx->cct, reinterpret_cast<unsigned char*>(volume_key),
          volume_key_size, m_header.get_sector_size(),
          m_header.get_data_offset(), m_result_crypto);
  ceph_memzero_s(volume_key, 64, 64);
  finish(r);
}

template <typename I>
void LoadRequest<I>::finish(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;
  
  m_on_finish->complete(r);
  delete this;
}

} // namespace luks
} // namespace crypto
} // namespace librbd

template class librbd::crypto::luks::LoadRequest<librbd::ImageCtx>;
