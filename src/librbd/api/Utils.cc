// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#include "librbd/api/Utils.h"
#include "common/dout.h"

#if defined(HAVE_LIBCRYPTSETUP)
#include "librbd/crypto/luks/GetVolumeKeyRequest.h"
#include "librbd/crypto/luks/HeaderBackupRequest.h"
#include "librbd/crypto/luks/HeaderRestoreRequest.h"
#include "librbd/crypto/luks/LUKSEncryptionFormat.h"
#include "librbd/crypto/luks/ReadHeaderRequest.h"
#include "librbd/crypto/luks/UpdateHeaderRequest.h"
#endif

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::api::util: " << __func__ << ": "

namespace librbd {
namespace api {
namespace util {

template <typename I>
int create_encryption_format(
        CephContext* cct, encryption_format_t format,
        encryption_options_t opts, size_t opts_size, bool c_api,
        crypto::EncryptionFormat<I>** result_format) {
  size_t expected_opts_size;
  switch (format) {
#if defined(HAVE_LIBCRYPTSETUP)
    case RBD_ENCRYPTION_FORMAT_LUKS1: {
      if (c_api) {
        expected_opts_size = sizeof(rbd_encryption_luks1_format_options_t);
        if (expected_opts_size == opts_size) {
          auto c_opts = (rbd_encryption_luks1_format_options_t*)opts;
          *result_format = new crypto::luks::LUKS1EncryptionFormat<I>(
                  c_opts->alg, {c_opts->passphrase, c_opts->passphrase_size});
        }
      } else {
        expected_opts_size = sizeof(encryption_luks1_format_options_t);
        if (expected_opts_size == opts_size) {
          auto cpp_opts = (encryption_luks1_format_options_t*)opts;
          *result_format = new crypto::luks::LUKS1EncryptionFormat<I>(
                  cpp_opts->alg, cpp_opts->passphrase);
        }
      }
      break;
    }
    case RBD_ENCRYPTION_FORMAT_LUKS2: {
      if (c_api) {
        expected_opts_size = sizeof(rbd_encryption_luks2_format_options_t);
        if (expected_opts_size == opts_size) {
          auto c_opts = (rbd_encryption_luks2_format_options_t*)opts;
          *result_format = new crypto::luks::LUKS2EncryptionFormat<I>(
                  c_opts->alg, {c_opts->passphrase, c_opts->passphrase_size});
        }
      } else {
        expected_opts_size = sizeof(encryption_luks2_format_options_t);
        if (expected_opts_size == opts_size) {
          auto cpp_opts = (encryption_luks2_format_options_t*)opts;
          *result_format = new crypto::luks::LUKS2EncryptionFormat<I>(
                  cpp_opts->alg, cpp_opts->passphrase);
        }
      }
      break;
    }
    case RBD_ENCRYPTION_FORMAT_LUKS: {
      if (c_api) {
        expected_opts_size = sizeof(rbd_encryption_luks_format_options_t);
        if (expected_opts_size == opts_size) {
          auto c_opts = (rbd_encryption_luks_format_options_t*)opts;
          *result_format = new crypto::luks::LUKSEncryptionFormat<I>(
                  {c_opts->passphrase, c_opts->passphrase_size});
        }
      } else {
        expected_opts_size = sizeof(encryption_luks_format_options_t);
        if (expected_opts_size == opts_size) {
          auto cpp_opts = (encryption_luks_format_options_t*)opts;
          *result_format = new crypto::luks::LUKSEncryptionFormat<I>(
                  cpp_opts->passphrase);
        }
      }
      break;
    }
#endif
    default:
      lderr(cct) << "unsupported encryption format: " << format << dendl;
      return -ENOTSUP;
  }

  if (expected_opts_size != opts_size) {
    lderr(cct) << "expected opts_size: " << expected_opts_size << dendl;
    return -EINVAL;
  }

  return 0;
}

template <typename I>
void luks_volume_key_get(I* ictx, const void* opts, size_t opts_size,
                         bool c_api, size_t max_size, std::string* volume_key,
                         size_t* key_size, int* keyslot, Context* on_finish) {
#if defined(HAVE_LIBCRYPTSETUP)
  std::string_view passphrase;
  if (opts == nullptr) {
    lderr(ictx->cct) << "options missing" << dendl;
    on_finish->complete(-EINVAL);
    return;
  }
  size_t expected_opts_size;
  if (c_api) {
    expected_opts_size = sizeof(rbd_encryption_luks_volume_key_get_options_t);
    if (expected_opts_size == opts_size) {
      auto c_opts =
              (const rbd_encryption_luks_volume_key_get_options_t*)opts;
      passphrase = {c_opts->passphrase, c_opts->passphrase_size};
    }
  } else {
    expected_opts_size = sizeof(encryption_luks_volume_key_get_options_t);
    if (expected_opts_size == opts_size) {
      auto cpp_opts = (const encryption_luks_volume_key_get_options_t*)opts;
      passphrase = cpp_opts->passphrase;
    }
  }
  if (expected_opts_size != opts_size) {
    lderr(ictx->cct) << "expected opts_size: " << expected_opts_size << dendl;
    on_finish->complete(-EINVAL);
    return;
  }

  auto req = crypto::luks::GetVolumeKeyRequest<I>::create(
          ictx, passphrase, max_size, volume_key, key_size, keyslot,
          on_finish);
  req->send();
#else
  lderr(ictx->cct) << "LUKS keyslots require libcryptsetup" << dendl;
  on_finish->complete(-ENOTSUP);
#endif
}

template <typename I>
void luks_keyslot_add(I* ictx, const void* opts, size_t opts_size,
                      bool c_api, int* result_keyslot, Context* on_finish) {
#if defined(HAVE_LIBCRYPTSETUP)
  static_assert(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT == CRYPT_ANY_SLOT,
                "the keyslot is passed to libcryptsetup unchanged");
  int keyslot;
  std::string_view volume_key;
  std::string_view passphrase;
  crypto::luks::KdfSettings kdf;
  if (opts == nullptr) {
    lderr(ictx->cct) << "options missing" << dendl;
    on_finish->complete(-EINVAL);
    return;
  }
  size_t expected_opts_size;
  if (c_api) {
    expected_opts_size = sizeof(rbd_encryption_luks_keyslot_add_options_t);
    if (expected_opts_size == opts_size) {
      auto c_opts = (const rbd_encryption_luks_keyslot_add_options_t*)opts;
      keyslot = c_opts->keyslot;
      volume_key = {c_opts->volume_key, c_opts->volume_key_size};
      passphrase = {c_opts->passphrase, c_opts->passphrase_size};
      kdf = {c_opts->kdf ? c_opts->kdf : "", c_opts->hash ? c_opts->hash : "",
             c_opts->kdf_iterations, c_opts->kdf_memory_kb,
             c_opts->kdf_threads};
    }
  } else {
    expected_opts_size = sizeof(encryption_luks_keyslot_add_options_t);
    if (expected_opts_size == opts_size) {
      auto cpp_opts = (const encryption_luks_keyslot_add_options_t*)opts;
      keyslot = cpp_opts->keyslot;
      volume_key = cpp_opts->volume_key;
      passphrase = cpp_opts->passphrase;
      kdf = {cpp_opts->kdf, cpp_opts->hash, cpp_opts->kdf_iterations,
             cpp_opts->kdf_memory_kb, cpp_opts->kdf_threads};
    }
  }
  if (expected_opts_size != opts_size) {
    lderr(ictx->cct) << "expected opts_size: " << expected_opts_size << dendl;
    on_finish->complete(-EINVAL);
    return;
  }
  if (volume_key.empty()) {
    lderr(ictx->cct) << "volume key missing" << dendl;
    on_finish->complete(-EINVAL);
    return;
  }

  // the KDF settings are complete or absent
  std::optional<crypto::luks::KdfSettings> new_kdf;
  if (!kdf.kdf.empty()) {
    new_kdf = std::move(kdf);
  } else if (!kdf.hash.empty() || kdf.iterations != 0 ||
             kdf.memory_kb != 0 || kdf.threads != 0) {
    lderr(ictx->cct) << "KDF settings need a KDF" << dendl;
    on_finish->complete(-EINVAL);
    return;
  }

  auto req = crypto::luks::UpdateHeaderRequest<I>::create_add_keyslot(
          ictx, keyslot, volume_key, passphrase, std::move(new_kdf),
          result_keyslot, on_finish);
  req->send();
#else
  lderr(ictx->cct) << "LUKS keyslots require libcryptsetup" << dendl;
  on_finish->complete(-ENOTSUP);
#endif
}

template <typename I>
void luks_keyslot_remove(I* ictx, const void* opts, size_t opts_size,
                         bool c_api, Context* on_finish) {
#if defined(HAVE_LIBCRYPTSETUP)
  int keyslot;
  if (opts == nullptr) {
    lderr(ictx->cct) << "options missing" << dendl;
    on_finish->complete(-EINVAL);
    return;
  }
  size_t expected_opts_size;
  if (c_api) {
    expected_opts_size = sizeof(rbd_encryption_luks_keyslot_remove_options_t);
    if (expected_opts_size == opts_size) {
      auto c_opts = (const rbd_encryption_luks_keyslot_remove_options_t*)opts;
      keyslot = c_opts->keyslot;
    }
  } else {
    expected_opts_size = sizeof(encryption_luks_keyslot_remove_options_t);
    if (expected_opts_size == opts_size) {
      auto cpp_opts = (const encryption_luks_keyslot_remove_options_t*)opts;
      keyslot = cpp_opts->keyslot;
    }
  }
  if (expected_opts_size != opts_size) {
    lderr(ictx->cct) << "expected opts_size: " << expected_opts_size << dendl;
    on_finish->complete(-EINVAL);
    return;
  }

  auto req = crypto::luks::UpdateHeaderRequest<I>::create_remove_keyslot(
          ictx, keyslot, on_finish);
  req->send();
#else
  lderr(ictx->cct) << "LUKS keyslots require libcryptsetup" << dendl;
  on_finish->complete(-ENOTSUP);
#endif
}

template <typename I>
void luks_keyslot_list(
    I* ictx, std::vector<encryption_luks_keyslot_info_t>* keyslots,
    Context* on_finish) {
#if defined(HAVE_LIBCRYPTSETUP)
  // the metadata only, as image open reads it, and nothing written back:
  // a repair that libcryptsetup makes to an outdated copy stays in memory
  auto header = new crypto::luks::Header(ictx->cct);
  auto ctx = new LambdaContext([header, keyslots, on_finish](int r) {
      if (r == 0) {
        r = header->list_keyslots(keyslots);
      }
      delete header;
      on_finish->complete(r);
    });
  auto area = ictx->encryption_format ? io::ImageArea::CRYPTO_HEADER :
                                        io::ImageArea::DATA;
  auto req = crypto::luks::ReadHeaderRequest<I>::create(
          ictx, area, RBD_ENCRYPTION_FORMAT_LUKS, false, header, nullptr,
          nullptr, nullptr, nullptr, ctx);
  req->send();
#else
  lderr(ictx->cct) << "LUKS keyslots require libcryptsetup" << dendl;
  on_finish->complete(-ENOTSUP);
#endif
}

template <typename I>
void luks_header_dump(I* ictx, size_t max_size, std::string* dump,
                      size_t* dump_size, Context* on_finish) {
#if defined(HAVE_LIBCRYPTSETUP)
  auto req = crypto::luks::HeaderBackupRequest<I>::create(
          ictx, max_size, dump, dump_size, on_finish);
  req->send();
#else
  lderr(ictx->cct) << "LUKS keyslots require libcryptsetup" << dendl;
  on_finish->complete(-ENOTSUP);
#endif
}

template <typename I>
void luks_header_restore(I* ictx, std::string_view dump, Context* on_finish) {
#if defined(HAVE_LIBCRYPTSETUP)
  auto req = crypto::luks::HeaderRestoreRequest<I>::create(ictx, dump,
                                                           on_finish);
  req->send();
#else
  lderr(ictx->cct) << "LUKS keyslots require libcryptsetup" << dendl;
  on_finish->complete(-ENOTSUP);
#endif
}

} // namespace util
} // namespace api
} // namespace librbd

template int librbd::api::util::create_encryption_format(
    CephContext* cct, encryption_format_t format, encryption_options_t opts,
    size_t opts_size, bool c_api,
    crypto::EncryptionFormat<librbd::ImageCtx>** result_format);
template void librbd::api::util::luks_volume_key_get(
    librbd::ImageCtx* ictx, const void* opts, size_t opts_size, bool c_api,
    size_t max_size, std::string* volume_key, size_t* key_size, int* keyslot,
    Context* on_finish);
template void librbd::api::util::luks_keyslot_add(
    librbd::ImageCtx* ictx, const void* opts, size_t opts_size, bool c_api,
    int* result_keyslot, Context* on_finish);
template void librbd::api::util::luks_keyslot_remove(
    librbd::ImageCtx* ictx, const void* opts, size_t opts_size, bool c_api,
    Context* on_finish);
template void librbd::api::util::luks_keyslot_list(
    librbd::ImageCtx* ictx,
    std::vector<encryption_luks_keyslot_info_t>* keyslots,
    Context* on_finish);
template void librbd::api::util::luks_header_dump(
    librbd::ImageCtx* ictx, size_t max_size, std::string* dump,
    size_t* dump_size, Context* on_finish);
template void librbd::api::util::luks_header_restore(
    librbd::ImageCtx* ictx, std::string_view dump, Context* on_finish);
