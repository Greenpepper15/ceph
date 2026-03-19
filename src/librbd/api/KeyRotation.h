// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#ifndef LIBRBD_API_KEY_ROTATION_H
#define LIBRBD_API_KEY_ROTATION_H

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include "include/buffer_fwd.h"
#include "include/common_fwd.h"
#include "include/rbd/librbd.hpp"
#include "include/rbd_types.h"
#include "librbd/crypto/EncryptionFormat.h"

namespace librbd {

struct ImageCtx;

namespace crypto {
class CryptoInterface;
}

namespace api {

template <typename ImageCtxT = librbd::ImageCtx>
struct KeyRotationContext {
  // --- Inputs (set by orchestrator) ---
  ImageCtxT* ictx = nullptr;
  CephContext* cct = nullptr;
  encryption_format_t format = RBD_ENCRYPTION_FORMAT_LUKS2;
  encryption_options_t opts = nullptr;
  bool c_api = false;
  uint32_t flags = 0;
  std::unique_ptr<crypto::EncryptionFormat<ImageCtxT>> new_format;

  // --- State (filled by phase methods) ---

  // Object layout
  uint64_t data_offset = 0;
  uint64_t raw_size = 0;
  uint64_t object_size = 0;
  uint64_t first_data_object = 0;
  uint64_t num_objects = 0;
  uint64_t stripe_period = 0;

  // LUKS parameters
  const char* luks_type = nullptr;
  size_t sector_size = 0;
  const char* cipher = nullptr;
  const char* cipher_mode = nullptr;
  size_t key_size = 0;
  std::string_view passphrase;

  // Crypto state
  crypto::CryptoInterface* old_crypto = nullptr;
  std::unique_ptr<crypto::CryptoInterface> new_crypto;
  crypto::CryptoInterface* new_crypto_ptr = nullptr;
  uint64_t start_cursor = 0;
  bool is_resume = false;

  // Backup snapshot
  std::string snap_name;

  // --- Phase methods (each returns 0 on success, negative errno on error) ---
  int validate_flags();
  int validate_preconditions();
  int load_old_encryption(encryption_format_t old_format,
                          encryption_options_t old_opts,
                          size_t old_opts_size, bool c_api);
  int compute_object_layout();
  int parse_format_params();
  int read_luks_header(ceph::bufferlist* header_bl);
  int load_header_and_detect_resume(ceph::bufferlist& header_bl);
  int prepare_fresh_key();
  int create_backup_snapshot();
  int swap_crypto_enter_dual_key();
  int reencrypt_objects();
  int persist_final_state();
  int finish_and_cleanup();

  // --- Shared helpers ---
  int write_header_to_rados(ceph::bufferlist& header_bl);
  void cleanup_dual_key();
  void remove_backup_snapshot();
};

} // namespace api
} // namespace librbd

extern template struct librbd::api::KeyRotationContext<librbd::ImageCtx>;

#endif // LIBRBD_API_KEY_ROTATION_H
