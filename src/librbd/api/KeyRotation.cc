// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#include "librbd/api/KeyRotation.h"
#include "librbd/api/Utils.h"
#include "include/rados/librados.hpp"
#include "include/rbd/librbd.h"
#include "include/rbd/librbd.hpp"
#include "common/Clock.h"
#include "common/dout.h"
#include "common/errno.h"
#include "common/Cond.h"
#include "cls/rbd/cls_rbd_client.h"
#include "librbd/ExclusiveLock.h"
#include "librbd/ImageCtx.h"
#include "librbd/internal.h"
#include "librbd/Operations.h"
#include "librbd/crypto/CryptoInterface.h"
#include "librbd/crypto/LoadRequest.h"
#include "librbd/crypto/CryptoObjectDispatch.h"
#include "librbd/crypto/EncryptionFormat.h"
#include "librbd/crypto/Utils.h"
#ifdef HAVE_LIBCRYPTSETUP
#include "librbd/crypto/luks/Header.h"
#include "include/compat.h"
#include <openssl/rand.h>
#endif
#include "librbd/io/AioCompletion.h"
#include "librbd/io/ImageDispatchSpec.h"
#include "librbd/io/ImageDispatcherInterface.h"
#include "librbd/asio/Utils.h"
#include "librbd/Utils.h"
#include "include/neorados/RADOS.hpp"
#include "osdc/Striper.h"

#include <shared_mutex>

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::api::KeyRotation: " << __func__ << ": "

namespace librbd {
namespace api {

static constexpr std::string_view XATTR_NAME = "rbd_reencrypt";

template <typename I>
int KeyRotationContext<I>::validate_flags() {
  if (flags != 0) {
    lderr(cct) << "unknown encryption_key_rotate flags: 0x"
               << std::hex << flags << std::dec << dendl;
    return -EINVAL;
  }
  return 0;
}

template <typename I>
int KeyRotationContext<I>::validate_preconditions() {
  if (!ictx->encryption_format) {
    lderr(cct) << "encryption is not loaded" << dendl;
    return -EINVAL;
  }
  if (ictx->test_features(RBD_FEATURE_JOURNALING)) {
    lderr(cct) << "cannot rotate key with journaling enabled" << dendl;
    return -ENOTSUP;
  }
  if (ictx->parent != nullptr) {
    lderr(cct) << "cannot rotate key on cloned image" << dendl;
    return -EINVAL;
  }
  {
    std::shared_lock owner_locker{ictx->owner_lock};
    if (ictx->exclusive_lock != nullptr &&
        !ictx->exclusive_lock->is_lock_owner()) {
      C_SaferCond lock_ctx;
      ictx->exclusive_lock->acquire_lock(&lock_ctx);
      owner_locker.unlock();
      int r = lock_ctx.wait();
      if (r < 0) {
        lderr(cct) << "failed to acquire exclusive lock: "
                   << cpp_strerror(r) << dendl;
        return r;
      }
    }
  }
  return 0;
}

template <typename I>
int KeyRotationContext<I>::load_old_encryption(
    encryption_format_t old_format, encryption_options_t old_opts,
    size_t old_opts_size, bool c_api) {
#ifndef HAVE_LIBCRYPTSETUP
  return -ENOTSUP;
#else
  // Parse old passphrase from options
  crypto::EncryptionFormat<I>* old_enc_format;
  int r = api::util::create_encryption_format(
      cct, old_format, old_opts, old_opts_size, c_api, &old_enc_format);
  if (r != 0) {
    return r;
  }
  std::unique_ptr<crypto::EncryptionFormat<I>> old_format_ptr(old_enc_format);

  // Load encryption via the standard LoadRequest path
  C_SaferCond load_cond;
  std::vector<std::unique_ptr<crypto::EncryptionFormat<I>>> formats;
  formats.push_back(std::move(old_format_ptr));
  auto load_req = crypto::LoadRequest<I>::create(
      ictx, std::move(formats), &load_cond);
  load_req->send();
  r = load_cond.wait();
  if (r < 0) {
    lderr(cct) << "failed to load old encryption: "
               << cpp_strerror(r) << dendl;
    return r;
  }

  ldout(cct, 5) << "old encryption loaded successfully" << dendl;
  return 0;
#endif
}

template <typename I>
int KeyRotationContext<I>::compute_object_layout() {
  data_offset = ictx->get_data_offset();
  {
    std::shared_lock image_locker{ictx->image_lock};
    raw_size = ictx->get_image_size(CEPH_NOSNAP);
  }
  // Copy layout fields since are interconnected and must
  // stay consistent throughout re-encryption. Copying them
  //  avoids holding image_lock in the hot loop.
  object_size = ictx->layout.object_size;
  first_data_object = Striper::get_num_objects(ictx->layout, data_offset);
  num_objects = Striper::get_num_objects(ictx->layout, raw_size);
  stripe_period = ictx->get_stripe_period();

  // DO NOT move encryption_format out of ictx! get_data_offset() returns 0
  // when encryption_format is nullptr, which breaks image-to-raw offset
  // translation for all concurrent reads.
  //
  // When resuming an interrupted rotation (old_encryption_format exists),
  // the actual old crypto lives in old_encryption_format. encryption_format
  // holds the new key from the previous swap_crypto_enter_dual_key.
  {
    std::shared_lock image_locker{ictx->image_lock};
    if (ictx->old_encryption_format) {
      old_crypto = ictx->old_encryption_format->get_crypto();
    } else {
      old_crypto = ictx->encryption_format->get_crypto();
    }
  }

  start_cursor = first_data_object;
  return 0;
}

template <typename I>
int KeyRotationContext<I>::parse_format_params() {
  if (format != RBD_ENCRYPTION_FORMAT_LUKS2) {
    lderr(cct) << "key rotation requires LUKS2" << dendl;
    return -ENOTSUP;
  }
  luks_type = CRYPT_LUKS2;
  sector_size = 4096;

  encryption_algorithm_t alg;
  if (c_api) {
    auto* c_opts = static_cast<const rbd_encryption_luks2_format_options_t*>(
        opts);
    alg = c_opts->alg;
    passphrase = {c_opts->passphrase, c_opts->passphrase_size};
  } else {
    auto* cpp_opts = static_cast<const encryption_luks2_format_options_t*>(
        opts);
    alg = cpp_opts->alg;
    passphrase = cpp_opts->passphrase;
  }

  if (passphrase.empty()) {
    lderr(cct) << "passphrase must not be empty" << dendl;
    return -EINVAL;
  }

  switch (alg) {
    case RBD_ENCRYPTION_ALGORITHM_AES128:
      cipher = "aes";
      key_size = 32;
      break;
    case RBD_ENCRYPTION_ALGORITHM_AES256:
      cipher = "aes";
      key_size = 64;
      break;
    default:
      lderr(cct) << "unsupported encryption algorithm" << dendl;
      return -EINVAL;
  }
  return 0;
}

template <typename I>
int KeyRotationContext<I>::read_luks_header(ceph::bufferlist* header_bl) {
  uint64_t off = 0;
  while (off < data_offset) {
    uint64_t obj_no = off / object_size;
    std::string oid = ictx->get_object_name(obj_no);
    uint64_t obj_off = off % object_size;
    uint64_t read_len = std::min(object_size - obj_off, data_offset - off);

    ceph::bufferlist chunk;
    int r = ictx->data_ctx.read(oid, chunk, read_len, obj_off);
    if (r < 0) {
      lderr(cct) << "error reading LUKS header object " << oid << ": "
                 << cpp_strerror(r) << dendl;
      return r;
    }
    header_bl->claim_append(chunk);
    off += read_len;
  }
  return 0;
}

template <typename I>
int KeyRotationContext<I>::load_header_and_detect_resume(
    ceph::bufferlist& header_bl) {
#ifndef HAVE_LIBCRYPTSETUP
  return -ENOTSUP;
#else
  crypto::luks::Header header(cct);
  int r = header.init();
  if (r < 0) {
    return r;
  }
  r = header.write(header_bl);
  if (r < 0) {
    return r;
  }
  r = header.load(luks_type);
  if (r < 0) {
    return r;
  }

  std::string cursor_str;
  r = librbd::metadata_get(ictx, "rbd_reencrypt_cursor", &cursor_str);
  bool has_cursor = (r == 0 && !cursor_str.empty());
  int unbound_slot = header.find_unbound_keyslot();

  if (unbound_slot >= 0 && has_cursor) {
    // RESUME PATH: unbound keyslot + cursor = interrupted re-encryption.
    ldout(cct, 1) << "detected interrupted re-encryption (unbound keyslot="
                  << unbound_slot << ", cursor=" << cursor_str << ")" << dendl;

    if (key_size > 64) {
      lderr(cct) << "key_size " << key_size << " exceeds maximum (64)" << dendl;
      return -EINVAL;
    }
    char new_vk[64];
    size_t new_vk_size = key_size;
    r = header.read_volume_key_from_slot(
        unbound_slot, passphrase.data(), passphrase.size(),
        new_vk, &new_vk_size);
    if (r < 0) {
      lderr(cct) << "failed to read new key from unbound keyslot "
                 << "(wrong new passphrase?)" << dendl;
      return -EACCES;
    }

    r = crypto::util::build_crypto(
        cct, reinterpret_cast<const unsigned char*>(new_vk), new_vk_size,
        header.get_sector_size(), header.get_data_offset(), &new_crypto);
    ceph_memzero_s(new_vk, sizeof(new_vk), sizeof(new_vk));
    if (r != 0) {
      return r;
    }

    new_crypto_ptr = new_crypto.get();
    try {
      start_cursor = std::stoull(cursor_str);
    } catch (const std::exception& e) {
      lderr(cct) << "corrupt re-encryption cursor '" << cursor_str
                 << "': " << e.what()
                 << ". Cannot determine re-encryption boundary. "
                    "Image requires manual recovery." << dendl;
      return -EIO;
    }
    if (start_cursor < first_data_object || start_cursor > num_objects) {
      lderr(cct) << "re-encryption cursor " << start_cursor
                 << " out of range [" << first_data_object << ", "
                 << num_objects << "]. Cannot determine re-encryption "
                    "boundary. Image requires manual recovery." << dendl;
      return -EIO;
    }
    is_resume = true;
  }
  return 0;
#endif
}

template <typename I>
int KeyRotationContext<I>::prepare_fresh_key() {
#ifndef HAVE_LIBCRYPTSETUP
  return -ENOTSUP;
#else
  if (key_size > 64) {
    lderr(cct) << "key_size " << key_size << " exceeds maximum (64)" << dendl;
    return -EINVAL;
  }
  unsigned char new_key[64];
  if (RAND_bytes(new_key, key_size) != 1) {
    lderr(cct) << "failed to generate random encryption key" << dendl;
    return -EAGAIN;
  }

  // Load header again for modification
  crypto::luks::Header header(cct);
  int r = header.init();
  if (r < 0) {
    ceph_memzero_s(new_key, sizeof(new_key), sizeof(new_key));
    return r;
  }

  // Read existing header from RADOS
  ceph::bufferlist existing_bl;
  r = read_luks_header(&existing_bl);
  if (r < 0) {
    ceph_memzero_s(new_key, sizeof(new_key), sizeof(new_key));
    return r;
  }

  r = header.write(existing_bl);
  if (r < 0) {
    ceph_memzero_s(new_key, sizeof(new_key), sizeof(new_key));
    return r;
  }
  r = header.load(luks_type);
  if (r < 0) {
    ceph_memzero_s(new_key, sizeof(new_key), sizeof(new_key));
    return r;
  }

  // Add new DEK as unbound keyslot (not associated with any segment).
  int new_slot = header.add_unbound_keyslot(
      reinterpret_cast<const char*>(new_key), key_size,
      passphrase.data(), passphrase.size());
  if (new_slot < 0) {
    ceph_memzero_s(new_key, sizeof(new_key), sizeof(new_key));
    return new_slot;
  }

  r = crypto::util::build_crypto(
      cct, new_key, key_size, header.get_sector_size(),
      header.get_data_offset(), &new_crypto);
  ceph_memzero_s(new_key, sizeof(new_key), sizeof(new_key));
  if (r != 0) {
    return r;
  }
  new_crypto_ptr = new_crypto.get();

  // Read updated header (now has old active + new unbound keyslots)
  ceph::bufferlist header_bl;
  r = header.read(&header_bl);
  if (r < 0) {
    return r;
  }

  // Write updated LUKS header to RADOS (crash-safe: header written
  // before cursor, so on crash without cursor we start fresh)
  r = write_header_to_rados(header_bl);
  if (r < 0) {
    return r;
  }

  // Persist cursor AFTER header write
  r = ictx->operations->metadata_set(
      "rbd_reencrypt_cursor", std::to_string(first_data_object));
  if (r < 0) {
    lderr(cct) << "failed to persist initial cursor: "
               << cpp_strerror(r) << dendl;
    return r;
  }
  return 0;
#endif
}

template <typename I>
int KeyRotationContext<I>::write_header_to_rados(ceph::bufferlist& header_bl) {
  auto alignment = header_bl.length() % stripe_period;
  if (alignment > 0) {
    header_bl.append_zero(stripe_period - alignment);
  }

  uint64_t header_len = header_bl.length();
  uint64_t off = 0;
  // Write directly to RADOS, bypassing the image I/O path. The crypto
  // dispatch layer is already loaded, so a normal image write would encrypt
  // the header bytes as if they were file data. The LUKS header lives below
  // data_offset and is not addressable through the encrypted block device.
  while (off < header_len) {
    uint64_t obj_no = off / object_size;
    uint64_t obj_off = off % object_size;
    uint64_t write_len = std::min(object_size - obj_off, header_len - off);

    std::string oid = ictx->get_object_name(obj_no);
    ceph::bufferlist chunk;
    chunk.substr_of(header_bl, off, write_len);

    int r;
    if (obj_off == 0 && write_len == object_size) {
      r = ictx->data_ctx.write_full(oid, chunk);
    } else {
      r = ictx->data_ctx.write(oid, chunk, write_len, obj_off);
    }
    if (r < 0) {
      lderr(cct) << "error writing header object " << oid << ": "
                 << cpp_strerror(r) << dendl;
      return r;
    }
    off += write_len;
  }
  return 0;
}

template <typename I>
int KeyRotationContext<I>::create_backup_snapshot() {
  // On resume, reuse the snapshot name from the previous attempt.
  std::string existing_snap;
  int r = librbd::metadata_get(ictx, "rbd_reencrypt_snap", &existing_snap);
  if (r == 0 && !existing_snap.empty()) {
    snap_name = existing_snap;
    ldout(cct, 5) << "reusing existing backup snapshot: " << snap_name << dendl;
    return 0;
  }

  snap_name = ".rbd-reencrypt-backup-"
              + std::to_string(ceph_clock_now().sec());

  ldout(cct, 5) << "creating backup snapshot: " << snap_name << dendl;
  NoOpProgressContext prog_ctx;
  r = ictx->operations->snap_create(
      cls::rbd::UserSnapshotNamespace(), snap_name,
      SNAP_CREATE_FLAG_SKIP_OBJECT_MAP | SNAP_CREATE_FLAG_SKIP_NOTIFY_QUIESCE,
      prog_ctx);
  if (r < 0) {
    lderr(cct) << "failed to create backup snapshot: "
               << cpp_strerror(r) << dendl;
    return r;
  }

  r = ictx->operations->metadata_set("rbd_reencrypt_snap", snap_name);
  if (r < 0) {
    lderr(cct) << "failed to persist backup snapshot name: "
               << cpp_strerror(r) << dendl;
    // Best-effort: remove the snapshot we just created
    C_SaferCond rm_ctx;
    ictx->operations->snap_remove(
        cls::rbd::UserSnapshotNamespace(), snap_name, &rm_ctx);
    rm_ctx.wait();
    return r;
  }

  return 0;
}

template <typename I>
int KeyRotationContext<I>::swap_crypto_enter_dual_key() {
  // On online resume (already in dual-key mode), the CryptoObjectDispatch
  // atomics and ictx formats are already correct from the first rotation
  // attempt. Calling swap_crypto + replacing encryption_format would
  // destroy the crypto object that in-flight async reads still reference.
  if (ictx->old_encryption_format) {
    ldout(cct, 5) << "already in dual-key mode (online resume), "
                  << "skipping swap" << dendl;
    return 0;
  }

  new_format->set_crypto(std::move(new_crypto));
  ictx->crypto_object_dispatch->swap_crypto(
      new_crypto_ptr, old_crypto, start_cursor);

  // Atomically replace encryption_format. Store old format in
  // ictx->old_encryption_format so old_crypto stays alive even if
  // the KeyRotationContext is destroyed (e.g., rotation error returns
  // to caller while dual-key mode stays active).
  {
    std::unique_lock image_locker{ictx->image_lock};
    ictx->old_encryption_format = std::move(ictx->encryption_format);
    ictx->encryption_format = std::move(new_format);
  }
  return 0;
}

template <typename I>
int KeyRotationContext<I>::reencrypt_objects() {
  const uint64_t PERSIST_INTERVAL = 64;

  auto io_ctx = ictx->get_data_io_context();

  for (uint64_t obj_no = start_cursor; obj_no < num_objects; obj_no++) {
    ictx->crypto_object_dispatch->set_reencrypting_object(obj_no);

    std::string oid = ictx->get_object_name(obj_no);

    // Check if object exists
    uint64_t obj_stat_size;
    time_t obj_mtime;    int r = ictx->data_ctx.stat(oid, &obj_stat_size, &obj_mtime);
    if (r == -ENOENT) {
      // Non-existent objects are implicitly zero-filled and were never
      // encrypted with the old key, so no re-encryption is needed.
      ictx->crypto_object_dispatch->advance_reencrypt_cursor(obj_no + 1);
      continue;
    }
    if (r < 0) {
      lderr(cct) << "error stat'ing object " << oid << ": "
                 << cpp_strerror(r) << dendl;
      cleanup_dual_key();
      return r;
    }

    // On resume, check if this object was already re-encrypted by looking
    // for the xattr marker. Xattrs are part of RADOS object state and
    // revert with snapshot rollback, making them safe for resume detection.
    if (is_resume) {
      ceph::bufferlist xattr_bl;
      boost::system::error_code ec;
      neorados::ReadOp read_op;
      read_op.get_xattr(XATTR_NAME, &xattr_bl, &ec);

      C_SaferCond xattr_cond;
      ictx->rados_api.execute(
          {oid}, *io_ctx, std::move(read_op), nullptr,
          librbd::asio::util::get_callback_adapter(
              [&xattr_cond](int r) { xattr_cond.complete(r); }));
      r = xattr_cond.wait();
      if (r == 0 && !ec) {
        // Xattr present — already re-encrypted, skip
        ictx->crypto_object_dispatch->advance_reencrypt_cursor(obj_no + 1);
        continue;
      }
      // Distinguish "xattr not found" (expected) from real errors.
      // -ENODATA means no such xattr (expected on objects not yet re-encrypted).
      if (r < 0 && r != -ENODATA) {
        lderr(cct) << "error checking xattr on object " << oid << ": "
                   << cpp_strerror(r) << dendl;
        cleanup_dual_key();
        return r;
      }
      // r == 0 with ec set, or r == -ENODATA — xattr absent, proceed
    }

    ceph::bufferlist raw_bl;
    r = ictx->data_ctx.read(oid, raw_bl, obj_stat_size, 0);
    if (r < 0) {
      lderr(cct) << "error reading object " << oid << ": "
                 << cpp_strerror(r) << dendl;
      cleanup_dual_key();
      return r;
    }

    // Crypto offset is relative to the data area (after LUKS header).
    uint64_t file_offset = static_cast<uint64_t>(obj_no) * object_size
                           - data_offset;

    r = old_crypto->decrypt(&raw_bl, file_offset);
    if (r != 0) {
      lderr(cct) << "error decrypting object " << oid << ": "
                 << cpp_strerror(r) << dendl;
      cleanup_dual_key();
      return r;
    }

    r = new_crypto_ptr->encrypt(&raw_bl, file_offset);
    if (r != 0) {
      lderr(cct) << "error encrypting object " << oid << ": "
                 << cpp_strerror(r) << dendl;
      cleanup_dual_key();
      return r;
    }

    // Write re-encrypted data + set xattr atomically in one OSD op.
    // The xattr marks this object as re-encrypted for resume detection.
    // Unlike the old marker-byte approach, xattrs don't change object size,
    // so they're compatible with deep copy, mirroring, flatten, and copyup.
    {
      neorados::WriteOp write_op;
      write_op.write_full(std::move(raw_bl));
      write_op.setxattr(XATTR_NAME, ceph::bufferlist{});

      C_SaferCond write_cond;
      ictx->rados_api.execute(
          {oid}, *io_ctx, std::move(write_op),
          librbd::asio::util::get_callback_adapter(
              [&write_cond](int r) { write_cond.complete(r); }));
      r = write_cond.wait();
      if (r < 0) {
        lderr(cct) << "error writing object " << oid << ": "
                   << cpp_strerror(r) << dendl;
        cleanup_dual_key();
        return r;
      }
    }

    ictx->crypto_object_dispatch->advance_reencrypt_cursor(obj_no + 1);

    if ((obj_no - start_cursor) % PERSIST_INTERVAL == 0) {
      r = ictx->operations->metadata_set(
          "rbd_reencrypt_cursor", std::to_string(obj_no + 1));
      if (r < 0) {
        lderr(cct) << "failed to persist cursor at object " << (obj_no + 1)
                   << ": " << cpp_strerror(r) << dendl;
        cleanup_dual_key();
        return r;
      }
    }
  }
  return 0;
}

template <typename I>
int KeyRotationContext<I>::persist_final_state() {
#ifndef HAVE_LIBCRYPTSETUP
  return -ENOTSUP;
#else
  // Persist cursor at num_objects so resume path knows all data is done.
  int r = ictx->operations->metadata_set(
      "rbd_reencrypt_cursor", std::to_string(num_objects));
  if (r < 0) {
    lderr(cct) << "failed to persist final cursor: "
               << cpp_strerror(r) << dendl;
    cleanup_dual_key();
    return r;
  }

  // Write clean LUKS header BEFORE exiting dual-key mode. Header objects
  // are before first_data_object and written via data_ctx (bypass crypto),
  // so this is safe during dual-key mode. If the write fails,
  // cleanup_dual_key preserves dual-key mode and on-disk state
  // (cursor + unbound keyslot) so rotate_key() can resume later.
  crypto::luks::Header final_header(cct);
  r = final_header.init();
  if (r < 0) {
    lderr(cct) << "failed to init final header: "
               << cpp_strerror(r) << dendl;
    cleanup_dual_key();
    return r;
  }

  r = final_header.format(
      luks_type, cipher,
      reinterpret_cast<const char*>(new_crypto_ptr->get_key()),
      new_crypto_ptr->get_key_length(),
      "xts-plain64", sector_size, stripe_period, false);
  if (r != 0) {
    lderr(cct) << "failed to format final header: "
               << cpp_strerror(r) << dendl;
    cleanup_dual_key();
    return r;
  }

  r = final_header.add_keyslot(passphrase.data(), passphrase.size());
  if (r != 0) {
    lderr(cct) << "failed to add keyslot to final header: "
               << cpp_strerror(r) << dendl;
    cleanup_dual_key();
    return r;
  }

  ceph::bufferlist final_header_bl;
  r = final_header.read(&final_header_bl);
  if (r < 0) {
    lderr(cct) << "failed to read final header: "
               << cpp_strerror(r) << dendl;
    cleanup_dual_key();
    return r;
  }

  // If write_header_to_rados fails here, all data objects are already
  // encrypted with the new key. cleanup_dual_key() exits dual-key mode
  // and blocks I/O. On disk, the unbound keyslot + cursor (at
  // num_objects) are preserved, so a subsequent rotate_key() with the
  // same passphrase will resume, skip all objects, and retry the header.
  r = write_header_to_rados(final_header_bl);
  if (r < 0) {
    cleanup_dual_key();
    return r;
  }

  return 0;
#endif
}

template <typename I>
int KeyRotationContext<I>::finish_and_cleanup() {
  // Header is on disk. Exit dual-key mode — safe now because even on
  // crash, encryption_load(new_pass) will work with the clean header.
  ictx->crypto_object_dispatch->finish_reencryption();
  {
    std::unique_lock image_locker{ictx->image_lock};
    ictx->old_encryption_format.reset();
  }

  {
    int rm_r = ictx->operations->metadata_remove("rbd_reencrypt_cursor");
    if (rm_r < 0 && rm_r != -ENOENT) {
      ldout(cct, 1) << "warning: failed to remove cursor metadata: "
                     << cpp_strerror(rm_r) << dendl;
    }
  }

  // Remove re-encryption xattr markers from all data objects.
  auto io_ctx = ictx->get_data_io_context();
  for (uint64_t obj_no = first_data_object; obj_no < num_objects; obj_no++) {
    std::string oid = ictx->get_object_name(obj_no);

    neorados::WriteOp rm_op;
    rm_op.rmxattr(XATTR_NAME);

    C_SaferCond rm_cond;
    ictx->rados_api.execute(
        {oid}, *io_ctx, std::move(rm_op),
        librbd::asio::util::get_callback_adapter(
            [&rm_cond](int r) { rm_cond.complete(r); }));
    int r = rm_cond.wait();
    // Ignore -ENOENT (object doesn't exist) and -ENODATA (no such xattr)
    if (r < 0 && r != -ENOENT && r != -ENODATA) {
      ldout(cct, 1) << "warning: failed to remove xattr from " << oid
                     << ": " << cpp_strerror(r) << dendl;
    }
  }

  remove_backup_snapshot();

  C_SaferCond flush_cond;
  auto flush_aio = io::AioCompletion::create_and_start(
      &flush_cond, ictx, io::AIO_TYPE_FLUSH);
  auto flush_req = io::ImageDispatchSpec::create_flush(
      *ictx, io::IMAGE_DISPATCH_LAYER_INTERNAL_START, flush_aio,
      io::FLUSH_SOURCE_INTERNAL, {});
  flush_req->send();
  flush_cond.wait();

  return 0;
}

template <typename I>
void KeyRotationContext<I>::cleanup_dual_key() {
  // Stay in dual-key mode — IO continues to work correctly with the
  // cursor-based key selection. On-disk state (cursor + unbound keyslot)
  // is preserved so rotate_key() can resume.
  // old_encryption_format keeps old_crypto alive in ictx.
  lderr(cct) << "re-encryption interrupted; call rotate_key() again "
                "with the same new passphrase to resume." << dendl;
}

template <typename I>
void KeyRotationContext<I>::remove_backup_snapshot() {
  if (snap_name.empty()) {
    return;
  }

  ldout(cct, 5) << "removing backup snapshot: " << snap_name << dendl;
  C_SaferCond ctx;
  ictx->operations->snap_remove(
      cls::rbd::UserSnapshotNamespace(), snap_name, &ctx);
  int r = ctx.wait();
  if (r < 0 && r != -ENOENT) {
    ldout(cct, 1) << "warning: failed to remove backup snapshot "
                  << snap_name << ": " << cpp_strerror(r) << dendl;
  }

  int rm_r = ictx->operations->metadata_remove("rbd_reencrypt_snap");
  if (rm_r < 0 && rm_r != -ENOENT) {
    ldout(cct, 1) << "warning: failed to remove snap metadata: "
                   << cpp_strerror(rm_r) << dendl;
  }
}

} // namespace api
} // namespace librbd

template struct librbd::api::KeyRotationContext<librbd::ImageCtx>;
