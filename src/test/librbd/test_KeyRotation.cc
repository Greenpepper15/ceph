// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

/*
 * Ceph - scalable distributed file system
 *
 * Copyright (C) 2024 Red Hat
 *
 * This is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public
 * License version 2, as published by the Free Software
 * Foundation.  See file COPYING.
 *
 */

// Internal key rotation tests that access librbd internals
// (KeyRotationContext, CryptoObjectDispatch, etc.).

#include "include/int_types.h"
#include "include/rados/librados.h"
#include "include/rbd_types.h"
#include "include/rbd/librbd.h"
#include "include/rbd/librbd.hpp"
#include "include/stringify.h"

#include "librbd/api/KeyRotation.h"
#include "librbd/api/Utils.h"
#include "librbd/ImageCtx.h"
#include "librbd/Operations.h"
#include "librbd/crypto/CryptoInterface.h"
#include "librbd/crypto/CryptoObjectDispatch.h"
#include "librbd/asio/Utils.h"
#include "include/neorados/RADOS.hpp"
#include "common/Cond.h"

#include "test/librados/test.h"
#include "test/librados/test_cxx.h"
#include "test/librados/test_shared.h"
#include "test/librbd/test_support.h"

#include "gtest/gtest.h"

#include <atomic>
#include <string>
#include <thread>
#include <vector>

void register_test_key_rotation() {
}

namespace {

static int get_features(bool *old_format, uint64_t *features) {
  const char *c = getenv("RBD_FEATURES");
  if (c && strlen(c) > 0) {
    std::stringstream ss;
    ss << c;
    ss >> *features;
    if (ss.fail())
      return -EINVAL;
    *old_format = false;
  } else {
    *old_format = true;
    *features = 0;
  }
  return 0;
}

static int create_image(rados_ioctx_t ioctx, const char *name,
                        uint64_t size, int *order) {
  bool old_format;
  uint64_t features;
  int r = get_features(&old_format, &features);
  if (r < 0)
    return r;
  if (old_format) {
    r = rados_conf_set(rados_ioctx_get_cluster(ioctx),
                       "rbd_default_format", "1");
    if (r < 0)
      return r;
    return rbd_create(ioctx, name, size, order);
  } else if ((features & RBD_FEATURE_STRIPINGV2) != 0) {
    uint64_t stripe_unit = IMAGE_STRIPE_UNIT;
    if (*order)
      stripe_unit = (1ull << (*order - 1));
    return rbd_create3(ioctx, name, size, features, order,
                       stripe_unit, IMAGE_STRIPE_COUNT);
  } else {
    return rbd_create2(ioctx, name, size, features, order);
  }
}

} // anonymous namespace

class KeyRotationInternalTest : public ::testing::Test {
protected:
  static constexpr size_t BLOCK_SIZE = 4096;
  static constexpr uint64_t IMAGE_SIZE = 32 << 20;  // 32MB

  static void SetUpTestCase() {
    ASSERT_EQ("", connect_cluster(&_cluster));
    ASSERT_EQ("", connect_cluster_pp(_rados));

    _pool_name = get_temp_pool_name("test-librbd-keyrot-");
    ASSERT_EQ("", create_one_pool_pp(_pool_name, _rados));
  }

  static void TearDownTestCase() {
    ASSERT_EQ(0, destroy_one_pool_pp(_pool_name, _rados));
    rados_shutdown(_cluster);
  }

  void SetUp() override {
    ASSERT_EQ(0, rados_ioctx_create(_cluster, _pool_name.c_str(), &m_ioctx));
    m_name = get_temp_image_name();
    int order = 0;
    ASSERT_EQ(0, create_image(m_ioctx, m_name.c_str(), IMAGE_SIZE, &order));
    ASSERT_EQ(0, rbd_open(m_ioctx, m_name.c_str(), &m_image, NULL));
  }

  void TearDown() override {
    if (m_image) {
      rbd_close(m_image);
    }
    rados_ioctx_destroy(m_ioctx);
  }

  static std::string get_temp_image_name() {
    ++_image_number;
    return "image" + stringify(_image_number);
  }

  void format_encryption(const char* passphrase) {
    rbd_encryption_luks2_format_options_t opts = {
            .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
            .passphrase = passphrase,
            .passphrase_size = strlen(passphrase),
    };
    ASSERT_EQ(0, rbd_encryption_format(
            m_image, RBD_ENCRYPTION_FORMAT_LUKS2, &opts, sizeof(opts)));
  }

  int rotate_key(const char* passphrase, uint32_t flags = 0) {
    rbd_encryption_luks2_format_options_t opts = {
            .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
            .passphrase = passphrase,
            .passphrase_size = strlen(passphrase),
    };
    return rbd_encryption_key_rotate(
            m_image, RBD_ENCRYPTION_FORMAT_LUKS2, &opts, sizeof(opts), flags);
  }

  int resume_key_rotate(const char* old_passphrase,
                        const char* new_passphrase) {
    rbd_encryption_luks2_format_options_t old_opts = {
            .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
            .passphrase = old_passphrase,
            .passphrase_size = strlen(old_passphrase),
    };
    rbd_encryption_luks2_format_options_t new_opts = {
            .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
            .passphrase = new_passphrase,
            .passphrase_size = strlen(new_passphrase),
    };
    return rbd_encryption_key_rotate_resume(
            m_image,
            RBD_ENCRYPTION_FORMAT_LUKS2, &old_opts, sizeof(old_opts),
            RBD_ENCRYPTION_FORMAT_LUKS2, &new_opts, sizeof(new_opts), 0);
  }

  int load_encryption(const char* passphrase) {
    rbd_encryption_luks2_format_options_t opts = {
            .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
            .passphrase = passphrase,
            .passphrase_size = strlen(passphrase),
    };
    return rbd_encryption_load(
            m_image, RBD_ENCRYPTION_FORMAT_LUKS2, &opts, sizeof(opts));
  }

  void reopen_image() {
    ASSERT_EQ(0, rbd_close(m_image));
    m_image = nullptr;
    ASSERT_EQ(0, rbd_open(m_ioctx, m_name.c_str(), &m_image, NULL));
  }

  void write_pattern(uint64_t offset, size_t len, char pattern) {
    std::vector<char> data(len, pattern);
    ASSERT_EQ(static_cast<ssize_t>(len),
              rbd_write(m_image, offset, len, data.data()));
  }

  void verify_pattern(uint64_t offset, size_t len, char pattern) {
    std::vector<char> expected(len, pattern);
    std::vector<char> actual(len);
    ASSERT_EQ(static_cast<ssize_t>(len),
              rbd_read(m_image, offset, len, actual.data()));
    ASSERT_EQ(expected, actual);
  }

  static rados_t _cluster;
  static librados::Rados _rados;
  static std::string _pool_name;
  static int _image_number;

  rados_ioctx_t m_ioctx;
  rbd_image_t m_image = nullptr;
  std::string m_name;
};

rados_t KeyRotationInternalTest::_cluster;
librados::Rados KeyRotationInternalTest::_rados;
std::string KeyRotationInternalTest::_pool_name;
int KeyRotationInternalTest::_image_number = 0;

TEST_F(KeyRotationInternalTest, ValidatePreconditions_NoEncryption)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

  // Image has no encryption loaded — validate_preconditions should fail
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  ctx.cct = ctx.ictx->cct;
  ASSERT_EQ(-EINVAL, ctx.validate_preconditions());
}

TEST_F(KeyRotationInternalTest, ComputeObjectLayout_AfterFormat)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("pass");

  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  ctx.cct = ctx.ictx->cct;
  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_GT(ctx.first_data_object, 0u);
  ASSERT_GT(ctx.num_objects, ctx.first_data_object);
  ASSERT_GT(ctx.object_size, 0u);
  ASSERT_GT(ctx.data_offset, 0u);
  ASSERT_NE(nullptr, ctx.old_crypto);
#endif
}

TEST_F(KeyRotationInternalTest, ReadLuksHeader_AfterFormat)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("pass");

  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  ctx.cct = ctx.ictx->cct;
  ASSERT_EQ(0, ctx.compute_object_layout());

  ceph::bufferlist header_bl;
  ASSERT_EQ(0, ctx.read_luks_header(&header_bl));
  ASSERT_GT(header_bl.length(), 0u);
#endif
}

TEST_F(KeyRotationInternalTest, ParseFormatParams_NonLUKS2)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("pass");

  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  ctx.cct = ctx.ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS1;
  ctx.c_api = true;
  ASSERT_EQ(-ENOTSUP, ctx.parse_format_params());
#endif
}

TEST_F(KeyRotationInternalTest, ValidateFlags_RejectsUnknown)
{
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  ctx.cct = ctx.ictx->cct;
  ctx.flags = 0xFFFF;  // unknown bits
  ASSERT_EQ(-EINVAL, ctx.validate_flags());
}

TEST_F(KeyRotationInternalTest, ValidateFlags_AcceptsZero)
{
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  ctx.cct = ctx.ictx->cct;
  ctx.flags = 0;
  ASSERT_EQ(0, ctx.validate_flags());
}

TEST_F(KeyRotationInternalTest, CorruptCursorDetected)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  write_pattern(0, BLOCK_SIZE * 4, 0xAA);

  // Run prepare_fresh_key to create unbound keyslot + cursor on disk
  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = ictx;
  ctx.cct = ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx.c_api = true;
  rbd_encryption_luks2_format_options_t opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "new_pass",
    .passphrase_size = 8,
  };
  ctx.opts = &opts;
  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_EQ(0, ctx.parse_format_params());
  ASSERT_EQ(0, ctx.prepare_fresh_key());

  // Corrupt the cursor with non-numeric garbage
  ASSERT_EQ(0, rbd_metadata_set(m_image, "rbd_reencrypt_cursor", "garbage"));

  // Resume path should detect corrupt cursor and fail with -EIO
  ASSERT_EQ(-EIO, rotate_key("new_pass"));

  // Data still readable with old passphrase
  verify_pattern(0, BLOCK_SIZE * 4, 0xAA);
  rbd_metadata_remove(m_image, "rbd_reencrypt_cursor");
#endif
}

TEST_F(KeyRotationInternalTest, OutOfRangeCursorDetected)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  write_pattern(0, BLOCK_SIZE * 4, 0xAA);

  // Create unbound keyslot + cursor via prepare_fresh_key
  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = ictx;
  ctx.cct = ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx.c_api = true;
  rbd_encryption_luks2_format_options_t opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "new_pass",
    .passphrase_size = 8,
  };
  ctx.opts = &opts;
  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_EQ(0, ctx.parse_format_params());
  ASSERT_EQ(0, ctx.prepare_fresh_key());

  // Inject cursor way past num_objects
  ASSERT_EQ(0, rbd_metadata_set(m_image, "rbd_reencrypt_cursor", "999999999"));

  // Resume path should detect out-of-range and fail with -EIO
  ASSERT_EQ(-EIO, rotate_key("new_pass"));

  // Data still readable
  verify_pattern(0, BLOCK_SIZE * 4, 0xAA);
  rbd_metadata_remove(m_image, "rbd_reencrypt_cursor");
#endif
}

TEST_F(KeyRotationInternalTest, WrongPassphraseOnResume)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  write_pattern(0, BLOCK_SIZE * 4, 0xAA);

  // Create unbound keyslot protected with "correct_pass"
  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = ictx;
  ctx.cct = ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx.c_api = true;
  rbd_encryption_luks2_format_options_t correct_opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "correct_pass",
    .passphrase_size = 12,
  };
  ctx.opts = &correct_opts;
  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_EQ(0, ctx.parse_format_params());
  ASSERT_EQ(0, ctx.prepare_fresh_key());

  // Attempt rotation with WRONG passphrase — can't unlock unbound keyslot
  ASSERT_EQ(-EACCES, rotate_key("wrong_pass"));

  // Data still readable with old pass
  verify_pattern(0, BLOCK_SIZE * 4, 0xAA);

  // Succeed with correct passphrase
  ASSERT_EQ(0, rotate_key("correct_pass"));
  verify_pattern(0, BLOCK_SIZE * 4, 0xAA);

  reopen_image();
  ASSERT_EQ(0, load_encryption("correct_pass"));
  verify_pattern(0, BLOCK_SIZE * 4, 0xAA);
#endif
}

TEST_F(KeyRotationInternalTest, StaleCursorIgnoredWithoutUnboundKeyslot)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  write_pattern(0, BLOCK_SIZE * 4, 0xAA);

  // Inject a stale cursor (no matching unbound keyslot in header)
  ASSERT_EQ(0, rbd_metadata_set(m_image, "rbd_reencrypt_cursor", "5"));

  // Rotation should proceed as fresh (cursor without unbound slot is ignored)
  ASSERT_EQ(0, rotate_key("new_pass"));
  verify_pattern(0, BLOCK_SIZE * 4, 0xAA);

  // Cursor should be cleaned up after successful rotation
  char value[64];
  size_t value_len = sizeof(value);
  ASSERT_NE(0, rbd_metadata_get(m_image, "rbd_reencrypt_cursor",
                                 value, &value_len));

  reopen_image();
  ASSERT_EQ(0, load_encryption("new_pass"));
  verify_pattern(0, BLOCK_SIZE * 4, 0xAA);
#endif
}

TEST_F(KeyRotationInternalTest, ResumeAfterPrepareKeyInterruption)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  write_pattern(0, BLOCK_SIZE * 4, 0xAA);

  // Run prepare_fresh_key to write header + cursor, simulating a crash
  // right after (before swap_crypto / reencrypt_objects)
  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = ictx;
  ctx.cct = ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx.c_api = true;
  rbd_encryption_luks2_format_options_t opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "new_pass",
    .passphrase_size = 8,
  };
  ctx.opts = &opts;
  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_EQ(0, ctx.parse_format_params());
  ASSERT_EQ(0, ctx.prepare_fresh_key());

  // On disk: header has old active + new unbound keyslot, cursor=first_data_object
  // No objects re-encrypted. Simulates crash right after prepare_fresh_key.

  // "Resume" via the public API — should detect unbound keyslot + cursor
  ASSERT_EQ(0, rotate_key("new_pass"));

  verify_pattern(0, BLOCK_SIZE * 4, 0xAA);

  reopen_image();
  ASSERT_NE(0, load_encryption("old_pass"));
  reopen_image();
  ASSERT_EQ(0, load_encryption("new_pass"));
  verify_pattern(0, BLOCK_SIZE * 4, 0xAA);
#endif
}

TEST_F(KeyRotationInternalTest, CleanupDualKeyPreservesDualKey)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");

  // Write distinct patterns to different regions so we can verify
  // IO to both new-key and old-key sides of the cursor boundary.
  write_pattern(0, BLOCK_SIZE * 2, 0xAA);
  write_pattern(BLOCK_SIZE * 2, BLOCK_SIZE * 2, 0xBB);

  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = ictx;
  ctx.cct = ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx.c_api = true;
  rbd_encryption_luks2_format_options_t opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "new_pass",
    .passphrase_size = 8,
  };
  ctx.opts = &opts;

  librbd::crypto::EncryptionFormat<librbd::ImageCtx>* result_format;
  ASSERT_EQ(0, librbd::api::util::create_encryption_format(
      ictx->cct, RBD_ENCRYPTION_FORMAT_LUKS2,
      &opts, sizeof(opts), true, &result_format));
  ctx.new_format.reset(result_format);

  // Enter dual-key mode and partially re-encrypt
  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_EQ(0, ctx.parse_format_params());
  ASSERT_EQ(0, ctx.prepare_fresh_key());
  ASSERT_EQ(0, ctx.swap_crypto_enter_dual_key());

  // Re-encrypt 2 objects manually (inline — helper is in ShutdownTest)
  {
    uint64_t end = std::min(ctx.start_cursor + 2, ctx.num_objects);
    for (uint64_t obj_no = ctx.start_cursor; obj_no < end; obj_no++) {
      ictx->crypto_object_dispatch->set_reencrypting_object(obj_no);
      std::string oid = ictx->get_object_name(obj_no);
      ceph::bufferlist raw_bl;
      int r = ictx->data_ctx.read(oid, raw_bl, ctx.object_size, 0);
      if (r == -ENOENT) {
        ictx->crypto_object_dispatch->advance_reencrypt_cursor(obj_no + 1);
        continue;
      }
      ASSERT_GE(r, 0);
      uint64_t file_offset = obj_no * ctx.object_size - ctx.data_offset;
      ASSERT_EQ(0, ctx.old_crypto->decrypt(&raw_bl, file_offset));
      ASSERT_EQ(0, ctx.new_crypto_ptr->encrypt(&raw_bl, file_offset));
      r = ictx->data_ctx.write_full(oid, raw_bl);
      ASSERT_GE(r, 0);
      // Set xattr to mark as re-encrypted (same as production code).
      {
        auto io_ctx = ictx->get_data_io_context();
        neorados::WriteOp xattr_op;
        xattr_op.setxattr("rbd_reencrypt", ceph::bufferlist{});
        C_SaferCond xattr_cond;
        ictx->rados_api.execute(
            {oid}, *io_ctx, std::move(xattr_op),
            librbd::asio::util::get_callback_adapter(
                [&xattr_cond](int r) { xattr_cond.complete(r); }));
        ASSERT_GE(xattr_cond.wait(), 0);
      }
      ictx->crypto_object_dispatch->advance_reencrypt_cursor(obj_no + 1);
      ASSERT_EQ(0, ictx->operations->metadata_set(
          "rbd_reencrypt_cursor", std::to_string(obj_no + 1)));
    }
  }

  // Simulate failure — stay in dual-key mode
  ctx.cleanup_dual_key();

  // Status should show partial progress
  uint64_t progress = 0;
  ASSERT_EQ(0, rbd_encryption_reencrypt_status(m_image, &progress));
  ASSERT_GT(progress, 0u);
  ASSERT_LT(progress, 100u);

  // IO works in dual-key mode — verify both regions readable
  verify_pattern(0, BLOCK_SIZE * 2, 0xAA);
  verify_pattern(BLOCK_SIZE * 2, BLOCK_SIZE * 2, 0xBB);

  // Write to both regions (new-key and old-key sides of cursor)
  write_pattern(0, BLOCK_SIZE, 0xCC);
  write_pattern(BLOCK_SIZE * 3, BLOCK_SIZE, 0xDD);
  verify_pattern(0, BLOCK_SIZE, 0xCC);
  verify_pattern(BLOCK_SIZE * 3, BLOCK_SIZE, 0xDD);

  // After reopen, encryption_load fails due to pending cursor
  reopen_image();
  ASSERT_EQ(-EUCLEAN, load_encryption("old_pass"));

  // Resume with both passphrases
  ASSERT_EQ(0, resume_key_rotate("old_pass", "new_pass"));
  ASSERT_EQ(0, rbd_encryption_reencrypt_status(m_image, &progress));
  ASSERT_EQ(100u, progress);

  // Verify modified patterns survive rotation
  verify_pattern(0, BLOCK_SIZE, 0xCC);
  verify_pattern(BLOCK_SIZE, BLOCK_SIZE, 0xAA);
  verify_pattern(BLOCK_SIZE * 2, BLOCK_SIZE, 0xBB);
  verify_pattern(BLOCK_SIZE * 3, BLOCK_SIZE, 0xDD);

  // Final verification with new passphrase after reopen
  reopen_image();
  ASSERT_EQ(0, load_encryption("new_pass"));
  verify_pattern(0, BLOCK_SIZE, 0xCC);
  verify_pattern(BLOCK_SIZE, BLOCK_SIZE, 0xAA);
  verify_pattern(BLOCK_SIZE * 2, BLOCK_SIZE, 0xBB);
  verify_pattern(BLOCK_SIZE * 3, BLOCK_SIZE, 0xDD);
#endif
}

TEST_F(KeyRotationInternalTest, ReencryptStatus)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");

  // Status should be 100 (no re-encryption pending)
  uint64_t progress = 0;
  ASSERT_EQ(0, rbd_encryption_reencrypt_status(m_image, &progress));
  ASSERT_EQ(100u, progress);

  // After starting rotation, inject a cursor to simulate interrupted rotation
  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = ictx;
  ctx.cct = ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx.c_api = true;
  rbd_encryption_luks2_format_options_t opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "new_pass",
    .passphrase_size = 8,
  };
  ctx.opts = &opts;
  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_EQ(0, ctx.parse_format_params());
  ASSERT_EQ(0, ctx.prepare_fresh_key());

  // Cursor at start_cursor means 0% done
  ASSERT_EQ(0, rbd_encryption_reencrypt_status(m_image, &progress));
  ASSERT_LT(progress, 100u);

  // Complete rotation
  ASSERT_EQ(0, rotate_key("new_pass"));

  // Status should be 100 after successful rotation
  ASSERT_EQ(0, rbd_encryption_reencrypt_status(m_image, &progress));
  ASSERT_EQ(100u, progress);
#endif
}

TEST_F(KeyRotationInternalTest, ReencryptStatusNoEncryption)
{
  // Status without encryption loaded should return -EINVAL
  uint64_t progress = 0;
  ASSERT_EQ(-EINVAL, rbd_encryption_reencrypt_status(m_image, &progress));
}

TEST_F(KeyRotationInternalTest, EmptyImageRotation)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  // Rotate key on image with no data written.
  // Tests edge case: num_objects == first_data_object, loop runs 0 iterations.
  format_encryption("old_pass");
  ASSERT_EQ(0, rotate_key("new_pass"));

  uint64_t progress = 0;
  ASSERT_EQ(0, rbd_encryption_reencrypt_status(m_image, &progress));
  ASSERT_EQ(100u, progress);

  reopen_image();
  ASSERT_EQ(0, load_encryption("new_pass"));
#endif
}

TEST_F(KeyRotationInternalTest, StatusAfterReopenWithCursor)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  write_pattern(0, BLOCK_SIZE * 4, 0xAA);

  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = ictx;
  ctx.cct = ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx.c_api = true;
  rbd_encryption_luks2_format_options_t opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "new_pass",
    .passphrase_size = 8,
  };
  ctx.opts = &opts;

  librbd::crypto::EncryptionFormat<librbd::ImageCtx>* result_format;
  ASSERT_EQ(0, librbd::api::util::create_encryption_format(
      ictx->cct, RBD_ENCRYPTION_FORMAT_LUKS2,
      &opts, sizeof(opts), true, &result_format));
  ctx.new_format.reset(result_format);

  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_EQ(0, ctx.parse_format_params());
  ASSERT_EQ(0, ctx.prepare_fresh_key());
  ASSERT_EQ(0, ctx.swap_crypto_enter_dual_key());
  ctx.cleanup_dual_key();

  // Reopen — encryption_load should fail with -EUCLEAN due to pending cursor
  reopen_image();
  ASSERT_EQ(-EUCLEAN, load_encryption("old_pass"));

  // Encryption is not loaded, so reencrypt_status should fail
  uint64_t progress = 0;
  ASSERT_EQ(-EINVAL, rbd_encryption_reencrypt_status(m_image, &progress));

  // Resume with both passphrases — loads old key, enters dual-key, re-encrypts
  ASSERT_EQ(0, resume_key_rotate("old_pass", "new_pass"));
  ASSERT_EQ(0, rbd_encryption_reencrypt_status(m_image, &progress));
  ASSERT_EQ(100u, progress);

  verify_pattern(0, BLOCK_SIZE * 4, 0xAA);
#endif
}

TEST_F(KeyRotationInternalTest, DiscardDuringRotation)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  write_pattern(0, BLOCK_SIZE * 8, 0xAA);

  // Discard some blocks, then rotate
  ASSERT_EQ(BLOCK_SIZE * 2, rbd_discard(m_image, BLOCK_SIZE * 4, BLOCK_SIZE * 2));
  ASSERT_EQ(0, rotate_key("new_pass"));

  // Non-discarded blocks should still be readable
  verify_pattern(0, BLOCK_SIZE * 4, 0xAA);
  verify_pattern(BLOCK_SIZE * 6, BLOCK_SIZE * 2, 0xAA);

  reopen_image();
  ASSERT_EQ(0, load_encryption("new_pass"));
  verify_pattern(0, BLOCK_SIZE * 4, 0xAA);
  verify_pattern(BLOCK_SIZE * 6, BLOCK_SIZE * 2, 0xAA);
#endif
}

TEST_F(KeyRotationInternalTest, ResumeWhenEncryptionAlreadyLoaded)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  // Encryption is loaded from format_encryption.
  // Resume should fail with -EEXIST since crypto is already active.
  ASSERT_EQ(-EEXIST, resume_key_rotate("old_pass", "new_pass"));
#endif
}

TEST_F(KeyRotationInternalTest, ResumeWhenNoPendingRotation)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  write_pattern(0, BLOCK_SIZE * 4, 0xAA);

  // Reopen so encryption is not loaded
  reopen_image();

  // No cursor, no unbound keyslot — nothing to resume → -EINVAL
  ASSERT_EQ(-EINVAL, resume_key_rotate("old_pass", "new_pass"));

  // resume loaded old crypto internally before failing; reopen to clear it
  reopen_image();

  // Image should still be usable with normal load
  ASSERT_EQ(0, load_encryption("old_pass"));
  verify_pattern(0, BLOCK_SIZE * 4, 0xAA);
#endif
}

TEST_F(KeyRotationInternalTest, ResumeWithWrongOldPassphrase)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  write_pattern(0, BLOCK_SIZE * 4, 0xAA);

  // Create interrupted state: prepare_fresh_key + swap_crypto + partial reencrypt
  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = ictx;
  ctx.cct = ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx.c_api = true;
  rbd_encryption_luks2_format_options_t opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "new_pass",
    .passphrase_size = 8,
  };
  ctx.opts = &opts;

  librbd::crypto::EncryptionFormat<librbd::ImageCtx>* result_format;
  ASSERT_EQ(0, librbd::api::util::create_encryption_format(
      ictx->cct, RBD_ENCRYPTION_FORMAT_LUKS2,
      &opts, sizeof(opts), true, &result_format));
  ctx.new_format.reset(result_format);

  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_EQ(0, ctx.parse_format_params());
  ASSERT_EQ(0, ctx.prepare_fresh_key());
  ASSERT_EQ(0, ctx.swap_crypto_enter_dual_key());
  ctx.cleanup_dual_key();

  // Reopen — encryption_load should fail with -EUCLEAN
  reopen_image();
  ASSERT_EQ(-EUCLEAN, load_encryption("old_pass"));

  // Resume with wrong OLD passphrase — should fail (can't load old encryption)
  ASSERT_NE(0, resume_key_rotate("wrong_pass", "new_pass"));

  // Correct resume should still work
  ASSERT_EQ(0, resume_key_rotate("old_pass", "new_pass"));
  verify_pattern(0, BLOCK_SIZE * 4, 0xAA);
#endif
}

TEST_F(KeyRotationInternalTest, ResumeWithWrongNewPassphrase)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  write_pattern(0, BLOCK_SIZE * 4, 0xBB);

  // Create interrupted state with new_pass="correct_new"
  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = ictx;
  ctx.cct = ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx.c_api = true;
  rbd_encryption_luks2_format_options_t opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "correct_new",
    .passphrase_size = 11,
  };
  ctx.opts = &opts;

  librbd::crypto::EncryptionFormat<librbd::ImageCtx>* result_format;
  ASSERT_EQ(0, librbd::api::util::create_encryption_format(
      ictx->cct, RBD_ENCRYPTION_FORMAT_LUKS2,
      &opts, sizeof(opts), true, &result_format));
  ctx.new_format.reset(result_format);

  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_EQ(0, ctx.parse_format_params());
  ASSERT_EQ(0, ctx.prepare_fresh_key());
  ASSERT_EQ(0, ctx.swap_crypto_enter_dual_key());
  ctx.cleanup_dual_key();

  // Reopen
  reopen_image();
  ASSERT_EQ(-EUCLEAN, load_encryption("old_pass"));

  // Resume with wrong NEW passphrase — can't unlock unbound keyslot
  ASSERT_NE(0, resume_key_rotate("old_pass", "wrong_new"));

  // Need to reopen since load_old_encryption loaded crypto
  reopen_image();

  // Correct resume works
  ASSERT_EQ(0, resume_key_rotate("old_pass", "correct_new"));
  verify_pattern(0, BLOCK_SIZE * 4, 0xBB);

  // Verify new passphrase works
  reopen_image();
  ASSERT_EQ(0, load_encryption("correct_new"));
  verify_pattern(0, BLOCK_SIZE * 4, 0xBB);
#endif
}

TEST_F(KeyRotationInternalTest, BackupSnapshotReusedOnResume)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  write_pattern(0, BLOCK_SIZE * 4, 0xCC);

  // Full rotation creates and removes a backup snapshot
  ASSERT_EQ(0, rotate_key("new_pass"));

  // After successful rotation, snapshot metadata should be gone
  char val[256];
  size_t val_len = sizeof(val);
  ASSERT_NE(0, rbd_metadata_get(m_image, "rbd_reencrypt_snap", val, &val_len));

  // Now create an interrupted state to test snapshot reuse on resume
  reopen_image();
  ASSERT_EQ(0, load_encryption("new_pass"));

  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = ictx;
  ctx.cct = ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx.c_api = true;
  rbd_encryption_luks2_format_options_t opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "newer_pass",
    .passphrase_size = 10,
  };
  ctx.opts = &opts;

  librbd::crypto::EncryptionFormat<librbd::ImageCtx>* result_format;
  ASSERT_EQ(0, librbd::api::util::create_encryption_format(
      ictx->cct, RBD_ENCRYPTION_FORMAT_LUKS2,
      &opts, sizeof(opts), true, &result_format));
  ctx.new_format.reset(result_format);

  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_EQ(0, ctx.parse_format_params());
  ASSERT_EQ(0, ctx.prepare_fresh_key());
  ASSERT_EQ(0, ctx.create_backup_snapshot());
  ASSERT_EQ(0, ctx.swap_crypto_enter_dual_key());
  ctx.cleanup_dual_key();

  // Snapshot metadata should exist now
  val_len = sizeof(val);
  ASSERT_EQ(0, rbd_metadata_get(m_image, "rbd_reencrypt_snap", val, &val_len));
  std::string snap_before(val, val_len);

  // Reopen and resume — snapshot should be reused, not duplicated
  reopen_image();
  ASSERT_EQ(-EUCLEAN, load_encryption("new_pass"));
  ASSERT_EQ(0, resume_key_rotate("new_pass", "newer_pass"));

  // After completion, snapshot metadata should be cleaned up
  val_len = sizeof(val);
  ASSERT_NE(0, rbd_metadata_get(m_image, "rbd_reencrypt_snap", val, &val_len));

  verify_pattern(0, BLOCK_SIZE * 4, 0xCC);

  reopen_image();
  ASSERT_EQ(0, load_encryption("newer_pass"));
  verify_pattern(0, BLOCK_SIZE * 4, 0xCC);
#endif
}

TEST_F(KeyRotationInternalTest, ResumeWithInvalidFlags)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");

  // Create interrupted state
  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = ictx;
  ctx.cct = ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx.c_api = true;
  rbd_encryption_luks2_format_options_t opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "new_pass",
    .passphrase_size = 8,
  };
  ctx.opts = &opts;

  librbd::crypto::EncryptionFormat<librbd::ImageCtx>* result_format;
  ASSERT_EQ(0, librbd::api::util::create_encryption_format(
      ictx->cct, RBD_ENCRYPTION_FORMAT_LUKS2,
      &opts, sizeof(opts), true, &result_format));
  ctx.new_format.reset(result_format);

  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_EQ(0, ctx.parse_format_params());
  ASSERT_EQ(0, ctx.prepare_fresh_key());
  ASSERT_EQ(0, ctx.swap_crypto_enter_dual_key());
  ctx.cleanup_dual_key();

  reopen_image();

  // Resume with invalid flags via raw C API
  rbd_encryption_luks2_format_options_t old_opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "old_pass",
    .passphrase_size = 8,
  };
  rbd_encryption_luks2_format_options_t new_opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "new_pass",
    .passphrase_size = 8,
  };
  ASSERT_EQ(-EINVAL, rbd_encryption_key_rotate_resume(
      m_image,
      RBD_ENCRYPTION_FORMAT_LUKS2, &old_opts, sizeof(old_opts),
      RBD_ENCRYPTION_FORMAT_LUKS2, &new_opts, sizeof(new_opts),
      0xFF));
  ASSERT_EQ(-EINVAL, rbd_encryption_key_rotate_resume(
      m_image,
      RBD_ENCRYPTION_FORMAT_LUKS2, &old_opts, sizeof(old_opts),
      RBD_ENCRYPTION_FORMAT_LUKS2, &new_opts, sizeof(new_opts),
      0x01));

  // Valid flags (0) should work
  ASSERT_EQ(0, rbd_encryption_key_rotate_resume(
      m_image,
      RBD_ENCRYPTION_FORMAT_LUKS2, &old_opts, sizeof(old_opts),
      RBD_ENCRYPTION_FORMAT_LUKS2, &new_opts, sizeof(new_opts),
      0));
#endif
}

class KeyRotationShutdownTest
    : public KeyRotationInternalTest,
      public ::testing::WithParamInterface<bool> {
protected:
  void TearDown() override {
    if (m_io_thread.joinable()) {
      m_stop_io.store(true, std::memory_order_relaxed);
      m_io_thread.join();
    }
    KeyRotationInternalTest::TearDown();
  }

  bool parallel_io() const { return GetParam(); }

  void start_parallel_io() {
    m_stop_io.store(false, std::memory_order_relaxed);
    m_io_errors.store(0, std::memory_order_relaxed);
    m_io_thread = std::thread([this] {
      std::vector<char> buf(BLOCK_SIZE);
      // Read/write at block-aligned offsets within the image
      uint64_t off = 0;
      while (!m_stop_io.load(std::memory_order_relaxed)) {
        ssize_t r = rbd_read(m_image, off, BLOCK_SIZE, buf.data());
        if (r < 0) {
          m_io_errors.fetch_add(1, std::memory_order_relaxed);
        }
        r = rbd_write(m_image, off, BLOCK_SIZE, buf.data());
        if (r < 0) {
          m_io_errors.fetch_add(1, std::memory_order_relaxed);
        }
        off = (off + BLOCK_SIZE) % (IMAGE_SIZE / 2);
      }
    });
  }

  void stop_parallel_io() {
    m_stop_io.store(true, std::memory_order_relaxed);
    if (m_io_thread.joinable()) {
      m_io_thread.join();
    }
    ASSERT_EQ(0, m_io_errors.load(std::memory_order_relaxed));
  }

  // Re-encrypt `count` objects manually, simulating a partial reencrypt_objects.
  // Sets xattr (same as production code) for resume detection.
  void reencrypt_n_objects(
      librbd::api::KeyRotationContext<librbd::ImageCtx>& ctx,
      uint64_t count) {
    auto* ictx = ctx.ictx;
    uint64_t end = std::min(ctx.start_cursor + count, ctx.num_objects);
    for (uint64_t obj_no = ctx.start_cursor; obj_no < end; obj_no++) {
      ictx->crypto_object_dispatch->set_reencrypting_object(obj_no);

      std::string oid = ictx->get_object_name(obj_no);
      ceph::bufferlist raw_bl;
      int r = ictx->data_ctx.read(oid, raw_bl, ctx.object_size, 0);
      if (r == -ENOENT) {
        ictx->crypto_object_dispatch->advance_reencrypt_cursor(obj_no + 1);
        continue;
      }
      ASSERT_GE(r, 0);

      uint64_t file_offset = obj_no * ctx.object_size - ctx.data_offset;
      ASSERT_EQ(0, ctx.old_crypto->decrypt(&raw_bl, file_offset));
      ASSERT_EQ(0, ctx.new_crypto_ptr->encrypt(&raw_bl, file_offset));

      r = ictx->data_ctx.write_full(oid, raw_bl);
      ASSERT_GE(r, 0);

      // Set xattr to mark as re-encrypted (same as production code).
      // Must use neorados — old librados setxattr is not in the test stub.
      {
        auto io_ctx = ictx->get_data_io_context();
        neorados::WriteOp xattr_op;
        xattr_op.setxattr("rbd_reencrypt", ceph::bufferlist{});
        C_SaferCond xattr_cond;
        ictx->rados_api.execute(
            {oid}, *io_ctx, std::move(xattr_op),
            librbd::asio::util::get_callback_adapter(
                [&xattr_cond](int r) { xattr_cond.complete(r); }));
        r = xattr_cond.wait();
        ASSERT_GE(r, 0);
      }

      ictx->crypto_object_dispatch->advance_reencrypt_cursor(obj_no + 1);
      ASSERT_EQ(0, ictx->operations->metadata_set(
          "rbd_reencrypt_cursor", std::to_string(obj_no + 1)));
    }
  }

  std::atomic<bool> m_stop_io{false};
  std::atomic<int> m_io_errors{0};
  std::thread m_io_thread;
};

INSTANTIATE_TEST_SUITE_P(
    ParallelIO, KeyRotationShutdownTest,
    ::testing::Values(false, true),
    [](const ::testing::TestParamInfo<bool>& info) {
      return info.param ? "WithParallelIO" : "NoParallelIO";
    });

TEST_P(KeyRotationShutdownTest, ResumeAfterPrepareKey_CloseReopen)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  write_pattern(0, BLOCK_SIZE * 4, 0xAA);

  if (parallel_io()) start_parallel_io();

  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = ictx;
  ctx.cct = ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx.c_api = true;
  rbd_encryption_luks2_format_options_t opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "new_pass",
    .passphrase_size = 8,
  };
  ctx.opts = &opts;
  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_EQ(0, ctx.parse_format_params());
  ASSERT_EQ(0, ctx.prepare_fresh_key());

  if (parallel_io()) stop_parallel_io();

  // Close image — destroys all in-memory crypto state
  reopen_image();

  // encryption_load fails with -EUCLEAN due to pending cursor
  ASSERT_EQ(-EUCLEAN, load_encryption("old_pass"));

  // Resume with both passphrases: detects unbound keyslot + cursor, completes rotation
  ASSERT_EQ(0, resume_key_rotate("old_pass", "new_pass"));
  verify_pattern(0, BLOCK_SIZE * 4, 0xAA);

  // Verify new passphrase works after full reopen
  reopen_image();
  ASSERT_EQ(0, load_encryption("new_pass"));
  verify_pattern(0, BLOCK_SIZE * 4, 0xAA);

  // Old passphrase should no longer work
  reopen_image();
  ASSERT_NE(0, load_encryption("old_pass"));
#endif
}

TEST_P(KeyRotationShutdownTest, ResumeAfterPartialReencrypt_CloseReopen)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  // Write pattern across full image so multiple objects have data
  write_pattern(0, IMAGE_SIZE / 2, 0xBB);

  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = ictx;
  ctx.cct = ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx.c_api = true;
  rbd_encryption_luks2_format_options_t opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "new_pass",
    .passphrase_size = 8,
  };
  ctx.opts = &opts;
  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_EQ(0, ctx.parse_format_params());
  ASSERT_EQ(0, ctx.prepare_fresh_key());

  // Create new_format for swap_crypto_enter_dual_key
  librbd::crypto::EncryptionFormat<librbd::ImageCtx>* result_format;
  ASSERT_EQ(0, librbd::api::util::create_encryption_format(
      ictx->cct, RBD_ENCRYPTION_FORMAT_LUKS2,
      &opts, sizeof(opts), true, &result_format));
  ctx.new_format.reset(result_format);

  ASSERT_EQ(0, ctx.swap_crypto_enter_dual_key());

  if (parallel_io()) start_parallel_io();

  // Re-encrypt 5 objects (out of ~8 data objects for 32MB / 4MB)
  reencrypt_n_objects(ctx, 5);

  // Simulate interrupted rotation — stay in dual-key mode.
  // IO continues to work (correct key selection via cursor).
  if (parallel_io()) stop_parallel_io();

  // Close and reopen — all in-memory state destroyed
  reopen_image();
  // encryption_load fails with -EUCLEAN due to pending cursor
  ASSERT_EQ(-EUCLEAN, load_encryption("old_pass"));

  // Resume with both passphrases: re-encrypts remaining objects from cursor
  ASSERT_EQ(0, resume_key_rotate("old_pass", "new_pass"));
  verify_pattern(0, IMAGE_SIZE / 2, 0xBB);

  // Verify new passphrase
  reopen_image();
  ASSERT_EQ(0, load_encryption("new_pass"));
  verify_pattern(0, IMAGE_SIZE / 2, 0xBB);
#endif
}

TEST_P(KeyRotationShutdownTest, ResumeAfterAllObjectsReencrypted_CloseReopen)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  write_pattern(0, BLOCK_SIZE * 4, 0xCC);

  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = ictx;
  ctx.cct = ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx.c_api = true;
  rbd_encryption_luks2_format_options_t opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "new_pass",
    .passphrase_size = 8,
  };
  ctx.opts = &opts;
  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_EQ(0, ctx.parse_format_params());
  ASSERT_EQ(0, ctx.prepare_fresh_key());

  // Create new_format and enter dual-key mode
  librbd::crypto::EncryptionFormat<librbd::ImageCtx>* result_format;
  ASSERT_EQ(0, librbd::api::util::create_encryption_format(
      ictx->cct, RBD_ENCRYPTION_FORMAT_LUKS2,
      &opts, sizeof(opts), true, &result_format));
  ctx.new_format.reset(result_format);

  ASSERT_EQ(0, ctx.swap_crypto_enter_dual_key());

  // Re-encrypt ALL objects
  ASSERT_EQ(0, ctx.reencrypt_objects());

  // Do NOT call write_final_header — simulate crash here.
  // Stay in dual-key mode (all objects already re-encrypted).

  // Close and reopen
  reopen_image();
  // encryption_load fails with -EUCLEAN due to pending cursor
  ASSERT_EQ(-EUCLEAN, load_encryption("old_pass"));

  // Resume with both passphrases: cursor at num_objects → skips reencrypt, writes final header
  ASSERT_EQ(0, resume_key_rotate("old_pass", "new_pass"));
  verify_pattern(0, BLOCK_SIZE * 4, 0xCC);

  // Verify new passphrase
  reopen_image();
  ASSERT_EQ(0, load_encryption("new_pass"));
  verify_pattern(0, BLOCK_SIZE * 4, 0xCC);

  // Old passphrase should fail
  reopen_image();
  ASSERT_NE(0, load_encryption("old_pass"));
#endif
}

TEST_P(KeyRotationShutdownTest, FreshRotationAfterCleanShutdown)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  write_pattern(0, BLOCK_SIZE * 4, 0xDD);

  if (parallel_io()) start_parallel_io();

  // Run only early phases — no RADOS writes
  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = ictx;
  ctx.cct = ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx.c_api = true;
  rbd_encryption_luks2_format_options_t opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "new_pass",
    .passphrase_size = 8,
  };
  ctx.opts = &opts;
  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_EQ(0, ctx.parse_format_params());
  // No prepare_fresh_key — no on-disk state written

  if (parallel_io()) stop_parallel_io();

  // Close and reopen — no persistent rotation state
  reopen_image();
  ASSERT_EQ(0, load_encryption("old_pass"));

  // Fresh rotation (no unbound keyslot, no cursor)
  ASSERT_EQ(0, rotate_key("new_pass"));
  verify_pattern(0, BLOCK_SIZE * 4, 0xDD);

  // Verify new passphrase
  reopen_image();
  ASSERT_EQ(0, load_encryption("new_pass"));
  verify_pattern(0, BLOCK_SIZE * 4, 0xDD);
#endif
}

TEST_P(KeyRotationShutdownTest, OnlineResumeWithConcurrentIO)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  // Use a larger image (128MB) so there are more data objects (~28)
  // to spread IO across during the concurrent resume.
  constexpr uint64_t LARGE_IMAGE_SIZE = 128 << 20;
  constexpr uint64_t DATA_SIZE = LARGE_IMAGE_SIZE / 2;
  ASSERT_EQ(0, rbd_resize(m_image, LARGE_IMAGE_SIZE));

  format_encryption("old_pass");
  write_pattern(0, DATA_SIZE, 0xEE);

  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = ictx;
  ctx.cct = ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx.c_api = true;
  rbd_encryption_luks2_format_options_t opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "new_pass",
    .passphrase_size = 8,
  };
  ctx.opts = &opts;
  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_EQ(0, ctx.parse_format_params());
  ASSERT_EQ(0, ctx.prepare_fresh_key());

  // Create new_format for swap_crypto_enter_dual_key
  librbd::crypto::EncryptionFormat<librbd::ImageCtx>* result_format;
  ASSERT_EQ(0, librbd::api::util::create_encryption_format(
      ictx->cct, RBD_ENCRYPTION_FORMAT_LUKS2,
      &opts, sizeof(opts), true, &result_format));
  ctx.new_format.reset(result_format);

  ASSERT_EQ(0, ctx.swap_crypto_enter_dual_key());

  // Re-encrypt 5 objects (out of ~28 data objects for 128MB / 4MB)
  reencrypt_n_objects(ctx, 5);

  // Simulate interrupted rotation — stay in dual-key mode.
  // IO continues to work (correct key selection via cursor).

  constexpr int NUM_IO_THREADS = 4;
  std::vector<std::thread> io_threads;
  std::atomic<int> io_errors{0};
  std::atomic<bool> stop_io{false};

  if (parallel_io()) {
    // Spawn multiple reader threads that validate content while
    // dual-key mode is active and rotate_key resumes concurrently.
    for (int t = 0; t < NUM_IO_THREADS; t++) {
      io_threads.emplace_back([this, &stop_io, &io_errors, t] {
        std::vector<char> buf(BLOCK_SIZE);
        std::vector<char> expected(BLOCK_SIZE, static_cast<char>(0xEE));
        // Each thread starts at a different offset to spread reads
        uint64_t off = (t * BLOCK_SIZE) % DATA_SIZE;
        while (!stop_io.load(std::memory_order_relaxed)) {
          ssize_t r = rbd_read(m_image, off, BLOCK_SIZE, buf.data());
          if (r < 0) {
            std::cerr << "IO ERROR: thread " << t << " read at offset "
                      << off << " returned " << r << std::endl;
            io_errors.fetch_add(1, std::memory_order_relaxed);
          } else if (r == BLOCK_SIZE) {
            // Validate read content matches the written pattern
            if (memcmp(buf.data(), expected.data(), BLOCK_SIZE) != 0) {
              // Find first mismatch byte
              size_t mpos = 0;
              for (size_t i = 0; i < BLOCK_SIZE; i++) {
                if (buf[i] != expected[i]) { mpos = i; break; }
              }
              std::cerr << "DATA MISMATCH: thread " << t << " at offset "
                        << off << " first_mismatch_byte=" << mpos
                        << " got=0x" << std::hex
                        << (unsigned)(unsigned char)buf[mpos]
                        << std::dec << std::endl;
              io_errors.fetch_add(1, std::memory_order_relaxed);
            }
          }
          off = (off + BLOCK_SIZE) % DATA_SIZE;
        }
      });
    }
  }

  // Resume rotation on the SAME open image while IO threads are running
  ASSERT_EQ(0, rotate_key("new_pass"));

  if (parallel_io()) {
    // Let IO run briefly after rotation completes to exercise the
    // new single-key mode under concurrent load from multiple threads
    usleep(200000);
    stop_io.store(true, std::memory_order_relaxed);
    for (auto& t : io_threads) {
      t.join();
    }
    ASSERT_EQ(0, io_errors.load(std::memory_order_relaxed));
  }

  verify_pattern(0, DATA_SIZE, 0xEE);

  // Verify new passphrase works after full reopen
  reopen_image();
  ASSERT_EQ(0, load_encryption("new_pass"));
  verify_pattern(0, DATA_SIZE, 0xEE);

  // Old passphrase should no longer work
  reopen_image();
  ASSERT_NE(0, load_encryption("old_pass"));
#endif
}

TEST_P(KeyRotationShutdownTest, MultipleCrashResumeCycles)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  write_pattern(0, IMAGE_SIZE / 2, 0xBB);

  // --- Phase 1: partial reencrypt (3 objects), then "crash" ---
  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = ictx;
  ctx.cct = ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx.c_api = true;
  rbd_encryption_luks2_format_options_t opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "new_pass",
    .passphrase_size = 8,
  };
  ctx.opts = &opts;

  librbd::crypto::EncryptionFormat<librbd::ImageCtx>* result_format;
  ASSERT_EQ(0, librbd::api::util::create_encryption_format(
      ictx->cct, RBD_ENCRYPTION_FORMAT_LUKS2,
      &opts, sizeof(opts), true, &result_format));
  ctx.new_format.reset(result_format);

  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_EQ(0, ctx.parse_format_params());
  ASSERT_EQ(0, ctx.prepare_fresh_key());
  ASSERT_EQ(0, ctx.create_backup_snapshot());
  ASSERT_EQ(0, ctx.swap_crypto_enter_dual_key());

  if (parallel_io()) start_parallel_io();
  reencrypt_n_objects(ctx, 3);
  if (parallel_io()) stop_parallel_io();

  // "Crash" — close and reopen
  reopen_image();
  ASSERT_EQ(-EUCLEAN, load_encryption("old_pass"));

  // --- Phase 2: resume loads old encryption + enters dual-key, but we
  // interrupt again by manually doing only 2 more objects ---
  ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx2;
  ctx2.ictx = ictx;
  ctx2.cct = ictx->cct;
  ctx2.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx2.c_api = true;
  ctx2.opts = &opts;

  ASSERT_EQ(0, librbd::api::util::create_encryption_format(
      ictx->cct, RBD_ENCRYPTION_FORMAT_LUKS2,
      &opts, sizeof(opts), true, &result_format));
  ctx2.new_format.reset(result_format);

  // Load old encryption manually
  rbd_encryption_luks2_format_options_t old_opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "old_pass",
    .passphrase_size = 8,
  };
  ASSERT_EQ(0, ctx2.load_old_encryption(
      RBD_ENCRYPTION_FORMAT_LUKS2, &old_opts, sizeof(old_opts), true));
  ASSERT_EQ(0, ctx2.compute_object_layout());
  ASSERT_EQ(0, ctx2.parse_format_params());

  ceph::bufferlist header_bl;
  ASSERT_EQ(0, ctx2.read_luks_header(&header_bl));
  ASSERT_EQ(0, ctx2.load_header_and_detect_resume(header_bl));
  ASSERT_TRUE(ctx2.is_resume);
  ASSERT_EQ(0, ctx2.swap_crypto_enter_dual_key());

  // Re-encrypt 2 more objects, then "crash" again
  reencrypt_n_objects(ctx2, 2);
  ctx2.cleanup_dual_key();

  reopen_image();
  ASSERT_EQ(-EUCLEAN, load_encryption("old_pass"));

  // --- Phase 3: full resume to completion ---
  ASSERT_EQ(0, resume_key_rotate("old_pass", "new_pass"));
  verify_pattern(0, IMAGE_SIZE / 2, 0xBB);

  // Verify new passphrase works
  reopen_image();
  ASSERT_EQ(0, load_encryption("new_pass"));
  verify_pattern(0, IMAGE_SIZE / 2, 0xBB);

  // Old passphrase should fail
  reopen_image();
  ASSERT_NE(0, load_encryption("old_pass"));
#endif
}

TEST_F(KeyRotationInternalTest, XattrSkipsAlreadyReencryptedObjects)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  write_pattern(0, IMAGE_SIZE / 2, 0xAA);

  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = ictx;
  ctx.cct = ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx.c_api = true;
  rbd_encryption_luks2_format_options_t opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "new_pass",
    .passphrase_size = 8,
  };
  ctx.opts = &opts;

  librbd::crypto::EncryptionFormat<librbd::ImageCtx>* result_format;
  ASSERT_EQ(0, librbd::api::util::create_encryption_format(
      ictx->cct, RBD_ENCRYPTION_FORMAT_LUKS2,
      &opts, sizeof(opts), true, &result_format));
  ctx.new_format.reset(result_format);

  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_EQ(0, ctx.parse_format_params());
  ASSERT_EQ(0, ctx.prepare_fresh_key());
  ASSERT_EQ(0, ctx.swap_crypto_enter_dual_key());

  // Re-encrypt all objects — this sets xattrs via compound op
  ASSERT_EQ(0, ctx.reencrypt_objects());

  // Verify xattr exists on a data object via neorados
  std::string first_data_oid = ictx->get_object_name(ctx.first_data_object);
  {
    auto io_ctx = ictx->get_data_io_context();
    ceph::bufferlist xattr_bl;
    boost::system::error_code ec;
    neorados::ReadOp read_op;
    read_op.get_xattr("rbd_reencrypt", &xattr_bl, &ec);
    C_SaferCond cond;
    ictx->rados_api.execute(
        {first_data_oid}, *io_ctx, std::move(read_op), nullptr,
        librbd::asio::util::get_callback_adapter(
            [&cond](int r) { cond.complete(r); }));
    ASSERT_EQ(0, cond.wait());
    ASSERT_FALSE(ec);
  }

  // Reset cursor to start — simulating a crash that lost cursor state.
  // reencrypt_objects should skip all objects thanks to xattrs
  // (instead of double-encrypting them, which would corrupt data).
  ASSERT_EQ(0, ictx->operations->metadata_set(
      "rbd_reencrypt_cursor",
      std::to_string(ctx.first_data_object)));
  ctx.start_cursor = ctx.first_data_object;
  ctx.is_resume = true;  // xattr check only runs on resume

  // Re-run reencrypt_objects — xattr check should skip everything
  ASSERT_EQ(0, ctx.reencrypt_objects());

  // Finish rotation normally
  ASSERT_EQ(0, ctx.persist_final_state());
  ASSERT_EQ(0, ctx.finish_and_cleanup());

  // Data should still be intact (not double-encrypted)
  verify_pattern(0, IMAGE_SIZE / 2, 0xAA);

  // Verify xattr was cleaned up via neorados
  {
    auto io_ctx = ictx->get_data_io_context();
    ceph::bufferlist xattr_bl;
    boost::system::error_code ec;
    neorados::ReadOp read_op;
    read_op.get_xattr("rbd_reencrypt", &xattr_bl, &ec);
    C_SaferCond cond;
    ictx->rados_api.execute(
        {first_data_oid}, *io_ctx, std::move(read_op), nullptr,
        librbd::asio::util::get_callback_adapter(
            [&cond](int r) { cond.complete(r); }));
    // get_xattr returns -ENODATA when xattr doesn't exist, but the
    // error may surface via ec or the execute return code depending
    // on the test stub — accept either signal.
    int r = cond.wait();
    ASSERT_TRUE(r < 0 || ec);
  }

  // Verify new passphrase works after reopen
  reopen_image();
  ASSERT_EQ(0, load_encryption("new_pass"));
  verify_pattern(0, IMAGE_SIZE / 2, 0xAA);
#endif
}

TEST_F(KeyRotationInternalTest, XattrCleanedUpAfterSuccessfulRotation)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  write_pattern(0, BLOCK_SIZE * 4, 0xBB);

  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);

  // Full rotation via public API
  ASSERT_EQ(0, rotate_key("new_pass"));

  // Verify xattr is gone on the first data object via neorados
  uint64_t data_offset = ictx->encryption_format->get_crypto()->get_data_offset();
  uint64_t obj_size_layout = ictx->layout.object_size;
  uint64_t first_data_obj = data_offset / obj_size_layout;
  if (data_offset % obj_size_layout != 0) first_data_obj++;

  std::string first_data_oid = ictx->get_object_name(first_data_obj);
  {
    auto io_ctx = ictx->get_data_io_context();
    ceph::bufferlist xattr_bl;
    boost::system::error_code ec;
    neorados::ReadOp read_op;
    read_op.get_xattr("rbd_reencrypt", &xattr_bl, &ec);
    C_SaferCond cond;
    ictx->rados_api.execute(
        {first_data_oid}, *io_ctx, std::move(read_op), nullptr,
        librbd::asio::util::get_callback_adapter(
            [&cond](int r) { cond.complete(r); }));
    int r = cond.wait();
    ASSERT_TRUE(r < 0 || ec);
  }

  // Data intact
  verify_pattern(0, BLOCK_SIZE * 4, 0xBB);

  // New passphrase works
  reopen_image();
  ASSERT_EQ(0, load_encryption("new_pass"));
  verify_pattern(0, BLOCK_SIZE * 4, 0xBB);
#endif
}

TEST_P(KeyRotationShutdownTest, ResumeWithXattrSkipsCompletedObjects)
{
  REQUIRE(!is_feature_enabled(RBD_FEATURE_JOURNALING));

#ifndef HAVE_LIBCRYPTSETUP
  return;
#else
  format_encryption("old_pass");
  write_pattern(0, IMAGE_SIZE / 2, 0xCC);

  auto* ictx = reinterpret_cast<librbd::ImageCtx*>(m_image);
  librbd::api::KeyRotationContext<librbd::ImageCtx> ctx;
  ctx.ictx = ictx;
  ctx.cct = ictx->cct;
  ctx.format = RBD_ENCRYPTION_FORMAT_LUKS2;
  ctx.c_api = true;
  rbd_encryption_luks2_format_options_t opts = {
    .alg = RBD_ENCRYPTION_ALGORITHM_AES256,
    .passphrase = "new_pass",
    .passphrase_size = 8,
  };
  ctx.opts = &opts;

  librbd::crypto::EncryptionFormat<librbd::ImageCtx>* result_format;
  ASSERT_EQ(0, librbd::api::util::create_encryption_format(
      ictx->cct, RBD_ENCRYPTION_FORMAT_LUKS2,
      &opts, sizeof(opts), true, &result_format));
  ctx.new_format.reset(result_format);

  ASSERT_EQ(0, ctx.compute_object_layout());
  ASSERT_EQ(0, ctx.parse_format_params());
  ASSERT_EQ(0, ctx.prepare_fresh_key());
  ASSERT_EQ(0, ctx.swap_crypto_enter_dual_key());

  if (parallel_io()) start_parallel_io();

  // Re-encrypt 5 objects with xattr markers
  reencrypt_n_objects(ctx, 5);

  if (parallel_io()) stop_parallel_io();

  // Simulate crash: reset persisted cursor to BEFORE the 5 objects
  // (as if cursor persistence lagged behind actual progress).
  ASSERT_EQ(0, ictx->operations->metadata_set(
      "rbd_reencrypt_cursor",
      std::to_string(ctx.first_data_object)));

  // Close and reopen — all in-memory state lost
  reopen_image();
  ASSERT_EQ(-EUCLEAN, load_encryption("old_pass"));

  // Resume: cursor says start from beginning, but xattrs on the first
  // 5 objects will cause them to be skipped (no double re-encryption).
  ASSERT_EQ(0, resume_key_rotate("old_pass", "new_pass"));

  // Data should be intact — the 5 objects were not double-encrypted
  verify_pattern(0, IMAGE_SIZE / 2, 0xCC);

  // New passphrase works
  reopen_image();
  ASSERT_EQ(0, load_encryption("new_pass"));
  verify_pattern(0, IMAGE_SIZE / 2, 0xCC);
#endif
}
