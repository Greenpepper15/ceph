// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>
#include "include/scope_guard.h"
#include "test/librbd/test_mock_fixture.h"
#include "test/librbd/test_support.h"
#include "test/librbd/mock/MockImageCtx.h"

namespace librbd {
namespace util {

inline ImageCtx *get_image_ctx(MockImageCtx *image_ctx) {
  return image_ctx->image_ctx;
}

} // namespace util
} // namespace librbd

#include "librbd/crypto/luks/GetVolumeKeyRequest.cc"
#include "librbd/crypto/luks/HeaderBackupRequest.cc"
#include "librbd/crypto/luks/HeaderRestoreRequest.cc"
#include "librbd/crypto/luks/ReadHeaderRequest.cc"
#include "librbd/crypto/luks/UpdateHeaderRequest.cc"

namespace librbd {
namespace crypto {
namespace luks {

using ::testing::_;
using ::testing::Invoke;
using ::testing::Return;

struct TestMockCryptoLuksUpdateHeaderRequest : public TestMockFixture {
  typedef GetVolumeKeyRequest<librbd::MockImageCtx> MockGetVolumeKeyRequest;
  typedef HeaderBackupRequest<librbd::MockImageCtx> MockHeaderBackupRequest;
  typedef HeaderRestoreRequest<librbd::MockImageCtx> MockHeaderRestoreRequest;
  typedef ReadHeaderRequest<librbd::MockImageCtx> MockReadHeaderRequest;
  typedef UpdateHeaderRequest<librbd::MockImageCtx> MockUpdateHeaderRequest;

  const size_t OBJECT_SIZE = 4 * 1024 * 1024;
  const std::string passphrase = "password";
  const std::string new_passphrase = "new-password";

  librbd::ImageCtx* ictx;
  MockImageCtx* mock_image_ctx;
  MockImageCtx* mock_parent_image_ctx = nullptr;
  // the image content, [0, data_offset)
  ceph::bufferlist image_bl;
  // the volume key the header was formatted with
  std::string volume_key;
  // reads issued by the request, completed by drain_reads()
  std::vector<Context*> read_requests;
  // (offset, length) of every write the request issued
  std::vector<std::pair<uint64_t, uint64_t>> writes;
  size_t flushes = 0;
  // lets a test drop, corrupt or fail a write: gets the write's index and
  // payload, returns the write's result and whether to store the payload
  std::function<int(size_t, ceph::bufferlist*, bool*)> on_write;

  void SetUp() override {
    TestMockFixture::SetUp();

    ASSERT_EQ(0, open_image(m_image_name, &ictx));
    mock_image_ctx = new MockImageCtx(*ictx);
    mock_image_ctx->snap_id = CEPH_NOSNAP;
    mock_image_ctx->read_only = false;
    expect_image_io();
    expect_get_image_size();
  }

  void TearDown() override {
    delete mock_parent_image_ctx;
    delete mock_image_ctx;
    TestMockFixture::TearDown();
  }

  // keyslots holds passphrase and gets pbkdf, or the fast settings of
  // format() without it
  void generate_header(const char* type, uint32_t sector_size,
                       bool clone_magic = false,
                       const struct crypt_pbkdf_type* pbkdf = nullptr,
                       int keyslots = 1) {
    Header header(mock_image_ctx->cct);

    ASSERT_EQ(0, header.init());
    ASSERT_EQ(0, header.format(type, "aes", nullptr, 64, "xts-plain64",
                               sector_size, OBJECT_SIZE, true));
    if (pbkdf != nullptr) {
      ASSERT_EQ(0, header.set_pbkdf(pbkdf));
    }
    for (int i = 0; i < keyslots; ++i) {
      ASSERT_EQ(0, header.add_keyslot(passphrase.c_str(), passphrase.size()));
    }
    char key[64];
    size_t key_size = sizeof(key);
    ASSERT_EQ(0, header.read_volume_key(passphrase.c_str(), passphrase.size(),
                                        key, &key_size));
    volume_key.assign(key, key_size);
    auto data_offset = header.get_data_offset();
    ASSERT_LT(0, header.read(&image_bl));
    ASSERT_LE(image_bl.length(), data_offset);
    image_bl.append_zero(data_offset - image_bl.length());
    if (clone_magic) {
      ASSERT_EQ(0, Magic::replace_magic(mock_image_ctx->cct, image_bl));
      mock_parent_image_ctx = new MockImageCtx(*ictx);
      mock_image_ctx->parent = mock_parent_image_ctx;
    }
    image_bl.rebuild();
  }

  // adds a LUKS2 keyslot with a key of its own, not bound to the data,
  // as keyslot 1
  void add_unbound_keyslot(const std::string& pass) {
    char path[] = "/tmp/luks-unbound-XXXXXX";
    int fd = mkstemp(path);
    ASSERT_LE(0, fd);
    auto sg = make_scope_guard([&] {
      close(fd);
      unlink(path);
    });
    ASSERT_EQ(static_cast<ssize_t>(image_bl.length()),
              pwrite(fd, image_bl.c_str(), image_bl.length(), 0));
    // libcryptsetup checks the device size, see Header::load()
    ASSERT_EQ(0, ftruncate(fd, ANONYMOUS_FILE_SIZE));

    struct crypt_device* cd = nullptr;
    ASSERT_EQ(0, crypt_init(&cd, path));
    ASSERT_EQ(0, crypt_load(cd, CRYPT_LUKS2, nullptr));
    struct crypt_pbkdf_type pbkdf = {};
    pbkdf.type = CRYPT_KDF_PBKDF2;
    pbkdf.hash = "sha256";
    pbkdf.iterations = 1000;
    pbkdf.flags = CRYPT_PBKDF_NO_BENCHMARK;
    ASSERT_EQ(0, crypt_set_pbkdf_type(cd, &pbkdf));
    ASSERT_EQ(1, crypt_keyslot_add_by_key(
            cd, CRYPT_ANY_SLOT, nullptr, 64, pass.c_str(), pass.size(),
            CRYPT_VOLUME_KEY_NO_SEGMENT));
    crypt_free(cd);

    ceph::bufferptr bp(image_bl.length());
    ASSERT_EQ(static_cast<ssize_t>(bp.length()),
              pread(fd, bp.c_str(), bp.length(), 0));
    image_bl.clear();
    image_bl.push_back(std::move(bp));
  }

  // destroys a keyslot the way cryptsetup outside librbd would
  void destroy_keyslot_outside(int keyslot) {
    char path[] = "/tmp/luks-destroy-XXXXXX";
    int fd = mkstemp(path);
    ASSERT_LE(0, fd);
    auto sg = make_scope_guard([&] {
      close(fd);
      unlink(path);
    });
    ASSERT_EQ(static_cast<ssize_t>(image_bl.length()),
              pwrite(fd, image_bl.c_str(), image_bl.length(), 0));
    ASSERT_EQ(0, ftruncate(fd, ANONYMOUS_FILE_SIZE));

    struct crypt_device* cd = nullptr;
    ASSERT_EQ(0, crypt_init(&cd, path));
    ASSERT_EQ(0, crypt_load(cd, CRYPT_LUKS, nullptr));
    ASSERT_EQ(0, crypt_keyslot_destroy(cd, keyslot));
    crypt_free(cd);

    ceph::bufferptr bp(image_bl.length());
    ASSERT_EQ(static_cast<ssize_t>(bp.length()),
              pread(fd, bp.c_str(), bp.length(), 0));
    image_bl.clear();
    image_bl.push_back(std::move(bp));
  }

  void expect_image_io() {
    EXPECT_CALL(*mock_image_ctx->io_image_dispatcher, send(_))
            .WillRepeatedly(Invoke([this](io::ImageDispatchSpec* spec) {
                spec->dispatch_result = io::DISPATCH_RESULT_COMPLETE;
                auto aio_comp = spec->aio_comp;

                if (auto* read = std::get_if<io::ImageDispatchSpec::Read>(
                            &spec->request); read != nullptr) {
                  ASSERT_EQ(1, spec->image_extents.size());
                  auto [offset, length] = spec->image_extents[0];
                  aio_comp->set_request_count(1);
                  aio_comp->read_result = std::move(read->read_result);
                  aio_comp->read_result.set_image_extents(spec->image_extents);
                  auto ctx = new io::ReadResult::C_ImageReadRequest(
                          aio_comp, 0, spec->image_extents);
                  // ReadHeaderRequest replaces the clone magic in ctx->bl
                  // in place, which must not change image_bl.
                  uint64_t stored = 0;
                  if (offset < image_bl.length()) {
                    stored = std::min<uint64_t>(
                            length, image_bl.length() - offset);
                    ctx->bl.append(image_bl.c_str() + offset, stored);
                  }
                  // image_bl does not end at data offset. The rest is zero'ed
                  ctx->bl.append_zero(length - stored);
                  read_requests.push_back(ctx);
                  return;
                }

                int r = 0;
                if (auto* write = std::get_if<io::ImageDispatchSpec::Write>(
                            &spec->request); write != nullptr) {
                  ASSERT_EQ(1, spec->image_extents.size());
                  auto [offset, length] = spec->image_extents[0];
                  ASSERT_EQ(length, write->bl.length());
                  ASSERT_LE(offset + length, image_bl.length());
                  writes.emplace_back(offset, length);
                  bool store = true;
                  if (on_write) {
                    r = on_write(writes.size() - 1, &write->bl, &store);
                  }
                  if (store) {
                    store_write(offset, write->bl);
                  }
                } else if (std::holds_alternative<io::ImageDispatchSpec::Flush>(
                                   spec->request)) {
                  ++flushes;
                }

                aio_comp->set_request_count(1);
                aio_comp->add_request();
                aio_comp->complete_request(r);
            }));
  }

  void store_write(uint64_t offset, const ceph::bufferlist& bl) {
    ceph::bufferlist updated;
    updated.substr_of(image_bl, 0, offset);
    updated.append(bl);
    ceph::bufferlist tail;
    tail.substr_of(image_bl, offset + bl.length(),
                   image_bl.length() - offset - bl.length());
    updated.append(tail);
    // keep c_str() contiguous for the next read
    updated.rebuild();
    image_bl = std::move(updated);
  }

  void expect_get_image_size() {
    EXPECT_CALL(*mock_image_ctx, get_image_size(_))
            .WillRepeatedly(Return(OBJECT_SIZE << 5));
  }

  // completing a read issues the next one synchronously, so every read the
  // request makes completes here
  void drain_reads() {
    for (size_t i = 0; i < read_requests.size(); i++) {
      auto ctx = read_requests[i];
      ctx->complete(0);
    }
  }

  template <typename Create>
  int run(Create&& create) {
    read_requests.clear();
    writes.clear();
    flushes = 0;
    C_SaferCond cond;
    auto req = create(&cond);
    req->send();
    drain_reads();
    return cond.wait();
  }

  int add_keyslot(int keyslot, const std::string& key,
                  const std::string& pass, int* result_keyslot,
                  std::optional<KdfSettings> kdf = std::nullopt) {
    return run([&](Context* ctx) {
      return MockUpdateHeaderRequest::create_add_keyslot(
              mock_image_ctx, keyslot, key, pass, kdf, result_keyslot, ctx);
    });
  }

  int remove_keyslot(int keyslot) {
    return run([&](Context* ctx) {
      return MockUpdateHeaderRequest::create_remove_keyslot(
              mock_image_ctx, keyslot, ctx);
    });
  }

  int get_volume_key(const std::string& pass, std::string* key, int* keyslot,
                     size_t* key_size = nullptr, size_t max_size = SIZE_MAX) {
    size_t size = 0;
    auto r = run([&](Context* ctx) {
      return MockGetVolumeKeyRequest::create(
              mock_image_ctx, pass, max_size, key, &size, keyslot, ctx);
    });
    if (key_size != nullptr) {
      *key_size = size;
    }
    return r;
  }

  int header_dump(std::string* dump, size_t* dump_size = nullptr,
                  size_t max_size = SIZE_MAX) {
    size_t size = 0;
    auto r = run([&](Context* ctx) {
      return MockHeaderBackupRequest::create(mock_image_ctx, max_size, dump,
                                             &size, ctx);
    });
    if (dump_size != nullptr) {
      *dump_size = size;
    }
    return r;
  }

  int header_restore(const std::string& dump) {
    return run([&](Context* ctx) {
      return MockHeaderRestoreRequest::create(mock_image_ctx, dump, ctx);
    });
  }

  // a header dump of another image whose data offset differs: the same
  // version, formatted with a larger alignment
  std::string other_header_dump(const char* type, uint32_t sector_size) {
    Header header(mock_image_ctx->cct);
    EXPECT_EQ(0, header.init());
    EXPECT_EQ(0, header.format(type, "aes", nullptr, 64, "xts-plain64",
                               sector_size, 3 * OBJECT_SIZE, true));
    EXPECT_EQ(0, header.add_keyslot(passphrase.c_str(), passphrase.size()));
    ceph::bufferlist bl;
    EXPECT_LT(0, header.read(&bl));
    bl.append_zero(header.get_data_offset() - bl.length());
    return std::string(bl.c_str(), bl.length());
  }

  // lists the keyslots the way util::luks_keyslot_list() does
  int list_keyslots(std::vector<encryption_luks_keyslot_info_t>* keyslots) {
    Header header(mock_image_ctx->cct);
    auto r = run([&](Context* ctx) {
      return MockReadHeaderRequest::create(
              mock_image_ctx, io::ImageArea::DATA, RBD_ENCRYPTION_FORMAT_LUKS,
              false, &header, nullptr, nullptr, nullptr, nullptr, ctx);
    });
    if (r < 0) {
      return r;
    }
    return header.list_keyslots(keyslots);
  }

  std::vector<int> listed_slots() {
    std::vector<encryption_luks_keyslot_info_t> keyslots;
    std::vector<int> slots;
    EXPECT_EQ(0, list_keyslots(&keyslots));
    for (auto& k : keyslots) {
      slots.push_back(k.keyslot);
    }
    return slots;
  }

  // unlocks the header as the image now stores it, with its LUKS magic
  // restored if it was stored as a clone; 0 if passphrase recovers the
  // image's original volume key
  int unlock_luks(const std::string& passphrase) {
    // a deep copy: replace_magic() works in place
    ceph::bufferlist bl;
    bl.append(image_bl.c_str(), image_bl.length());
    if (Magic::is_rbd_clone(bl) > 0) {
      auto r = Magic::replace_magic(mock_image_ctx->cct, bl);
      if (r < 0) {
        return r;
      }
    }
    Header header(mock_image_ctx->cct);
    auto r = header.init();
    if (r == 0) {
      r = header.write(bl);
    }
    if (r == 0) {
      r = header.load(CRYPT_LUKS);
    }
    if (r < 0) {
      return r;
    }

    char key[64];
    size_t key_size = sizeof(key);
    r = header.read_volume_key(passphrase.c_str(), passphrase.size(), key,
                               &key_size);
    if (r < 0) {
      return r;
    }

    return std::string(key, key_size) == volume_key ? 0 : -EBADMSG;
  }
};

struct TestMockCryptoLuksUpdateHeaderRequestPerVersion
    : public TestMockCryptoLuksUpdateHeaderRequest,
      public ::testing::WithParamInterface<const char*> {
  // LUKS1 only supports 512-byte sectors
  uint32_t sector_size() const {
    return strcmp(GetParam(), CRYPT_LUKS1) == 0 ? 512 : 4096;
  }
};

TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion, AddKeyslot) {
  generate_header(GetParam(), sector_size());

  int added = -1;
  ASSERT_EQ(0, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                           new_passphrase, &added));
  ASSERT_EQ(1, added);
  ASSERT_FALSE(writes.empty());
  ASSERT_EQ(1u, flushes);
  ASSERT_EQ(0, unlock_luks(passphrase));
  ASSERT_EQ(0, unlock_luks(new_passphrase));
  ASSERT_EQ((std::vector<int>{0, 1}), listed_slots());
}

TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion, AddExplicitKeyslot) {
  generate_header(GetParam(), sector_size());

  int added = -1;
  ASSERT_EQ(0, add_keyslot(5, volume_key, new_passphrase, &added));
  ASSERT_EQ(5, added);
  ASSERT_EQ((std::vector<int>{0, 5}), listed_slots());
}

// a benchmark of this host would have chosen other settings than the fast
// PBKDF2 settings of keyslot 0, the lowest keyslot in use
TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion,
       AddKeyslotCopiesKdfSettings) {
  generate_header(GetParam(), sector_size());

  int added = -1;
  ASSERT_EQ(0, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                           new_passphrase, &added));
  std::vector<encryption_luks_keyslot_info_t> keyslots;
  ASSERT_EQ(0, list_keyslots(&keyslots));
  ASSERT_EQ(2u, keyslots.size());
  ASSERT_EQ("pbkdf2", keyslots[1].kdf);
  ASSERT_EQ(keyslots[0].hash, keyslots[1].hash);
  ASSERT_EQ(1000u, keyslots[1].kdf_iterations);
  ASSERT_EQ(0u, keyslots[1].kdf_memory_kb);
  ASSERT_EQ(0u, keyslots[1].kdf_threads);
}

TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion,
       AddKeyslotWithKdfSettings) {
  generate_header(GetParam(), sector_size());

  int added = -1;
  ASSERT_EQ(0, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                           new_passphrase, &added,
                           KdfSettings{"pbkdf2", "sha256", 2000}));
  std::vector<encryption_luks_keyslot_info_t> keyslots;
  ASSERT_EQ(0, list_keyslots(&keyslots));
  ASSERT_EQ(2u, keyslots.size());
  ASSERT_EQ("pbkdf2", keyslots[1].kdf);
  ASSERT_EQ(2000u, keyslots[1].kdf_iterations);
  ASSERT_EQ(0, unlock_luks(new_passphrase));
}

TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion,
       AddToFullKeyslotTableFails) {
  generate_header(GetParam(), sector_size(), false, nullptr,
                  crypt_keyslot_max(GetParam()));
  ceph::bufferlist before = image_bl;

  int added = -1;
  ASSERT_EQ(-ENOSPC, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                                 new_passphrase, &added));
  ASSERT_TRUE(writes.empty());
  ASSERT_TRUE(before.contents_equal(image_bl));
}

// an explicit keyslot in use is refused, as libcryptsetup refuses it: a
// retry after a crash lists the keyslots instead of adding blindly
TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion,
       AddToOccupiedKeyslotFails) {
  generate_header(GetParam(), sector_size());

  int added = -1;
  ASSERT_EQ(0, add_keyslot(5, volume_key, new_passphrase, &added));
  ASSERT_EQ(5, added);
  ceph::bufferlist before = image_bl;

  ASSERT_EQ(-EEXIST, add_keyslot(5, volume_key, new_passphrase, &added));
  ASSERT_TRUE(writes.empty());
  ASSERT_TRUE(before.contents_equal(image_bl));
  ASSERT_EQ((std::vector<int>{0, 5}), listed_slots());
}

TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion,
       AddRejectionsLeaveHeaderIntact) {
  generate_header(GetParam(), sector_size());
  ceph::bufferlist before = image_bl;

  int added = -1;
  // a key that does not match the data's digest is refused by libcryptsetup
  // before anything is stored
  std::string wrong_key(volume_key.size(), 'x');
  ASSERT_EQ(-EPERM, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, wrong_key,
                                new_passphrase, &added));
  ASSERT_TRUE(writes.empty());
  // a key of the wrong size
  ASSERT_GT(0, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, "short",
                           new_passphrase, &added));
  ASSERT_TRUE(writes.empty());
  // keyslot 0 holds another passphrase
  ASSERT_EQ(-EEXIST, add_keyslot(0, volume_key, new_passphrase, &added));
  ASSERT_TRUE(writes.empty());
  // 99 is past the last keyslot of both versions
  ASSERT_EQ(-EINVAL, add_keyslot(99, volume_key, new_passphrase, &added));
  ASSERT_TRUE(writes.empty());
  ASSERT_TRUE(before.contents_equal(image_bl));
}

TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion, RemoveKeyslot) {
  generate_header(GetParam(), sector_size());
  int added = -1;
  ASSERT_EQ(0, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                           new_passphrase, &added));

  ASSERT_EQ(0, remove_keyslot(0));
  ASSERT_FALSE(writes.empty());
  ASSERT_EQ(1u, flushes);
  ASSERT_GT(0, unlock_luks(passphrase));
  ASSERT_EQ(0, unlock_luks(new_passphrase));

  std::vector<encryption_luks_keyslot_info_t> keyslots;
  ASSERT_EQ(0, list_keyslots(&keyslots));
  ASSERT_EQ(1u, keyslots.size());
  ASSERT_EQ(1, keyslots[0].keyslot);
  ASSERT_TRUE(keyslots[0].last);
}

// remove refuses a keyslot it must not or cannot remove, and no refusal
// changes the stored header
TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion,
       RemoveRejectionsLeaveHeaderIntact) {
  generate_header(GetParam(), sector_size());
  ceph::bufferlist before = image_bl;

  // keyslot 0 is the only keyslot bound to the data: removing it would
  // leave nobody but the holder of the volume key able to open the image
  ASSERT_EQ(-EBUSY, remove_keyslot(0));
  ASSERT_TRUE(writes.empty());
  // keyslot 3 is a valid number but holds nothing
  ASSERT_EQ(-ENOENT, remove_keyslot(3));
  ASSERT_TRUE(writes.empty());
  // 99 is past the last keyslot of both versions, and the any-keyslot
  // value is only meaningful for add: remove needs a slot number
  ASSERT_EQ(-EINVAL, remove_keyslot(99));
  ASSERT_TRUE(writes.empty());
  ASSERT_EQ(-EINVAL, remove_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT));
  ASSERT_TRUE(writes.empty());

  ASSERT_TRUE(before.contents_equal(image_bl));
}

TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion, ListKeyslots) {
  generate_header(GetParam(), sector_size());

  std::vector<encryption_luks_keyslot_info_t> keyslots;
  ASSERT_EQ(0, list_keyslots(&keyslots));
  ASSERT_EQ(1u, keyslots.size());
  ASSERT_EQ(0, keyslots[0].keyslot);
  ASSERT_TRUE(keyslots[0].last);
  ASSERT_EQ(64u, keyslots[0].key_size);
  // generate_header formats in insecure fast mode
  ASSERT_EQ("pbkdf2", keyslots[0].kdf);
  ASSERT_EQ("sha256", keyslots[0].hash);
  ASSERT_EQ(1000u, keyslots[0].kdf_iterations);
  // one read of the metadata, as image open does it, and no writes
  ASSERT_TRUE(writes.empty());
  ASSERT_EQ(0u, flushes);
  ASSERT_EQ(1u, read_requests.size());
}

// a crash between the two metadata writes of an update leaves one LUKS2
// copy outdated. libcryptsetup repairs it when it loads the header, and
// the listing must not write that repair back
TEST_F(TestMockCryptoLuksUpdateHeaderRequest, ListKeyslotsLeavesOutdatedCopy) {
  generate_header(CRYPT_LUKS2, 4096);
  ceph::bufferlist old_bl = image_bl;
  int added = -1;
  ASSERT_EQ(0, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                           new_passphrase, &added));
  // the primary copy from before the add, 16 KiB with the default
  // metadata size
  ceph::bufferlist primary;
  primary.substr_of(old_bl, 0, 16384);
  store_write(0, primary);
  ceph::bufferlist stored_bl = image_bl;

  Header header(mock_image_ctx->cct);
  ceph::bufferlist loaded_bl;
  ASSERT_EQ(0, header.init());
  ASSERT_EQ(0, header.write(image_bl));
  ASSERT_EQ(0, header.load(CRYPT_LUKS2));
  ASSERT_EQ(static_cast<ssize_t>(image_bl.length()),
            header.read(&loaded_bl, 0, image_bl.length()));
  ASSERT_FALSE(loaded_bl.contents_equal(image_bl)) << "needs a repair on load";

  // the newer copy wins
  ASSERT_EQ((std::vector<int>{0, 1}), listed_slots());
  ASSERT_TRUE(writes.empty());
  ASSERT_EQ(1u, read_requests.size());

  mock_image_ctx->read_only = true;
  ASSERT_EQ((std::vector<int>{0, 1}), listed_slots());
  ASSERT_TRUE(writes.empty());
  ASSERT_TRUE(stored_bl.contents_equal(image_bl));
}

TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion, ReadOnlyImage) {
  generate_header(GetParam(), sector_size());
  mock_image_ctx->read_only = true;
  ceph::bufferlist before = image_bl;

  ASSERT_EQ((std::vector<int>{0}), listed_slots());

  // refused before the header is read, also with a wrong key
  int added = -1;
  ASSERT_EQ(-EROFS, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                                new_passphrase, &added));
  ASSERT_TRUE(read_requests.empty());
  ASSERT_EQ(-EROFS, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, "wrong",
                                new_passphrase, &added));
  ASSERT_TRUE(read_requests.empty());
  ASSERT_EQ(-EROFS, remove_keyslot(0));
  ASSERT_TRUE(read_requests.empty());
  ASSERT_TRUE(writes.empty());
  ASSERT_TRUE(before.contents_equal(image_bl));
}

TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion, Snapshot) {
  generate_header(GetParam(), sector_size());
  mock_image_ctx->snap_id = 1;

  int added = -1;
  ASSERT_EQ(-EROFS, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                                new_passphrase, &added));
  ASSERT_TRUE(read_requests.empty());
  ASSERT_EQ(-EROFS, remove_keyslot(0));
  ASSERT_TRUE(read_requests.empty());
  ASSERT_TRUE(writes.empty());
}

TEST_F(TestMockCryptoLuksUpdateHeaderRequest, NotLuks) {
  image_bl.append_zero(OBJECT_SIZE);

  std::vector<encryption_luks_keyslot_info_t> keyslots;
  ASSERT_EQ(-EINVAL, list_keyslots(&keyslots));
  ASSERT_TRUE(writes.empty());

  std::string key;
  int keyslot = -1;
  ASSERT_EQ(-EINVAL, get_volume_key(passphrase, &key, &keyslot));
  ASSERT_TRUE(key.empty());

  std::string dump;
  ASSERT_EQ(-EINVAL, header_dump(&dump));
  ASSERT_TRUE(dump.empty());
}

// a dump taken before an add brings the header back to that state
TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion, HeaderDumpAndRestore) {
  generate_header(GetParam(), sector_size());

  std::string dump;
  size_t dump_size = 0;
  ASSERT_EQ(0, header_dump(&dump, &dump_size));
  // the whole header area, starting with the LUKS magic
  ASSERT_EQ(image_bl.length(), dump.size());
  ASSERT_EQ(dump.size(), dump_size);
  ceph::bufferlist dump_bl;
  dump_bl.append(dump);
  ASSERT_LT(0, Magic::is_luks(dump_bl));
  ASSERT_TRUE(writes.empty());
  ASSERT_EQ(0u, flushes);

  int added = -1;
  ASSERT_EQ(0, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                           new_passphrase, &added));
  ASSERT_EQ(0, unlock_luks(new_passphrase));

  ASSERT_EQ(0, header_restore(dump));
  // one write of the dump at offset 0, then a flush
  ASSERT_EQ(1u, writes.size());
  ASSERT_EQ(0u, writes[0].first);
  ASSERT_EQ(dump.size(), writes[0].second);
  ASSERT_EQ(1u, flushes);
  ASSERT_EQ((std::vector<int>{0}), listed_slots());
  ASSERT_EQ(0, unlock_luks(passphrase));
  ASSERT_GT(0, unlock_luks(new_passphrase));
}

// a header no client can read any more is replaced without conditions
TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion, HeaderRestoreTorn) {
  generate_header(GetParam(), sector_size());
  std::string dump;
  ASSERT_EQ(0, header_dump(&dump));

  // both LUKS2 metadata copies and the LUKS1 record lie in the first 64 KiB
  ceph::bufferlist zeros;
  zeros.append_zero(64 * 1024);
  store_write(0, zeros);
  std::vector<encryption_luks_keyslot_info_t> keyslots;
  ASSERT_EQ(-EINVAL, list_keyslots(&keyslots));

  ASSERT_EQ(0, header_restore(dump));
  ASSERT_EQ((std::vector<int>{0}), listed_slots());
  ASSERT_EQ(0, unlock_luks(passphrase));
}

// libcryptsetup refuses a dump whose data offset differs from the header
// on the image while that header still loads
TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion,
       HeaderRestoreRefusesOtherDataOffset) {
  generate_header(GetParam(), sector_size());
  ceph::bufferlist before = image_bl;

  std::string other = other_header_dump(GetParam(), sector_size());
  ASSERT_NE(image_bl.length(), other.size());
  ASSERT_GT(0, header_restore(other));
  ASSERT_TRUE(writes.empty());
  ASSERT_TRUE(before.contents_equal(image_bl));
}

// a dump of a clone carries the LUKS magic, and a restore puts the RBD
// clone magic back on the image
TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion, HeaderDumpOfClone) {
  generate_header(GetParam(), sector_size(), true);
  ASSERT_LT(0, Magic::is_rbd_clone(image_bl));

  std::string dump;
  ASSERT_EQ(0, header_dump(&dump));
  ceph::bufferlist dump_bl;
  dump_bl.append(dump);
  ASSERT_LT(0, Magic::is_luks(dump_bl));

  int added = -1;
  ASSERT_EQ(0, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                           new_passphrase, &added));
  ASSERT_EQ(0, header_restore(dump));
  ASSERT_LT(0, Magic::is_rbd_clone(image_bl));
  ASSERT_EQ(0, Magic::is_luks(image_bl));
  ASSERT_EQ((std::vector<int>{0}), listed_slots());
  ASSERT_EQ(0, unlock_luks(passphrase));
}

// restore puts back the magic the stored bytes carried: a clone whose own
// header has the LUKS magic keeps it, and a clone whose header lost its
// magic gets the RBD clone magic, as format gives it
TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion,
       HeaderRestoreMagicOnClone) {
  generate_header(GetParam(), sector_size());
  mock_parent_image_ctx = new MockImageCtx(*ictx);
  mock_image_ctx->parent = mock_parent_image_ctx;
  std::string dump;
  ASSERT_EQ(0, header_dump(&dump));

  // the stored magic stays what it was
  ASSERT_EQ(0, header_restore(dump));
  ASSERT_LT(0, Magic::is_luks(image_bl));
  ASSERT_EQ((std::vector<int>{0}), listed_slots());

  // the magic gone: the parent decides
  ceph::bufferlist zeros;
  zeros.append_zero(64 * 1024);
  store_write(0, zeros);
  ASSERT_EQ(0, header_restore(dump));
  ASSERT_LT(0, Magic::is_rbd_clone(image_bl));
  ASSERT_EQ((std::vector<int>{0}), listed_slots());
  ASSERT_EQ(0, unlock_luks(passphrase));
}

// the dump's size is reported before anything is copied; a dump works on
// a read-only handle and a snapshot, a restore refuses them
TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion,
       HeaderDumpSizeAndReadOnly) {
  generate_header(GetParam(), sector_size());

  std::string dump;
  size_t dump_size = 0;
  ASSERT_EQ(-ERANGE, header_dump(&dump, &dump_size, 0));
  ASSERT_EQ(image_bl.length(), dump_size);
  ASSERT_TRUE(dump.empty());

  mock_image_ctx->read_only = true;
  ASSERT_EQ(0, header_dump(&dump));
  ASSERT_EQ(image_bl.length(), dump.size());
  ASSERT_EQ(-EROFS, header_restore(dump));
  ASSERT_TRUE(read_requests.empty());

  mock_image_ctx->snap_id = 1;
  dump.clear();
  ASSERT_EQ(0, header_dump(&dump));
  ASSERT_EQ(image_bl.length(), dump.size());
  ASSERT_EQ(-EROFS, header_restore(dump));
  ASSERT_TRUE(writes.empty());
}

TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion, GetVolumeKey) {
  generate_header(GetParam(), sector_size());

  std::string key;
  int keyslot = -1;
  size_t key_size = 0;
  ASSERT_EQ(0, get_volume_key(passphrase, &key, &keyslot, &key_size));
  ASSERT_EQ(volume_key, key);
  ASSERT_EQ(64u, key_size);
  ASSERT_EQ(0, keyslot);
  // keyslot 0 lies inside the initial read: one read, nothing written
  ASSERT_EQ(1u, read_requests.size());
  ASSERT_TRUE(writes.empty());
  ASSERT_EQ(0u, flushes);

  // the keyslot the passphrase opens is reported; keyslot 3 lies beyond
  // the initial read, so the keyslot area is read on demand
  int added = -1;
  ASSERT_EQ(0, add_keyslot(3, volume_key, new_passphrase, &added));
  ASSERT_EQ(0, get_volume_key(new_passphrase, &key, &keyslot));
  ASSERT_EQ(volume_key, key);
  ASSERT_EQ(3, keyslot);
  ASSERT_EQ(2u, read_requests.size());
}

TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion,
       GetVolumeKeyWrongPassphrase) {
  generate_header(GetParam(), sector_size());

  std::string key;
  int keyslot = -1;
  ASSERT_EQ(-EPERM, get_volume_key("wrong", &key, &keyslot));
  ASSERT_TRUE(key.empty());
  ASSERT_EQ(-1, keyslot);
  // every keyslot was tried on the whole area before giving up
  ASSERT_EQ(2u, read_requests.size());
}

// a buffer too small for the key is reported with the size needed before
// any keyslot is tried
TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion,
       GetVolumeKeyBufferTooSmall) {
  generate_header(GetParam(), sector_size());

  std::string key;
  int keyslot = -1;
  size_t key_size = 0;
  ASSERT_EQ(-ERANGE, get_volume_key("wrong", &key, &keyslot, &key_size, 0));
  ASSERT_EQ(64u, key_size);
  ASSERT_TRUE(key.empty());
  ASSERT_EQ(-ERANGE, get_volume_key(passphrase, &key, &keyslot, &key_size,
                                    63));
  ASSERT_EQ(64u, key_size);
  ASSERT_EQ(0, get_volume_key(passphrase, &key, &keyslot, &key_size, 64));
  ASSERT_EQ(volume_key, key);
}

// get only reads, so a read-only handle, a snapshot and a clone work
TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion,
       GetVolumeKeyReadsAnywhere) {
  generate_header(GetParam(), sector_size(), true);
  std::string key;
  int keyslot = -1;

  mock_image_ctx->read_only = true;
  ASSERT_EQ(0, get_volume_key(passphrase, &key, &keyslot));
  ASSERT_EQ(volume_key, key);

  mock_image_ctx->snap_id = 1;
  key.clear();
  ASSERT_EQ(0, get_volume_key(passphrase, &key, &keyslot));
  ASSERT_EQ(volume_key, key);
  ASSERT_EQ(0, keyslot);
  ASSERT_TRUE(writes.empty());
  // the image still stores the header the way a clone does
  ASSERT_LT(0, Magic::is_rbd_clone(image_bl));
}

// a lost write, acknowledged but never stored, is not detected: the request
// returns success, and the caller sees the keyslot missing in the listing
TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion,
       LostWriteIsNotDetected) {
  generate_header(GetParam(), sector_size());
  on_write = [](size_t, ceph::bufferlist*, bool* store) {
    *store = false;
    return 0;
  };

  int added = -1;
  ASSERT_EQ(0, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                           new_passphrase, &added));
  ASSERT_EQ(1, added);
  ASSERT_FALSE(writes.empty());
  ASSERT_EQ(1u, flushes);
  ASSERT_EQ((std::vector<int>{0}), listed_slots());
  ASSERT_EQ(0, unlock_luks(passphrase));
  ASSERT_GT(0, unlock_luks(new_passphrase));
}

// a corrupted write, stored with a flipped byte in the key material, leaves
// a keyslot that is listed and does not open; the caller, with the volume
// key in hand, removes it and adds again
TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion,
       CorruptedKeyslotRepairedByRemoveAndAdd) {
  generate_header(GetParam(), sector_size());
  // range 0 is the header. Ranges after carry the new key material
  on_write = [](size_t index, ceph::bufferlist* bl, bool*) {
    if (index > 0) {
      bl->rebuild();
      bl->c_str()[bl->length() / 2] ^= 0xff;
    }
    return 0;
  };

  int added = -1;
  ASSERT_EQ(0, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                           new_passphrase, &added));
  ASSERT_EQ(1, added);
  ASSERT_EQ(1u, flushes);
  ASSERT_EQ((std::vector<int>{0, 1}), listed_slots());
  ASSERT_EQ(0, unlock_luks(passphrase));
  ASSERT_GT(0, unlock_luks(new_passphrase));

  on_write = nullptr;
  ASSERT_EQ(0, remove_keyslot(1));
  ASSERT_EQ(0, add_keyslot(1, volume_key, new_passphrase, &added));
  ASSERT_EQ(1, added);
  ASSERT_EQ(0, unlock_luks(passphrase));
  ASSERT_EQ(0, unlock_luks(new_passphrase));
}

// a write-back torn by an error keeps the old passphrase working; the
// metadata that landed lists a keyslot whose key material did not, and the
// caller completes the rotation by removing it and adding again
TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion, TornWriteThenRetry) {
  generate_header(GetParam(), sector_size());
  on_write = [](size_t index, ceph::bufferlist*, bool* store) {
    if (index == 0) {
      return 0;
    }
    *store = false;
    return -EIO;
  };

  int added = -1;
  ASSERT_EQ(-EIO, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                              new_passphrase, &added));
  ASSERT_LT(1u, writes.size()) << "needs more than one range to tear";
  ASSERT_EQ(0u, flushes);
  ASSERT_EQ(0, unlock_luks(passphrase));
  ASSERT_EQ((std::vector<int>{0, 1}), listed_slots());
  ASSERT_GT(0, unlock_luks(new_passphrase));

  on_write = nullptr;
  ASSERT_EQ(0, remove_keyslot(1));
  ASSERT_EQ(0, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                           new_passphrase, &added));
  ASSERT_EQ(1, added);
  ASSERT_EQ(0, unlock_luks(passphrase));
  ASSERT_EQ(0, unlock_luks(new_passphrase));
}

TEST_P(TestMockCryptoLuksUpdateHeaderRequestPerVersion, CloneMagicPreserved) {
  generate_header(GetParam(), sector_size(), true);

  int added = -1;
  ASSERT_EQ(0, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                           new_passphrase, &added));
  ASSERT_EQ(1, added);
  // the image still stores the header the way a clone does
  ASSERT_LT(0, Magic::is_rbd_clone(image_bl));
  ASSERT_EQ(0, Magic::is_luks(image_bl));
  ASSERT_EQ(0, unlock_luks(passphrase));
  ASSERT_EQ(0, unlock_luks(new_passphrase));

  ASSERT_EQ(0, remove_keyslot(0));
  ASSERT_LT(0, Magic::is_rbd_clone(image_bl));
  ASSERT_EQ((std::vector<int>{1}), listed_slots());
}

TEST_F(TestMockCryptoLuksUpdateHeaderRequest, AddKeyslotCopiesArgon2Settings) {
  struct crypt_pbkdf_type pbkdf = {};
  pbkdf.type = CRYPT_KDF_ARGON2ID;
  pbkdf.flags = CRYPT_PBKDF_NO_BENCHMARK;
  pbkdf.iterations = 4;
  pbkdf.max_memory_kb = 64;
  pbkdf.parallel_threads = 1;
  generate_header(CRYPT_LUKS2, 4096, false, &pbkdf);

  int added = -1;
  ASSERT_EQ(0, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                           new_passphrase, &added));
  std::vector<encryption_luks_keyslot_info_t> keyslots;
  ASSERT_EQ(0, list_keyslots(&keyslots));
  ASSERT_EQ(2u, keyslots.size());
  ASSERT_EQ(CRYPT_KDF_ARGON2ID, keyslots[1].kdf);
  ASSERT_EQ(4u, keyslots[1].kdf_iterations);
  ASSERT_EQ(64u, keyslots[1].kdf_memory_kb);
  ASSERT_EQ(1u, keyslots[1].kdf_threads);
  ASSERT_EQ(0, unlock_luks(new_passphrase));
}

TEST_F(TestMockCryptoLuksUpdateHeaderRequest, AddKeyslotWithArgon2Settings) {
  generate_header(CRYPT_LUKS2, 4096);

  int added = -1;
  ASSERT_EQ(0, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                           new_passphrase, &added,
                           KdfSettings{CRYPT_KDF_ARGON2ID, "", 4, 64, 1}));
  std::vector<encryption_luks_keyslot_info_t> keyslots;
  ASSERT_EQ(0, list_keyslots(&keyslots));
  ASSERT_EQ(2u, keyslots.size());
  ASSERT_EQ("pbkdf2", keyslots[0].kdf);
  ASSERT_EQ(CRYPT_KDF_ARGON2ID, keyslots[1].kdf);
  ASSERT_EQ(4u, keyslots[1].kdf_iterations);
  ASSERT_EQ(64u, keyslots[1].kdf_memory_kb);
  ASSERT_EQ(1u, keyslots[1].kdf_threads);
  ASSERT_EQ(0, unlock_luks(new_passphrase));
}

// keyslot 1 holds a key that does not belong to the data: the listing hides
// it, and remove destroys it like any other keyslot
TEST_F(TestMockCryptoLuksUpdateHeaderRequest, RemoveUnboundKeyslot) {
  generate_header(CRYPT_LUKS2, 4096);
  add_unbound_keyslot("unbound");
  ASSERT_EQ((std::vector<int>{0}), listed_slots());

  ASSERT_EQ(0, remove_keyslot(1));
  ASSERT_FALSE(writes.empty());
  ASSERT_EQ((std::vector<int>{0}), listed_slots());
  ASSERT_EQ(0, unlock_luks(passphrase));
  // keyslot 1 is free again
  int added = -1;
  ASSERT_EQ(0, add_keyslot(1, volume_key, new_passphrase, &added));
  ASSERT_EQ(1, added);
  ASSERT_EQ(0, unlock_luks(new_passphrase));
}

// with no keyslot in use to copy the KDF settings from, add needs them;
// the volume key still matches the data, so given settings work
TEST_F(TestMockCryptoLuksUpdateHeaderRequest, AddWithoutKeyslotInUse) {
  generate_header(CRYPT_LUKS2, 4096);
  destroy_keyslot_outside(0);
  ASSERT_TRUE(listed_slots().empty());
  ceph::bufferlist before = image_bl;

  int added = -1;
  ASSERT_EQ(-EINVAL, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                                 new_passphrase, &added));
  ASSERT_TRUE(writes.empty());
  ASSERT_TRUE(before.contents_equal(image_bl));

  ASSERT_EQ(0, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                           new_passphrase, &added,
                           KdfSettings{"pbkdf2", "sha256", 1000}));
  ASSERT_EQ(0, added);
  ASSERT_EQ(0, unlock_luks(new_passphrase));
}

// LUKS1 only knows PBKDF2
TEST_F(TestMockCryptoLuksUpdateHeaderRequest, AddKeyslotArgon2OnLuks1Fails) {
  generate_header(CRYPT_LUKS1, 512);
  ceph::bufferlist before = image_bl;

  int added = -1;
  KdfSettings argon2{CRYPT_KDF_ARGON2ID, "", 4, 64, 1};
  ASSERT_EQ(-EINVAL, add_keyslot(RBD_ENCRYPTION_LUKS_ANY_KEYSLOT, volume_key,
                                 new_passphrase, &added, argon2));
  ASSERT_TRUE(writes.empty());
  ASSERT_TRUE(before.contents_equal(image_bl));
}

INSTANTIATE_TEST_SUITE_P(, TestMockCryptoLuksUpdateHeaderRequestPerVersion,
                         ::testing::Values(CRYPT_LUKS1, CRYPT_LUKS2),
                         [](const auto& info) {
                           return std::string(info.param);
                         });

} // namespace luks
} // namespace crypto
} // namespace librbd
