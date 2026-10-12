// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#ifndef CEPH_LIBRBD_CRYPTO_LUKS_UPDATE_HEADER_REQUEST_H
#define CEPH_LIBRBD_CRYPTO_LUKS_UPDATE_HEADER_REQUEST_H

#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>
#include "include/buffer.h"
#include "include/Context.h"
#include "include/rbd/librbd.hpp"
#include "librbd/io/Types.h"
#include "librbd/crypto/luks/Header.h"
#include "librbd/crypto/luks/ReadHeaderRequest.h"

namespace librbd {

struct ImageCtx;

namespace crypto {
namespace luks {

// key derivation settings for a new keyslot, used as given
struct KdfSettings {
  std::string kdf;
  std::string hash;
  uint32_t iterations = 0;
  uint32_t memory_kb = 0;
  uint32_t threads = 0;
};

// One keyslot operation on the LUKS header of an image: the header is
// staged into libcryptsetup's anonymous file, the operation runs there,
// and the changed 4 KiB ranges are written back and flushed. Nothing is
// ordered or verified beyond that: the caller holds the volume key and
// handles a failed write-back with the listing, remove and add.
//
// The string views must outlive the request.
template <typename ImageCtxT = librbd::ImageCtx>
class UpdateHeaderRequest {
public:
  static UpdateHeaderRequest* create_add_keyslot(
      ImageCtxT* image_ctx, int keyslot, std::string_view volume_key,
      std::string_view passphrase, std::optional<KdfSettings> kdf,
      int* result_keyslot, Context* on_finish) {
    auto req = new UpdateHeaderRequest(image_ctx, KeyslotOp::ADD, keyslot,
                                       on_finish);
    req->m_volume_key = volume_key;
    req->m_passphrase = passphrase;
    req->m_kdf = std::move(kdf);
    req->m_result_keyslot = result_keyslot;
    return req;
  }

  static UpdateHeaderRequest* create_remove_keyslot(
      ImageCtxT* image_ctx, int keyslot, Context* on_finish) {
    return new UpdateHeaderRequest(image_ctx, KeyslotOp::REMOVE, keyslot,
                                   on_finish);
  }

  void send();

private:
  /**
   * @verbatim
   *
   * <start>
   *    |
   *    v
   * READ_HEADER . . . . (ReadHeaderRequest extended to the data offset so
   *    |                 the keyslot area is complete; on a clone the RBDL
   *    |                 magic is replaced with LUKS before feeding
   *    v                 libcryptsetup's anonymous file)
   * MODIFY_HEADER . . . (add or remove the keyslot in the anonymous file,
   *    |                 then diff it against the stored bytes, with the
   *    |                 clone magic restored)
   *    |
   *    | (no byte changed)
   *    |-------------------------------------------\
   *    v                                           |
   * WRITE_RANGES . . . . (one image write per changed range, unordered)
   *    |                                           |
   *    v                                           |
   * FLUSH                                          |
   *    |                                           |
   *    v                                           |
   * <finish> <-------------------------------------/
   *
   * @endverbatim
   */
  enum class KeyslotOp {
    ADD,
    REMOVE
  };

  UpdateHeaderRequest(ImageCtxT* image_ctx, KeyslotOp op, int keyslot,
                      Context* on_finish);

  ImageCtxT* m_image_ctx;
  KeyslotOp m_op;
  int m_keyslot;                   // in: slot to operate on. Can be ANY for add
  std::string_view m_volume_key;   // in, add: the key the new keyslot stores
  std::string_view m_passphrase;   // in, add: passphrase of the new keyslot
  std::optional<KdfSettings> m_kdf; // in: none copies an active keyslot's
  int* m_result_keyslot = nullptr; // out: the slot the add actually used
  Context* m_on_finish;

  io::ImageArea m_area;
  Header m_header;
  ceph::bufferlist m_orig_bl;   // header bytes as stored in the image
  bool m_clone_magic = false;   // the image stores the RBD clone magic, which
                                // the anonymous file has replaced with LUKS
  // changed ranges awaiting write-back
  std::vector<std::pair<uint64_t, ceph::bufferlist>> m_pending_writes;
  size_t m_write_index = 0;

  void handle_read_header(int r);
  void modify();
  int add_keyslot();
  bool has_free_keyslot();
  int lowest_active_keyslot();
  int remove_keyslot();
  int compute_writes();
  void write_next();
  void handle_write(int r);
  void flush();
  void handle_flush(int r);
  void finish(int r);
};

} // namespace luks
} // namespace crypto
} // namespace librbd

extern template class librbd::crypto::luks::UpdateHeaderRequest<
        librbd::ImageCtx>;

#endif // CEPH_LIBRBD_CRYPTO_LUKS_UPDATE_HEADER_REQUEST_H
