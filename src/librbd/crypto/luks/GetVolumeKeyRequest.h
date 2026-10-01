// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#ifndef CEPH_LIBRBD_CRYPTO_LUKS_GET_VOLUME_KEY_REQUEST_H
#define CEPH_LIBRBD_CRYPTO_LUKS_GET_VOLUME_KEY_REQUEST_H

#include <string>
#include <string_view>
#include "include/Context.h"
#include "librbd/io/Types.h"
#include "librbd/crypto/luks/Header.h"

namespace librbd {

struct ImageCtx;

namespace crypto {
namespace luks {

// Recovers the volume key through a keyslot that the passphrase unlocks,
// the way image open does, keyslot material read on demand included, and
// hands it to the caller with the keyslot's number. It only reads, so it
// works on read-only and snapshot handles.
//
// The passphrase view must outlive the request. key_size receives the
// key's size as soon as the header is read; the key itself is returned
// only when max_size holds it, -ERANGE otherwise, without a derivation.
template <typename ImageCtxT = librbd::ImageCtx>
class GetVolumeKeyRequest {
public:
  static GetVolumeKeyRequest* create(
      ImageCtxT* image_ctx, std::string_view passphrase, size_t max_size,
      std::string* volume_key, size_t* key_size, int* keyslot,
      Context* on_finish) {
    return new GetVolumeKeyRequest(image_ctx, passphrase, max_size,
                                   volume_key, key_size, keyslot, on_finish);
  }

  GetVolumeKeyRequest(ImageCtxT* image_ctx, std::string_view passphrase,
                      size_t max_size, std::string* volume_key,
                      size_t* key_size, int* keyslot, Context* on_finish);
  void send();

private:
  /**
   * @verbatim
   *
   * <start>
   *    |
   *    v
   * READ_HEADER . . . . (ReadHeaderRequest, the metadata only, as image
   *    |                 open reads it)
   *    v
   * UNLOCK <---------\ . (any keyslot with the passphrase, in the anonymous
   *    |             |    file)
   *    | (no keyslot opened and the keyslot area was not read whole)
   *    v             |
   * READ_KEYSLOTS ---/ . (the rest of the keyslot area, then one more try)
   *    |
   *    v
   * <finish>
   *
   * @endverbatim
   */
  ImageCtxT* m_image_ctx;
  std::string_view m_passphrase;
  size_t m_max_size;
  std::string* m_volume_key;
  size_t* m_key_size;
  int* m_keyslot;
  Context* m_on_finish;

  io::ImageArea m_area;
  Header m_header;
  uint64_t m_offset = 0;        // bytes of the header fed so far

  void handle_read_header(int r);
  void unlock();
  void handle_read_keyslots(int r);
  void finish(int r);
};

} // namespace luks
} // namespace crypto
} // namespace librbd

extern template class librbd::crypto::luks::GetVolumeKeyRequest<
        librbd::ImageCtx>;

#endif // CEPH_LIBRBD_CRYPTO_LUKS_GET_VOLUME_KEY_REQUEST_H
