// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#ifndef CEPH_LIBRBD_CRYPTO_LUKS_HEADER_BACKUP_REQUEST_H
#define CEPH_LIBRBD_CRYPTO_LUKS_HEADER_BACKUP_REQUEST_H

#include <string>
#include "include/Context.h"
#include "librbd/io/Types.h"
#include "librbd/crypto/luks/Header.h"

namespace librbd {

struct ImageCtx;

namespace crypto {
namespace luks {

// Copies the LUKS header out of the image: the bytes up to the data
// offset as the image stores them, with the LUKS magic even on a clone,
// so that cryptsetup can read the dump and restore it. It only reads.
//
// dump_size receives the size as soon as the header is read; the bytes
// are returned only when max_size holds them, -ERANGE otherwise.
template <typename ImageCtxT = librbd::ImageCtx>
class HeaderBackupRequest {
public:
  static HeaderBackupRequest* create(ImageCtxT* image_ctx, size_t max_size,
                                     std::string* dump, size_t* dump_size,
                                     Context* on_finish) {
    return new HeaderBackupRequest(image_ctx, max_size, dump, dump_size,
                                   on_finish);
  }

  HeaderBackupRequest(ImageCtxT* image_ctx, size_t max_size,
                      std::string* dump, size_t* dump_size,
                      Context* on_finish);
  void send();

private:
  /**
   * @verbatim
   *
   * <start>
   *    |
   *    v
   * READ_HEADER . . . . (ReadHeaderRequest to the data offset; on a clone
   *    |                 the RBDL magic is replaced with LUKS)
   *    v
   * COPY . . . . . . . . (the anonymous file's bytes up to the data offset)
   *    |
   *    v
   * <finish>
   *
   * @endverbatim
   */
  ImageCtxT* m_image_ctx;
  size_t m_max_size;
  std::string* m_dump;
  size_t* m_dump_size;
  Context* m_on_finish;

  io::ImageArea m_area;
  Header m_header;

  void handle_read_header(int r);
  void finish(int r);
};

} // namespace luks
} // namespace crypto
} // namespace librbd

extern template class librbd::crypto::luks::HeaderBackupRequest<
        librbd::ImageCtx>;

#endif // CEPH_LIBRBD_CRYPTO_LUKS_HEADER_BACKUP_REQUEST_H
