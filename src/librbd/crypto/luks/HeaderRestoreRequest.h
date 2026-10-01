// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#ifndef CEPH_LIBRBD_CRYPTO_LUKS_HEADER_RESTORE_REQUEST_H
#define CEPH_LIBRBD_CRYPTO_LUKS_HEADER_RESTORE_REQUEST_H

#include <string_view>
#include "include/buffer.h"
#include "include/Context.h"
#include "librbd/io/Types.h"
#include "librbd/crypto/luks/Header.h"

namespace librbd {

struct ImageCtx;

namespace crypto {
namespace luks {

// Writes a header dump back to the image through libcryptsetup's own
// restore, so its checks apply and nothing else: the dump must be a valid
// LUKS header, and while the image's header still loads the data offsets
// must match. The image's current bytes are staged even when they do not
// load, which is the case the restore exists for. The RBD clone magic goes
// back where the stored bytes carried it, and where their magic is gone,
// on an image with a parent, as format puts it. The dump view must outlive
// the request.
template <typename ImageCtxT = librbd::ImageCtx>
class HeaderRestoreRequest {
public:
  static HeaderRestoreRequest* create(ImageCtxT* image_ctx,
                                      std::string_view dump,
                                      Context* on_finish) {
    return new HeaderRestoreRequest(image_ctx, dump, on_finish);
  }

  HeaderRestoreRequest(ImageCtxT* image_ctx, std::string_view dump,
                       Context* on_finish);
  void send();

private:
  /**
   * @verbatim
   *
   * <start>
   *    |
   *    v
   * READ_IMAGE . . . . . (the bytes the dump will replace, staged into
   *    |                  the anonymous file with the clone magic
   *    v                  normalized)
   * RESTORE . . . . . . . (crypt_header_restore from a second anonymous
   *    |                   file that holds the dump; the clone magic is
   *    v                   re-applied to the result)
   * WRITE . . . . . . . . (the restored bytes in one write)
   *    |
   *    v
   * FLUSH
   *    |
   *    v
   * <finish>
   *
   * @endverbatim
   */
  ImageCtxT* m_image_ctx;
  std::string_view m_dump;
  Context* m_on_finish;

  io::ImageArea m_area;
  Header m_header;              // the image's header, restored in place
  Header m_backup;              // holds the dump for libcryptsetup
  ceph::bufferlist m_bl;

  void handle_read_image(int r);
  int restore();
  void handle_write(int r);
  void handle_flush(int r);
  void finish(int r);
};

} // namespace luks
} // namespace crypto
} // namespace librbd

extern template class librbd::crypto::luks::HeaderRestoreRequest<
        librbd::ImageCtx>;

#endif // CEPH_LIBRBD_CRYPTO_LUKS_HEADER_RESTORE_REQUEST_H
