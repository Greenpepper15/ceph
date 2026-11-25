// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#ifndef CEPH_LIBRBD_CRYPTO_LUKS_HEADER_SESSION_H
#define CEPH_LIBRBD_CRYPTO_LUKS_HEADER_SESSION_H

#include <utility>
#include <vector>
#include "include/buffer.h"
#include "include/Context.h"
#include "librbd/io/Types.h"
#include "librbd/crypto/luks/Header.h"

namespace librbd {

struct ImageCtx;

namespace crypto {
namespace luks {

// The LUKS header of an image staged in libcryptsetup's anonymous file and
// handed to the caller as a file descriptor. The caller edits the file
// with libcryptsetup or cryptsetup on /proc/self/fd/<fd>; commit() writes
// the 4 KiB ranges that differ from the stored bytes back and flushes, as
// UpdateHeaderRequest does for one keyslot operation. Nothing is ordered
// or verified beyond that, and one request runs at a time.
template <typename ImageCtxT = librbd::ImageCtx>
class HeaderSession {
public:
  HeaderSession(ImageCtxT* image_ctx);

  // stage the header up to the data offset; *fd is a duplicate of the
  // anonymous file's descriptor, owned by the caller
  void open(int* fd, Context* on_finish);
  // write the changed ranges of the header area back and flush
  void commit(Context* on_finish);

private:
  /**
   * @verbatim
   *
   * open:    READ_HEADER . . (ReadHeaderRequest to the data offset, the
   *              |            RBDL clone magic replaced with LUKS)
   *              v
   *          <finish>
   *
   * commit:  COMPUTE_WRITES . (parse the file again, refuse a moved data
   *              |             offset and data beyond it, diff against
   *              |             the stored bytes with the clone magic
   *              |             restored)
   *              | (no byte changed)
   *              |---------------------\
   *              v                     |
   *          WRITE_RANGES              |
   *              |                     |
   *              v                     |
   *          FLUSH                     |
   *              |                     |
   *              v                     |
   *          <finish> <----------------/
   *
   * @endverbatim
   */
  ImageCtxT* m_image_ctx;
  io::ImageArea m_area;
  Header m_header;
  ceph::bufferlist m_orig_bl;   // header bytes as stored in the image
  ceph::bufferlist m_new_bl;    // header bytes a commit is writing
  bool m_clone_magic = false;   // the image stores the RBD clone magic
  uint64_t m_data_offset = 0;
  int* m_fd = nullptr;
  Context* m_on_finish = nullptr;

  // changed ranges awaiting write-back
  std::vector<std::pair<uint64_t, ceph::bufferlist>> m_pending_writes;
  size_t m_write_index = 0;

  void handle_read_header(int r);
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

extern template class librbd::crypto::luks::HeaderSession<librbd::ImageCtx>;

#endif // CEPH_LIBRBD_CRYPTO_LUKS_HEADER_SESSION_H
