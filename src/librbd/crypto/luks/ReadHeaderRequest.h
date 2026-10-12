// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#ifndef CEPH_LIBRBD_CRYPTO_LUKS_READ_HEADER_REQUEST_H
#define CEPH_LIBRBD_CRYPTO_LUKS_READ_HEADER_REQUEST_H

#include <string>
#include "include/buffer.h"
#include "include/Context.h"
#include "include/rbd/librbd.hpp"
#include "librbd/io/Types.h"
#include "librbd/crypto/luks/Header.h"

namespace librbd {

struct ImageCtx;

namespace crypto {
namespace luks {

// max header size in LUKS1/2 (excl. keyslots) is 4MB
const uint64_t MAXIMUM_HEADER_SIZE = 4 * 1024 * 1024;
// default header size in LUKS2 2 X 16KB + 1 X 256KB keyslot
const uint64_t DEFAULT_INITIAL_READ_SIZE = 288 * 1024;

// Staged read of the LUKS header from the image into a caller-owned
// libcryptsetup Header: an initial read, a retry to the maximum header
// size when parsing fails, clone-magic replacement on a cloned image,
// and optionally an extension to the data offset so the whole keyslot
// area is fed.
//
// Parse mode (create): read from offset 0 until *header loads. With
// read_to_data_offset the read then extends unconditionally to the
// parsed data offset, checking it against the image size first.
// Extend mode (create_extend): append [*bytes_fed, end_offset) to an
// already loaded *header, for keyslot material that is only needed on
// demand.
//
// All out-parameters are optional: bytes_fed receives how many bytes
// were fed from offset 0 (in-out in extend mode), stored_bl the
// verbatim bytes as the image stores them, before any magic
// replacement, clone_magic whether the RBD clone magic was replaced,
// and detected_format_name "LUKS" once a known magic is seen. The
// Header and every out-parameter are caller-owned and must outlive the
// request.
template <typename ImageCtxT = librbd::ImageCtx>
class ReadHeaderRequest {
public:
  static ReadHeaderRequest* create(
      ImageCtxT* image_ctx, io::ImageArea area, encryption_format_t format,
      bool read_to_data_offset, Header* header, uint64_t* bytes_fed,
      ceph::bufferlist* stored_bl, bool* clone_magic,
      std::string* detected_format_name, Context* on_finish) {
    return new ReadHeaderRequest(image_ctx, area, format, read_to_data_offset,
                                 header, bytes_fed, stored_bl, clone_magic,
                                 detected_format_name, on_finish);
  }

  static ReadHeaderRequest* create_extend(
      ImageCtxT* image_ctx, io::ImageArea area, Header* header,
      uint64_t* bytes_fed, uint64_t end_offset, Context* on_finish) {
    auto req = new ReadHeaderRequest(image_ctx, area,
                                     RBD_ENCRYPTION_FORMAT_LUKS,
                                     false, header, bytes_fed, nullptr,
                                     nullptr, nullptr, on_finish);
    req->m_parse = false;
    req->m_end_offset = end_offset;
    req->m_offset = *bytes_fed;
    return req;
  }

  ReadHeaderRequest(ImageCtxT* image_ctx, io::ImageArea area,
                    encryption_format_t format, bool read_to_data_offset,
                    Header* header, uint64_t* bytes_fed,
                    ceph::bufferlist* stored_bl, bool* clone_magic,
                    std::string* detected_format_name, Context* on_finish);
  void send();
  void set_initial_read_size(uint64_t read_size);

private:
  ImageCtxT* m_image_ctx;
  io::ImageArea m_area;
  encryption_format_t m_format;
  bool m_read_to_data_offset;
  Header* m_header;
  uint64_t* m_bytes_fed;
  ceph::bufferlist* m_stored_bl;
  bool* m_clone_magic;
  std::string* m_detected_format_name;
  Context* m_on_finish;

  bool m_parse = true;
  uint64_t m_end_offset = 0;
  uint64_t m_initial_read_size = DEFAULT_INITIAL_READ_SIZE;
  ceph::bufferlist m_bl;
  uint64_t m_offset = 0;

  void read(uint64_t end_offset, Context* on_finish);
  bool handle_read(int r);
  void handle_read_header(int r);
  void handle_read_keyslots(int r);
  void finish(int r);
};

} // namespace luks
} // namespace crypto
} // namespace librbd

extern template class librbd::crypto::luks::ReadHeaderRequest<
        librbd::ImageCtx>;

#endif // CEPH_LIBRBD_CRYPTO_LUKS_READ_HEADER_REQUEST_H
