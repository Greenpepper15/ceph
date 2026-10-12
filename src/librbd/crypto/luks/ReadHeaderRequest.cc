// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#include "ReadHeaderRequest.h"

#include "common/dout.h"
#include "common/errno.h"
#include "librbd/ImageCtx.h"
#include "librbd/Utils.h"
#include "librbd/crypto/LoadRequest.h"
#include "librbd/crypto/luks/Magic.h"
#include "librbd/io/AioCompletion.h"
#include "librbd/io/ImageDispatchSpec.h"
#include "librbd/io/ReadResult.h"

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::crypto::luks::ReadHeaderRequest: " \
                           << this << " " << __func__ << ": "

namespace librbd {
namespace crypto {
namespace luks {

using librbd::util::create_context_callback;

template <typename I>
ReadHeaderRequest<I>::ReadHeaderRequest(
        I* image_ctx, io::ImageArea area, encryption_format_t format,
        bool read_to_data_offset, Header* header, uint64_t* bytes_fed,
        ceph::bufferlist* stored_bl, bool* clone_magic,
        std::string* detected_format_name,
        Context* on_finish) : m_image_ctx(image_ctx),
                              m_area(area),
                              m_format(format),
                              m_read_to_data_offset(read_to_data_offset),
                              m_header(header),
                              m_bytes_fed(bytes_fed),
                              m_stored_bl(stored_bl),
                              m_clone_magic(clone_magic),
                              m_detected_format_name(detected_format_name),
                              m_on_finish(on_finish) {
}

template <typename I>
void ReadHeaderRequest<I>::set_initial_read_size(uint64_t read_size) {
  m_initial_read_size = read_size;
}

template <typename I>
void ReadHeaderRequest<I>::send() {
  if (!m_parse) {
    ceph_assert(m_end_offset > m_offset);
    auto ctx = create_context_callback<
            ReadHeaderRequest<I>,
            &ReadHeaderRequest<I>::handle_read_keyslots>(this);
    read(m_end_offset, ctx);
    return;
  }

  auto ctx = create_context_callback<
          ReadHeaderRequest<I>,
          &ReadHeaderRequest<I>::handle_read_header>(this);
  read(m_initial_read_size, ctx);
}

template <typename I>
void ReadHeaderRequest<I>::read(uint64_t end_offset, Context* on_finish) {
  ldout(m_image_ctx->cct, 20) << "offset=" << m_offset << " end_offset="
                              << end_offset << " area=" << m_area << dendl;

  auto length = end_offset - m_offset;
  auto aio_comp = io::AioCompletion::create_and_start(
          on_finish, librbd::util::get_image_ctx(m_image_ctx),
          io::AIO_TYPE_READ);
  ZTracer::Trace trace;
  auto req = io::ImageDispatchSpec::create_read(
          *m_image_ctx, io::IMAGE_DISPATCH_LAYER_API_START, aio_comp,
          {{m_offset, length}}, m_area, io::ReadResult{&m_bl},
          m_image_ctx->get_data_io_context(), 0, 0, trace);
  req->send();
}

template <typename I>
bool ReadHeaderRequest<I>::handle_read(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  if (r < 0) {
    lderr(m_image_ctx->cct) << "error reading from image: " << cpp_strerror(r)
                            << dendl;
    finish(r);
    return false;
  }

  if (m_stored_bl != nullptr) {
    // verbatim copy of the bytes as the image stores them, taken before
    // any magic replacement edits m_bl in place
    m_stored_bl->append(m_bl.c_str(), m_bl.length());
  }

  // first, check LUKS magic at the beginning of the image
  // If no magic is detected, caller may assume image is actually plaintext
  if (m_offset == 0 && m_parse) {
    if (Magic::is_luks(m_bl) > 0 || Magic::is_rbd_clone(m_bl) > 0) {
      if (m_detected_format_name != nullptr) {
        *m_detected_format_name = "LUKS";
      }
    } else {
      if (m_detected_format_name != nullptr) {
        *m_detected_format_name = crypto::LoadRequest<I>::UNKNOWN_FORMAT;
      }
      finish(-EINVAL);
      return false;
    }

    if (m_image_ctx->parent != nullptr && Magic::is_rbd_clone(m_bl) > 0) {
      r = Magic::replace_magic(m_image_ctx->cct, m_bl);
      if (r < 0) {
        m_image_ctx->image_lock.lock_shared();
        auto image_size = m_image_ctx->get_image_size(m_image_ctx->snap_id);
        m_image_ctx->image_lock.unlock_shared();

        auto max_header_size = std::min(MAXIMUM_HEADER_SIZE, image_size);

        if (r == -EINVAL && m_bl.length() < max_header_size) {
          m_bl.clear();
          if (m_stored_bl != nullptr) {
            m_stored_bl->clear();
          }
          auto ctx = create_context_callback<
                ReadHeaderRequest<I>,
                &ReadHeaderRequest<I>::handle_read_header>(this);
          read(max_header_size, ctx);
          return false;
        }

        lderr(m_image_ctx->cct) << "error replacing rbd clone magic: "
                                << cpp_strerror(r) << dendl;
        finish(r);
        return false;
      }
      if (m_clone_magic != nullptr) {
        *m_clone_magic = true;
      }
    }
  }

  // setup interface with libcryptsetup
  r = m_header->init();
  if (r < 0) {
    finish(r);
    return false;
  }

  m_offset += m_bl.length();

  // write header to libcryptsetup interface
  r = m_header->write(m_bl);
  if (r < 0) {
    finish(r);
    return false;
  }

  m_bl.clear();

  if (m_bytes_fed != nullptr) {
    *m_bytes_fed = m_offset;
  }

  return true;
}

template <typename I>
void ReadHeaderRequest<I>::handle_read_header(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  if (!handle_read(r)) {
    return;
  }

  const char* type;
  switch (m_format) {
  case RBD_ENCRYPTION_FORMAT_LUKS:
    type = CRYPT_LUKS;
    break;
  case RBD_ENCRYPTION_FORMAT_LUKS1:
    type = CRYPT_LUKS1;
    break;
  case RBD_ENCRYPTION_FORMAT_LUKS2:
    type = CRYPT_LUKS2;
    break;
  default:
    lderr(m_image_ctx->cct) << "unsupported format type: " << m_format
                            << dendl;
    finish(-EINVAL);
    return;
  }

  // parse header via libcryptsetup
  r = m_header->load(type);
  if (r != 0) {
    if (m_offset < MAXIMUM_HEADER_SIZE) {
      // perhaps we did not feed the entire header to libcryptsetup, retry
      auto ctx = create_context_callback<
              ReadHeaderRequest<I>,
              &ReadHeaderRequest<I>::handle_read_header>(this);
      read(MAXIMUM_HEADER_SIZE, ctx);
      return;
    }

    finish(r);
    return;
  }

  if (m_read_to_data_offset) {
    auto data_offset = m_header->get_data_offset();

    m_image_ctx->image_lock.lock_shared();
    uint64_t image_size = m_image_ctx->get_image_size(m_image_ctx->snap_id);
    m_image_ctx->image_lock.unlock_shared();

    if (data_offset > image_size) {
      lderr(m_image_ctx->cct) << "image is too small, data offset "
                              << data_offset << dendl;
      finish(-EINVAL);
      return;
    }

    // crypt_load succeeds once the metadata parses, but a caller that
    // modifies the header needs the whole keyslot area, which extends to
    // the data offset; fetch the remainder when the reads stopped short
    if (m_offset < data_offset) {
      auto ctx = create_context_callback<
              ReadHeaderRequest<I>,
              &ReadHeaderRequest<I>::handle_read_keyslots>(this);
      read(data_offset, ctx);
      return;
    }
  }

  finish(0);
}

template <typename I>
void ReadHeaderRequest<I>::handle_read_keyslots(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  if (!handle_read(r)) {
    return;
  }

  if (m_read_to_data_offset && m_offset < m_header->get_data_offset()) {
    // the read was clipped: the image cannot hold the whole header
    lderr(m_image_ctx->cct) << "short header, read " << m_offset
                            << " bytes of " << m_header->get_data_offset()
                            << dendl;
    finish(-EINVAL);
    return;
  }

  finish(0);
}

template <typename I>
void ReadHeaderRequest<I>::finish(int r) {
  ldout(m_image_ctx->cct, 20) << "r=" << r << dendl;

  m_on_finish->complete(r);
  delete this;
}

} // namespace luks
} // namespace crypto
} // namespace librbd

template class librbd::crypto::luks::ReadHeaderRequest<librbd::ImageCtx>;
