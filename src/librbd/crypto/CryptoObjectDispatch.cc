// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:t -*-
// vim: ts=8 sw=2 smarttab

#include "librbd/crypto/CryptoObjectDispatch.h"
#include <thread>
#include "include/ceph_assert.h"
#include "include/scope_guard.h"
#include "include/neorados/RADOS.hpp"
#include "common/dout.h"
#include "osdc/Striper.h"
#include "librbd/ImageCtx.h"
#include "librbd/Utils.h"
#include "librbd/crypto/CryptoInterface.h"
#include "librbd/io/AioCompletion.h"
#include "librbd/io/ObjectDispatcherInterface.h"
#include "librbd/io/ObjectDispatchSpec.h"
#include "librbd/io/ReadResult.h"
#include "librbd/io/Utils.h"

#define dout_subsys ceph_subsys_rbd
#undef dout_prefix
#define dout_prefix *_dout << "librbd::crypto::CryptoObjectDispatch: " \
                           << this << " " << __func__ << ": "

namespace librbd {
namespace crypto {

using librbd::util::create_context_callback;
using librbd::util::data_object_name;
// TODO: Make Striper aware of ciphertext expansion? 
        // i.e. that we write more than 4096 bytes?
template <typename I>
uint64_t get_file_offset(I* image_ctx, uint64_t object_no,
                         uint64_t object_off) {
  auto off = io::util::raw_to_area_offset(
      *image_ctx, Striper::get_file_offset(image_ctx->cct, &image_ctx->layout,
                                           object_no, object_off));
  ceph_assert(off.second == io::ImageArea::DATA);
  return off.first;
}

template <typename I>
struct C_AlignedObjectReadRequest : public Context {
    I* image_ctx;
    CryptoInterface* crypto;
    uint64_t object_no;
    io::ReadExtents* extents;
    IOContext io_context;
    const ZTracer::Trace parent_trace;
    uint64_t* version;
    Context* on_finish;
    io::ObjectDispatchSpec* req;
    bool disable_read_from_parent;

    C_AlignedObjectReadRequest(
            I* image_ctx, CryptoInterface* crypto,
            uint64_t object_no, io::ReadExtents* extents, IOContext io_context,
            int op_flags, int read_flags, const ZTracer::Trace &parent_trace,
            uint64_t* version, int* object_dispatch_flags,
            Context* on_dispatched
            ) : image_ctx(image_ctx), crypto(crypto), object_no(object_no),
                extents(extents), io_context(io_context),
                parent_trace(parent_trace), version(version),
                on_finish(on_dispatched) {
      disable_read_from_parent =
              ((read_flags & io::READ_FLAG_DISABLE_READ_FROM_PARENT) != 0);
      read_flags |= io::READ_FLAG_DISABLE_READ_FROM_PARENT;

      auto ctx = create_context_callback<
              C_AlignedObjectReadRequest<I>,
              &C_AlignedObjectReadRequest<I>::handle_read>(this);

      req = io::ObjectDispatchSpec::create_read(
              image_ctx, io::OBJECT_DISPATCH_LAYER_CRYPTO, object_no,
              extents, io_context, op_flags, read_flags, parent_trace,
              version, ctx);
    }

    void send() {
      req->send();
    }

    void finish(int r) override {
      ldout(image_ctx->cct, 20) << "aligned read r=" << r << dendl;
      on_finish->complete(r);
    }

    void handle_read(int r) {
      auto cct = image_ctx->cct;
      ldout(cct, 20) << "aligned read r=" << r << dendl;
      if (r >= 0) {
        r = 0;
        const bool has_meta = (crypto->get_meta_size() > 0);
        const size_t stride = has_meta ? 2 : 1;
        for (size_t i = 0; i < extents->size(); i += stride) {
          if (has_meta && (i + 1 >= extents->size())) {
             lderr(cct) << "Missing metadata extent for index " << i << dendl;
             r = -EINVAL; 
             break;
          }
          auto& data_extent = (*extents)[i];
          auto* meta_extent = has_meta ? &(*extents)[i+1] : nullptr;
          auto crypto_ret = crypto->decrypt_aligned_extent(
              data_extent, 
              get_file_offset(image_ctx, object_no, data_extent.offset),
              meta_extent);
          if (crypto_ret != 0) {
            ceph_assert(crypto_ret < 0);
            r = crypto_ret;
            break;
          }
          r += data_extent.length;
        }
      }

      if (r == -ENOENT && !disable_read_from_parent) {
        // For AEAD, strip metadata extents before reading from parent.
        // read_parent is based on logical extents
        if (crypto->get_meta_size() > 0) {
          io::ReadExtents data_only;
          for (size_t i = 0; i < extents->size(); i += 2) {
            data_only.push_back(std::move((*extents)[i]));
          }
          *extents = std::move(data_only);
        }
        io::util::read_parent<I>(
                image_ctx, object_no, extents,
                io_context->read_snap().value_or(CEPH_NOSNAP),
                parent_trace, this);
      } else {
        complete(r);
      }
    }
};

template <typename I>
struct C_UnalignedObjectReadRequest : public Context {
    I* image_ctx;
    CryptoInterface* crypto;
    uint64_t object_no;
    CephContext* cct;
    io::ReadExtents* extents;
    IOContext io_context;
    const ZTracer::Trace parent_trace;
    Context* on_finish;
    io::ReadExtents aligned_extents;
    io::ObjectDispatchSpec* req;
    bool disable_read_from_parent;
    // Unaligned reads normally go through two buffers:
    //   1. Read aligned data into aligned_extents, decrypt it
    //   2. finish() calls remove_alignment_data() to extract the
    //      requested unaligned slice from aligned_extents into *extents
    //
    // When the object doesn't exist (-ENOENT), we fall back to
    // read_parent(), which reads directly into *extents — the parent's
    // crypto layer handles decryption and alignment. aligned_extents
    // stays empty, so remove_alignment_data() must be skipped.
    bool m_read_from_parent{false};

    C_UnalignedObjectReadRequest(
            I* image_ctx, CryptoInterface* crypto,
            uint64_t object_no, io::ReadExtents* extents, IOContext io_context,
            int op_flags, int read_flags, const ZTracer::Trace &parent_trace,
            uint64_t* version, int* object_dispatch_flags,
            Context* on_dispatched)
        : image_ctx(image_ctx), crypto(crypto), object_no(object_no),
          cct(image_ctx->cct), extents(extents), io_context(io_context),
          parent_trace(parent_trace), on_finish(on_dispatched) {
    if (crypto->get_meta_size() != 0) {
      crypto->get_physical_extends(*extents, &aligned_extents, image_ctx->get_object_size());
      read_flags |= io::READ_FLAG_ENCRYPTED_AEAD_READ;
    } else {
      crypto->align_extents(*extents, &aligned_extents);
    }

    ldout(cct, 20) << data_object_name(image_ctx, object_no) << " aligned extends "
                 << aligned_extents << dendl;

      disable_read_from_parent =
              ((read_flags & io::READ_FLAG_DISABLE_READ_FROM_PARENT) != 0);
      read_flags |= io::READ_FLAG_DISABLE_READ_FROM_PARENT;

      // We decrypt in handle_read().
      auto ctx = create_context_callback<
              C_UnalignedObjectReadRequest<I>,
              &C_UnalignedObjectReadRequest<I>::handle_read>(this);

      req = io::ObjectDispatchSpec::create_read(
              image_ctx, io::OBJECT_DISPATCH_LAYER_CRYPTO,
              object_no, &aligned_extents, io_context, op_flags, read_flags,
              parent_trace, version, ctx);
    }

    void send() {
      req->send();
    }

    void remove_alignment_data() {
      // When AEAD is active, get_physical_extends creates 2N aligned extents
      // (data+meta pairs) for N original extents. Use stride 2 to skip meta.
      const bool has_meta = (aligned_extents.size() > extents->size());
      const size_t stride = has_meta ? 2 : 1;
      for (uint64_t i = 0; i < extents->size(); ++i) {
        auto& extent = (*extents)[i];
        auto& aligned_extent = aligned_extents[i * stride];
        if (aligned_extent.extent_map.empty()) {
          uint64_t cut_offset = extent.offset - aligned_extent.offset;
          int64_t padding_count =
                  cut_offset + extent.length - aligned_extent.bl.length();
          if (padding_count > 0) {
            aligned_extent.bl.append_zero(padding_count);
          }
          aligned_extent.bl.splice(cut_offset, extent.length, &extent.bl);
        } else {
          for (auto [off, len]: aligned_extent.extent_map) {
            ceph::bufferlist tmp;
            aligned_extent.bl.splice(0, len, &tmp);

            uint64_t bytes_to_skip = 0;
            if (off < extent.offset) {
              bytes_to_skip = extent.offset - off;
              if (len <= bytes_to_skip) {
                continue;
              }
              off += bytes_to_skip;
              len -= bytes_to_skip;
            }

            len = std::min(len, extent.offset + extent.length - off);
            if (len == 0) {
              continue;
            }

            if (len > 0) {
              tmp.splice(bytes_to_skip, len, &extent.bl);
              extent.extent_map.emplace_back(off, len);
            }
          }
        }
      }
    }

    void handle_read(int r) {
      auto cct = image_ctx->cct;
      ldout(cct, 20) << "unaligned read r=" << r << dendl;
      if (r >= 0) {
        // Decrypt aligned extents using the crypto selected when
        // this request was created.
        r = 0;
        const bool has_meta = (crypto->get_meta_size() > 0);
        const size_t stride = has_meta ? 2 : 1;
        for (size_t i = 0; i < aligned_extents.size(); i += stride) {
          if (has_meta && (i + 1 >= aligned_extents.size())) {
            lderr(cct) << "Missing metadata extent for index " << i << dendl;
            r = -EINVAL;
            break;
          }
          auto& data_extent = aligned_extents[i];
          auto* meta_extent = has_meta ? &aligned_extents[i + 1] : nullptr;
          auto crypto_ret = crypto->decrypt_aligned_extent(
              data_extent,
              get_file_offset(image_ctx, object_no, data_extent.offset),
              meta_extent);
          if (crypto_ret != 0) {
            ceph_assert(crypto_ret < 0);
            r = crypto_ret;
            break;
          }
          r += data_extent.length;
        }
      }

      if (r == -ENOENT && !disable_read_from_parent) {
        // Parent read puts data directly into extents (not aligned_extents).
        // The parent's crypto layer decrypts, so no alignment removal needed.
        // For AEAD, strip metadata extents before reading from parent —
        // parent reads use logical extents only.
        if (crypto->get_meta_size() > 0) {
          io::ReadExtents data_only;
          for (size_t i = 0; i < extents->size(); i += 2) {
            data_only.push_back(std::move((*extents)[i]));
          }
          *extents = std::move(data_only);
        }
        m_read_from_parent = true;
        io::util::read_parent<I>(
                image_ctx, object_no, extents,
                io_context->read_snap().value_or(CEPH_NOSNAP),
                parent_trace, this);
      } else {
        complete(r);
      }
    }

    void finish(int r) override {
      ldout(cct, 20) << "unaligned read r=" << r << dendl;
      if (r >= 0 && !m_read_from_parent) {
        remove_alignment_data();

        r = 0;
        for (auto& extent: *extents) {
          r += extent.length;
        }
      }
      on_finish->complete(r);
    }
};

template <typename I>
struct C_UnalignedObjectWriteRequest : public Context {
    I* image_ctx;
    CryptoInterface* crypto;
    uint64_t object_no;
    uint64_t object_off;
    ceph::bufferlist data;
    ceph::bufferlist cmp_data;
    uint64_t* mismatch_offset;
    IOContext io_context;
    int op_flags;
    int write_flags;
    std::optional<uint64_t> assert_version;
    const ZTracer::Trace parent_trace;
    int* object_dispatch_flags;
    uint64_t* journal_tid;
    Context* on_finish;
    bool may_copyup;
    ceph::bufferlist aligned_data;
    io::ReadExtents extents;
    uint64_t version;
    C_UnalignedObjectReadRequest<I>* read_req;
    bool object_exists;

    C_UnalignedObjectWriteRequest(
            I* image_ctx, CryptoInterface* crypto,
            uint64_t object_no, uint64_t object_off, ceph::bufferlist&& data,
            ceph::bufferlist&& cmp_data, uint64_t* mismatch_offset,
            IOContext io_context, int op_flags, int write_flags,
            std::optional<uint64_t> assert_version,
            const ZTracer::Trace &parent_trace, int* object_dispatch_flags,
            uint64_t* journal_tid, Context* on_dispatched, bool may_copyup
            ) : image_ctx(image_ctx), crypto(crypto), object_no(object_no),
                object_off(object_off), data(data), cmp_data(cmp_data),
                mismatch_offset(mismatch_offset), io_context(io_context),
                op_flags(op_flags), write_flags(write_flags),
                assert_version(assert_version), parent_trace(parent_trace),
                object_dispatch_flags(object_dispatch_flags),
                journal_tid(journal_tid), on_finish(on_dispatched),
                may_copyup(may_copyup) {
      // build read extents
      auto [pre_align, post_align] = crypto->get_pre_and_post_align(
              object_off, data.length());
      if (pre_align != 0) {
        extents.emplace_back(object_off - pre_align, pre_align);
      }
      if (post_align != 0) {
        extents.emplace_back(object_off + data.length(), post_align);
      }
      if (cmp_data.length() != 0) {
        extents.emplace_back(object_off, cmp_data.length());
      }

      auto ctx = create_context_callback<
              C_UnalignedObjectWriteRequest<I>,
              &C_UnalignedObjectWriteRequest<I>::handle_read>(this);

      read_req = new C_UnalignedObjectReadRequest<I>(
              image_ctx, crypto, object_no, &extents, io_context,
              0, io::READ_FLAG_DISABLE_READ_FROM_PARENT, parent_trace,
              &version, 0, ctx);
    }

    void send() {
      read_req->send();
    }

    bool check_cmp_data() {
      if (cmp_data.length() == 0) {
        return true;
      }

      auto& cmp_extent = extents.back();
      io::util::unsparsify(image_ctx->cct, &cmp_extent.bl,
                           cmp_extent.extent_map, cmp_extent.offset,
                           cmp_extent.length);

      std::optional<uint64_t> found_mismatch = std::nullopt;

      auto it1 = cmp_data.cbegin();
      auto it2 = cmp_extent.bl.cbegin();
      for (uint64_t idx = 0; idx < cmp_data.length(); ++idx) {
        if (*it1 != *it2) {
          found_mismatch = std::make_optional(idx);
          break;
        }
        ++it1;
        ++it2;
      }

      extents.pop_back();

      if (found_mismatch.has_value()) {
        if (mismatch_offset != nullptr) {
          *mismatch_offset = found_mismatch.value();
        }
        complete(-EILSEQ);
        return false;
      }

      return true;
    }

    bool check_create_exclusive() {
      bool exclusive =
              ((write_flags & io::OBJECT_WRITE_FLAG_CREATE_EXCLUSIVE) != 0);
      if (exclusive && object_exists) {
        complete(-EEXIST);
        return false;
      }
      return true;
    }

    bool check_version() {
      int r = 0;
      if (assert_version.has_value()) {
        if (!object_exists) {
          r = -ENOENT;
        } else if (assert_version.value() < version) {
          r = -ERANGE;
        } else if (assert_version.value() > version) {
          r = -EOVERFLOW;
        }
      }

      if (r != 0) {
        complete(r);
        return false;
      }
      return true;
    }

    void build_aligned_data() {
      auto [pre_align, post_align] = crypto->get_pre_and_post_align(
              object_off, data.length());
      if (pre_align != 0) {
        auto &extent = extents.front();
        io::util::unsparsify(image_ctx->cct, &extent.bl, extent.extent_map,
                             extent.offset, extent.length);
        extent.bl.splice(0, pre_align, &aligned_data);
      }
      aligned_data.append(data);
      if (post_align != 0) {
        auto &extent = extents.back();
        io::util::unsparsify(image_ctx->cct, &extent.bl, extent.extent_map,
                             extent.offset, extent.length);
        extent.bl.splice(0, post_align, &aligned_data);
      }
    }

    void handle_copyup(int r) {
      ldout(image_ctx->cct, 20) << "r=" << r << dendl;
      if (r < 0) {
        complete(r);
      } else {
        restart_request(false);
      }
    }

    void handle_read(int r) {
      ldout(image_ctx->cct, 20) << "unaligned write r=" << r << dendl;

      if (r == -ENOENT) {
        if (may_copyup) {
          auto ctx = create_context_callback<
                  C_UnalignedObjectWriteRequest<I>,
                  &C_UnalignedObjectWriteRequest<I>::handle_copyup>(this);
          if (io::util::trigger_copyup(
                  image_ctx, object_no, io_context, ctx)) {
            return;
          }
          delete ctx;
        }
        object_exists = false;
      } else if (r < 0) {
        complete(r);
        return;
      } else {
        object_exists = true;
      }

      if (!check_create_exclusive() || !check_version() || !check_cmp_data()) {
        return;
      }

      build_aligned_data();

      auto aligned_off = crypto->align(object_off, data.length()).first;
      auto new_write_flags = write_flags;
      auto new_assert_version = std::make_optional(version);
      if (!object_exists) {
        new_write_flags |=  io::OBJECT_WRITE_FLAG_CREATE_EXCLUSIVE;
        new_assert_version = std::nullopt;
      }

      // Encrypt here instead of re-entering the crypto dispatch.
      // Re-entering via get_previous_layer(CRYPTO) → CACHE causes
      // upper_bound(CACHE) to find CRYPTO, which would deadlock with
      // set_reencrypting_object's spin loop during re-encryption.
      auto file_offset = get_file_offset(image_ctx, object_no, aligned_off);
      auto crypto_ret = crypto->encrypt(&aligned_data, file_offset);
      if (crypto_ret != 0) {
        on_finish->complete(crypto_ret);
        return;
      }

      if (crypto->get_meta_size() > 0) {
        new_write_flags |= io::OBJECT_WRITE_FLAG_ENCRYPTED_AEAD_WRITE;
      }

      auto ctx = create_context_callback<
              C_UnalignedObjectWriteRequest<I>,
              &C_UnalignedObjectWriteRequest<I>::handle_write>(this);

      auto write_req = io::ObjectDispatchSpec::create_write(
              image_ctx,
              io::OBJECT_DISPATCH_LAYER_CRYPTO,
              object_no, aligned_off, std::move(aligned_data), io_context,
              op_flags, new_write_flags, new_assert_version,
              journal_tid == nullptr ? 0 : *journal_tid, parent_trace, ctx);
      write_req->send();
    }

    void restart_request(bool may_copyup) {
      auto req = new C_UnalignedObjectWriteRequest<I>(
              image_ctx, crypto, object_no, object_off,
              std::move(data), std::move(cmp_data),
              mismatch_offset, io_context, op_flags, write_flags,
              assert_version, parent_trace,
              object_dispatch_flags, journal_tid, this, may_copyup);
      req->send();
    }

    void handle_write(int r) {
      ldout(image_ctx->cct, 20) << "r=" << r << dendl;
      bool exclusive = write_flags & io::OBJECT_WRITE_FLAG_CREATE_EXCLUSIVE;
      bool restart = false;
      if (r == -ERANGE && !assert_version.has_value()) {
        restart = true;
      } else if (r == -EEXIST && !exclusive) {
        restart = true;
      }

      if (restart) {
        restart_request(may_copyup);
      } else {
        complete(r);
      }
    }

    void finish(int r) override {
      ldout(image_ctx->cct, 20) << "unaligned write r=" << r << dendl;
      on_finish->complete(r);
    }
};

template <typename I>
CryptoObjectDispatch<I>::CryptoObjectDispatch(
    I* image_ctx, CryptoInterface* crypto)
  : m_image_ctx(image_ctx), m_crypto(crypto) {
  m_data_offset_object_no = Striper::get_num_objects(image_ctx->layout,
                                                     crypto->get_data_offset());
}

template <typename I>
CryptoInterface* CryptoObjectDispatch<I>::get_crypto_for_object(
    uint64_t object_no, bool& tracked) {

  // Wait if this object is being re-encrypted. Must be BEFORE any
  // counter increment to avoid deadlock with set_reencrypting_object's
  // condvar drain: IOs that spin here don't hold a counter.
  while (m_reencrypting_object_no.load(std::memory_order_acquire)
         == static_cast<int64_t>(object_no)) {
    std::this_thread::yield();
  }

  // seq_cst key selection: read m_crypto FIRST, m_old_crypto SECOND.
  // swap_crypto stores m_old_crypto FIRST, m_crypto SECOND (both seq_cst).
  // If we see m_old_crypto == nullptr, the m_crypto we already read is
  // guaranteed to be the pre-swap value (seq_cst total order).
  auto* crypto = m_crypto.load(std::memory_order_seq_cst);
  auto* old = m_old_crypto.load(std::memory_order_seq_cst);

  if (old == nullptr) {
    // Not in dual-key mode. No counting needed.
    tracked = false;
    return crypto;
  }

  // Dual-key mode: lock-free counter increment on sharded bucket.
  m_in_flight_buckets[object_no % BUCKET_COUNT].count.fetch_add(
      1, std::memory_order_acq_rel);
  tracked = true;

  if (object_no < m_reencrypt_cursor.load(std::memory_order_acquire)) {
    return m_crypto.load(std::memory_order_acquire);   // new key
  }
  return old;                                          // old key
}

template <typename I>
void CryptoObjectDispatch<I>::swap_crypto(
    CryptoInterface* new_crypto, CryptoInterface* old_crypto, uint64_t cursor) {
  // Store m_old_crypto FIRST, m_crypto LAST — both seq_cst.
  // get_crypto_for_object reads in reverse order (m_crypto first,
  // m_old_crypto second, both seq_cst), so a reader that sees
  // m_old_crypto == nullptr is guaranteed to have read the pre-swap
  // m_crypto (seq_cst total order).
  //
  // m_crypto is stored LAST to minimize the window during which
  // concurrent IO enters dual-key mode and increments bucket counters.
  // Storing it earlier causes set_reencrypting_object's drain to
  // contend with a flood of tracked IOs.
  m_old_crypto.store(old_crypto, std::memory_order_seq_cst);
  m_reencrypt_cursor.store(cursor, std::memory_order_release);
  m_reencrypting_object_no.store(-1, std::memory_order_release);
  m_crypto.store(new_crypto, std::memory_order_seq_cst);
}

template <typename I>
void CryptoObjectDispatch<I>::advance_reencrypt_cursor(uint64_t new_cursor) {
  m_reencrypting_object_no.store(-1, std::memory_order_release);
  m_reencrypt_cursor.store(new_cursor, std::memory_order_release);
}

template <typename I>
void CryptoObjectDispatch<I>::set_reencrypting_object(int64_t object_no) {
  auto cct = m_image_ctx->cct;
  auto& bucket = m_in_flight_buckets[object_no % BUCKET_COUNT];
  ldout(cct, 10) << "object_no=" << object_no
                 << " bucket=" << (object_no % BUCKET_COUNT)
                 << " bucket_count=" << bucket.count.load(std::memory_order_acquire)
                 << dendl;
  m_reencrypting_object_no.store(object_no, std::memory_order_release);

  // Wait for in-flight IOs in this object's bucket to complete.
  std::unique_lock lock(m_drain_lock);
  m_drain_cond.wait(lock, [&] {
    return bucket.count.load(std::memory_order_acquire) == 0;
  });
}

template <typename I>
void CryptoObjectDispatch<I>::complete_io(uint64_t object_no) {
  auto& bucket = m_in_flight_buckets[object_no % BUCKET_COUNT];
  if (bucket.count.fetch_sub(1, std::memory_order_acq_rel) == 1) {
    // Bucket reached 0. Signal any drain waiters.
    std::lock_guard lock(m_drain_lock);
    m_drain_cond.notify_all();
  }
}

template <typename I>
void CryptoObjectDispatch<I>::finish_reencryption() {
  m_reencrypting_object_no.store(-1, std::memory_order_release);

  // Wait for all in-flight dual-key IOs to complete.
  {
    std::unique_lock lock(m_drain_lock);
    m_drain_cond.wait(lock, [&] {
      for (auto& bucket : m_in_flight_buckets) {
        if (bucket.count.load(std::memory_order_acquire) > 0) {
          return false;
        }
      }
      return true;
    });
  }

  m_old_crypto.store(nullptr, std::memory_order_seq_cst);
}

template <typename I>
void CryptoObjectDispatch<I>::shut_down(Context* on_finish) {
  on_finish->complete(0);
}

template <typename I>
bool CryptoObjectDispatch<I>::read(
    uint64_t object_no, io::ReadExtents* extents, IOContext io_context,
    int op_flags, int read_flags, const ZTracer::Trace &parent_trace,
    uint64_t* version, int* object_dispatch_flags,
    io::DispatchResult* dispatch_result, Context** on_finish,
    Context* on_dispatched) {
  if (object_no < m_data_offset_object_no) {
    return false;
  }

  auto cct = m_image_ctx->cct;
  ldout(cct, 20) << data_object_name(m_image_ctx, object_no) << " "
                 << *extents << dendl;
  ceph_assert(m_crypto.load(std::memory_order_relaxed) != nullptr);

  bool tracked;
  auto crypto = get_crypto_for_object(object_no, tracked);

  auto* final_on_dispatched = on_dispatched;
  if (tracked) {
    auto* dispatch = this;
    final_on_dispatched = new LambdaContext(
        [on_dispatched, dispatch, object_no](int r) {
          dispatch->complete_io(object_no);
          on_dispatched->complete(r);
        });
  }

  *dispatch_result = io::DISPATCH_RESULT_COMPLETE;
  bool is_request_aligned;
  if (crypto->get_meta_size() != 0) {
    // If the READ_FLAG_ENCRYPTED_AEAD_READ we know it already contains
    // physically aligned extents.
    is_request_aligned = (read_flags & io::READ_FLAG_ENCRYPTED_AEAD_READ) != 0;
  } else {
    is_request_aligned = crypto->is_aligned(*extents);
  }
  if (is_request_aligned) {
    auto req = new C_AlignedObjectReadRequest<I>(
            m_image_ctx, crypto, object_no, extents, io_context,
            op_flags, read_flags, parent_trace, version, object_dispatch_flags,
            final_on_dispatched);
    req->send();
  } else {
    auto req = new C_UnalignedObjectReadRequest<I>(
            m_image_ctx, crypto, object_no, extents, io_context,
            op_flags, read_flags, parent_trace, version, object_dispatch_flags,
            final_on_dispatched);
    req->send();
  }

  return true;
}

template <typename I>
bool CryptoObjectDispatch<I>::write(
    uint64_t object_no, uint64_t object_off, ceph::bufferlist&& data,
    IOContext io_context, int op_flags, int write_flags,
    std::optional<uint64_t> assert_version,
    const ZTracer::Trace &parent_trace, int* object_dispatch_flags,
    uint64_t* journal_tid, io::DispatchResult* dispatch_result,
    Context** on_finish, Context* on_dispatched) {
  if (object_no < m_data_offset_object_no) {
    return false;
  }

  auto cct = m_image_ctx->cct;
  ldout(cct, 20) << data_object_name(m_image_ctx, object_no) << " "
                 << object_off << "~" << data.length() << dendl;
  ceph_assert(m_crypto.load(std::memory_order_relaxed) != nullptr);

  bool tracked;
  auto crypto = get_crypto_for_object(object_no, tracked);

  auto* final_on_dispatched = on_dispatched;
  if (tracked) {
    auto* dispatch = this;
    final_on_dispatched = new LambdaContext(
        [on_dispatched, dispatch, object_no](int r) {
          dispatch->complete_io(object_no);
          on_dispatched->complete(r);
        });
  }

  if (crypto->is_aligned(object_off, data.length())) {
    auto r = crypto->encrypt(
        &data, get_file_offset(m_image_ctx, object_no, object_off));
    // TODO: Maybe use issue a new write to use write_flags instead
    ceph_assert(object_dispatch_flags != nullptr);
    *object_dispatch_flags |= (crypto->get_meta_size() > 0)
                                  ? io::OBJECT_DISPATCH_FLAG_IS_AEAD_ENCRYPTED
                                  : 0;
    *dispatch_result = r == 0 ? io::DISPATCH_RESULT_CONTINUE
                              : io::DISPATCH_RESULT_COMPLETE;
    final_on_dispatched->complete(r);
  } else {
    *dispatch_result = io::DISPATCH_RESULT_COMPLETE;
    auto req = new C_UnalignedObjectWriteRequest<I>(
            m_image_ctx, crypto, object_no, object_off, std::move(data), {},
            nullptr, io_context, op_flags, write_flags, assert_version,
            parent_trace, object_dispatch_flags, journal_tid, final_on_dispatched,
            true);
    req->send();
  }

  return true;
}

template <typename I>
bool CryptoObjectDispatch<I>::write_same(
    uint64_t object_no, uint64_t object_off, uint64_t object_len,
    io::LightweightBufferExtents&& buffer_extents, ceph::bufferlist&& data,
    IOContext io_context, int op_flags,
    const ZTracer::Trace &parent_trace, int* object_dispatch_flags,
    uint64_t* journal_tid, io::DispatchResult* dispatch_result,
    Context** on_finish, Context* on_dispatched) {
  if (object_no < m_data_offset_object_no) {
    return false;
  }

  auto cct = m_image_ctx->cct;
  ldout(cct, 20) << data_object_name(m_image_ctx, object_no) << " "
                 << object_off << "~" << object_len << dendl;
  ceph_assert(m_crypto.load(std::memory_order_relaxed) != nullptr);

  // Do NOT call get_crypto_for_object() here. write_same converts to a
  // regular write dispatched through get_previous_layer(CRYPTO), which
  // re-enters write(). write() calls get_crypto_for_object() itself for
  // dual-key synchronization. Calling it here too would double-increment
  // the bucket counter, causing deadlock with set_reencrypting_object's
  // bucket drain.

  // convert to regular write
  io::LightweightObjectExtent extent(object_no, object_off, object_len, 0);
  extent.buffer_extents = std::move(buffer_extents);

  bufferlist ws_data;
  io::util::assemble_write_same_extent(extent, data, &ws_data, true);

  *dispatch_result = io::DISPATCH_RESULT_COMPLETE;
  auto req = io::ObjectDispatchSpec::create_write(
          m_image_ctx,
          io::util::get_previous_layer(io::OBJECT_DISPATCH_LAYER_CRYPTO),
          object_no, object_off, std::move(ws_data), io_context, op_flags, 0,
          std::nullopt, 0, parent_trace, on_dispatched);
  req->send();
  return true;
}

template <typename I>
bool CryptoObjectDispatch<I>::compare_and_write(
    uint64_t object_no, uint64_t object_off, ceph::bufferlist&& cmp_data,
    ceph::bufferlist&& write_data, IOContext io_context, int op_flags,
    const ZTracer::Trace &parent_trace, uint64_t* mismatch_offset,
    int* object_dispatch_flags, uint64_t* journal_tid,
    io::DispatchResult* dispatch_result, Context** on_finish,
    Context* on_dispatched) {
  if (object_no < m_data_offset_object_no) {
    return false;
  }

  auto cct = m_image_ctx->cct;
  ldout(cct, 20) << data_object_name(m_image_ctx, object_no) << " "
                 << object_off << "~" << write_data.length()
                 << dendl;
  ceph_assert(m_crypto.load(std::memory_order_relaxed) != nullptr);

  bool tracked;
  auto crypto = get_crypto_for_object(object_no, tracked);

  auto* final_on_dispatched = on_dispatched;
  if (tracked) {
    auto* dispatch = this;
    final_on_dispatched = new LambdaContext(
        [on_dispatched, dispatch, object_no](int r) {
          dispatch->complete_io(object_no);
          on_dispatched->complete(r);
        });
  }

  *dispatch_result = io::DISPATCH_RESULT_COMPLETE;
  auto req = new C_UnalignedObjectWriteRequest<I>(
          m_image_ctx, crypto, object_no, object_off, std::move(write_data),
          std::move(cmp_data), mismatch_offset, io_context, op_flags, 0,
          std::nullopt, parent_trace, object_dispatch_flags, journal_tid,
          final_on_dispatched, true);
  req->send();

  return true;
}

template <typename I>
bool CryptoObjectDispatch<I>::discard(
        uint64_t object_no, uint64_t object_off, uint64_t object_len,
        IOContext io_context, int discard_flags,
        const ZTracer::Trace &parent_trace, int* object_dispatch_flags,
        uint64_t* journal_tid, io::DispatchResult* dispatch_result,
        Context** on_finish, Context* on_dispatched) {
  if (object_no < m_data_offset_object_no) {
    return false;
  }

  auto cct = m_image_ctx->cct;
  ldout(cct, 20) << data_object_name(m_image_ctx, object_no) << " "
                 << object_off << "~" << object_len << dendl;
  ceph_assert(m_crypto.load(std::memory_order_relaxed) != nullptr);

  // Do NOT call get_crypto_for_object() here. discard converts to a
  // write_same dispatched through get_previous_layer(CRYPTO), which
  // re-enters write_same() → write(). The final write() call handles
  // dual-key synchronization. Calling get_crypto_for_object here would
  // cause triple bucket increment → deadlock with set_reencrypting_object.

  // convert to write-same
  bufferlist bl;
  const int buffer_size = 4096;
  bl.append_zero(buffer_size);

  *dispatch_result = io::DISPATCH_RESULT_COMPLETE;
  auto req = io::ObjectDispatchSpec::create_write_same(
          m_image_ctx,
          io::util::get_previous_layer(io::OBJECT_DISPATCH_LAYER_CRYPTO),
          object_no, object_off, object_len, {{0, object_len}}, std::move(bl),
          io_context, *object_dispatch_flags, 0, parent_trace,
          on_dispatched);
  req->send();
  return true;
}

template <typename I>
int CryptoObjectDispatch<I>::prepare_copyup(
        uint64_t object_no,
        io::SnapshotSparseBufferlist* snapshot_sparse_bufferlist) {
  if (object_no < m_data_offset_object_no) {
    return 0;
  }

  bool tracked;
  auto crypto = get_crypto_for_object(object_no, tracked);

  // prepare_copyup is synchronous, complete_io on exit if tracked
  auto decrement_guard = make_scope_guard([this, object_no, tracked]() {
    if (tracked) {
      complete_io(object_no);
    }
  });

  ceph::bufferlist current_bl;
  const uint64_t object_size = m_image_ctx->get_object_size();
  current_bl.append_zero(object_size);

  for (auto& [key, extent_map]: *snapshot_sparse_bufferlist) {
    // update current_bl with data from extent_map
    for (auto& extent : extent_map) {
      auto &sbe = extent.get_val();
      if (sbe.state == io::SPARSE_EXTENT_STATE_DATA) {
        current_bl.begin(extent.get_off()).copy_in(extent.get_len(), sbe.bl);
      } else if (sbe.state == io::SPARSE_EXTENT_STATE_ZEROED) {
        ceph::bufferlist zeros;
        zeros.append_zero(extent.get_len());
        current_bl.begin(extent.get_off()).copy_in(extent.get_len(), zeros);
      }
    }

    // encrypt
    io::SparseBufferlist encrypted_sparse_bufferlist;
    const uint64_t meta_size = crypto->get_meta_size();
    const uint64_t block_size = crypto->get_block_size();
    for (auto& extent : extent_map) {
      auto [aligned_off, aligned_len] = crypto->align(
              extent.get_off(), extent.get_len());

      auto [image_extents, _] = io::util::object_to_area_extents(
          m_image_ctx, object_no, {{aligned_off, aligned_len}});

      ceph::bufferlist encrypted_bl;
      uint64_t position = 0;
      for (auto [image_offset, image_length]: image_extents) {
        ceph::bufferlist aligned_bl;
        aligned_bl.substr_of(current_bl, aligned_off + position, image_length);
        aligned_bl.rebuild(); // to deep copy aligned_bl from current_bl
        position += image_length;

        auto r = crypto->encrypt(&aligned_bl, image_offset);
        if (r != 0) {
          return r;
        }

        encrypted_bl.append(aligned_bl);
      }

      if (meta_size != 0) {
        // Split layout: data at logical offsets, meta beyond object_size
        uint64_t num_blocks = aligned_len / block_size;
        uint64_t data_len = num_blocks * block_size;
        uint64_t meta_len = num_blocks * meta_size;
        ceph_assert(encrypted_bl.length() == data_len + meta_len);

        ceph::bufferlist data_bl;
        data_bl.substr_of(encrypted_bl, 0, data_len);
        encrypted_sparse_bufferlist.insert(
          aligned_off, data_len,
          {io::SPARSE_EXTENT_STATE_DATA, data_len, std::move(data_bl)});

        uint64_t start_block = aligned_off / block_size;
        uint64_t meta_off = object_size + start_block * meta_size;
        ceph::bufferlist meta_bl;
        meta_bl.substr_of(encrypted_bl, data_len, meta_len);
        encrypted_sparse_bufferlist.insert(
          meta_off, meta_len,
          {io::SPARSE_EXTENT_STATE_DATA, meta_len, std::move(meta_bl)});
      } else {
        ceph_assert(encrypted_bl.length() == aligned_len);
        encrypted_sparse_bufferlist.insert(aligned_off, aligned_len,
          {io::SPARSE_EXTENT_STATE_DATA, aligned_len,
           std::move(encrypted_bl)});
      }
    }

    // replace original plaintext sparse bufferlist with encrypted one
    extent_map.clear();
    extent_map.insert(std::move(encrypted_sparse_bufferlist));
  }

  return 0;
}

} // namespace crypto
} // namespace librbd

template class librbd::crypto::CryptoObjectDispatch<librbd::ImageCtx>;
