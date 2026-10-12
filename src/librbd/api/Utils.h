// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#ifndef CEPH_LIBRBD_API_UTILS_H
#define CEPH_LIBRBD_API_UTILS_H

#include "include/Context.h"
#include "include/rbd/librbd.hpp"
#include "librbd/ImageCtx.h"
#include "librbd/crypto/EncryptionFormat.h"
#include <vector>

namespace librbd {

struct ImageCtx;

namespace api {
namespace util {

template <typename ImageCtxT = librbd::ImageCtx>
int create_encryption_format(
        CephContext* cct, encryption_format_t format,
        encryption_options_t opts, size_t opts_size, bool c_api,
        crypto::EncryptionFormat<ImageCtxT>** result_format);

template <typename ImageCtxT = librbd::ImageCtx>
void luks_volume_key_get(ImageCtxT* ictx, const void* opts, size_t opts_size,
                         bool c_api, size_t max_size, std::string* volume_key,
                         size_t* key_size, int* keyslot, Context* on_finish);
template <typename ImageCtxT = librbd::ImageCtx>
void luks_keyslot_add(ImageCtxT* ictx, const void* opts, size_t opts_size,
                      bool c_api, int* result_keyslot, Context* on_finish);
template <typename ImageCtxT = librbd::ImageCtx>
void luks_keyslot_remove(ImageCtxT* ictx, const void* opts, size_t opts_size,
                         bool c_api, Context* on_finish);
template <typename ImageCtxT = librbd::ImageCtx>
void luks_keyslot_list(
    ImageCtxT* ictx, std::vector<encryption_luks_keyslot_info_t>* keyslots,
    Context* on_finish);
template <typename ImageCtxT = librbd::ImageCtx>
void luks_header_dump(ImageCtxT* ictx, size_t max_size, std::string* dump,
                      size_t* dump_size, Context* on_finish);
template <typename ImageCtxT = librbd::ImageCtx>
void luks_header_restore(ImageCtxT* ictx, std::string_view dump,
                         Context* on_finish);

} // namespace util
} // namespace api
} // namespace librbd

#endif // CEPH_LIBRBD_API_UTILS_H
