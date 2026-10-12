// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#ifndef CEPH_LIBRBD_CRYPTO_LUKS_HEADER_H
#define CEPH_LIBRBD_CRYPTO_LUKS_HEADER_H

#include <libcryptsetup.h>
#include <vector>
#include "common/ceph_context.h"
#include "include/buffer.h"
#include "include/rbd/librbd.hpp"

namespace librbd {
namespace crypto {
namespace luks {

// libcryptsetup checks the device size against the header: LUKS2's largest
// is two 4 MiB metadata copies plus a 128 MiB keyslot area
const uint64_t ANONYMOUS_FILE_SIZE = 136 * 1024 * 1024;

class Header {
public:
    Header(CephContext* cct);
    ~Header();
    int init();

    int write(const ceph::bufferlist& bl);
    ssize_t read(ceph::bufferlist* bl);
    ssize_t read(ceph::bufferlist* bl, uint64_t offset, uint64_t length);

    int format(const char* type, const char* alg, const char* key,
               size_t key_size, const char* cipher_mode, uint32_t sector_size,
               uint32_t data_alignment, bool insecure_fast_mode);
    int add_keyslot(const char* passphrase, size_t passphrase_size);
    int load(const char* type);
    int read_volume_key(const char* passphrase, size_t passphrase_size,
                        char* volume_key, size_t* volume_key_size);

    int unlock_keyslot(int keyslot, const char* passphrase,
                       size_t passphrase_size, char* volume_key,
                       size_t* volume_key_size);
    int add_keyslot_by_volume_key(int keyslot, const char* volume_key,
                                  size_t volume_key_size,
                                  const char* passphrase,
                                  size_t passphrase_size);
    int set_pbkdf(const struct crypt_pbkdf_type* pbkdf);
    int destroy_keyslot(int keyslot);
    crypt_keyslot_info get_keyslot_status(int keyslot);
    int get_keyslot_max();
    int get_keyslot_key_size(int keyslot);
    int get_keyslot_pbkdf(int keyslot, struct crypt_pbkdf_type* pbkdf);
    int list_keyslots(std::vector<encryption_luks_keyslot_info_t>* keyslots);

    int get_sector_size();
    uint64_t get_data_offset();
    int get_volume_key_size();

    // the anonymous file's path, for libcryptsetup calls that take one
    const std::string& get_path() const { return m_path; }
    int restore(const char* backup_path);
    const char* get_cipher();
    const char* get_cipher_mode();
    const char* get_format_name();

private:
    int extend_to_device_size();
    void libcryptsetup_log(int level, const char* msg);
    static void libcryptsetup_log_wrapper(int level, const char* msg,
                                          void* header);

    CephContext* m_cct;
    int m_fd;
    std::string m_path;
    struct crypt_device *m_cd;
};

} // namespace luks
} // namespace crypto
} // namespace librbd

#endif // CEPH_LIBRBD_CRYPTO_LUKS_HEADER_H
