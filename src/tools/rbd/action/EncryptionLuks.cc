// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

// PoC (option 1.5): cryptsetup's keyslot commands for an RBD image. librbd
// stages the LUKS header and hands out a file descriptor, libcryptsetup
// works on it here, and librbd writes the changed ranges back.

#include "include/compat.h"
#include "tools/rbd/ArgumentTypes.h"
#include "tools/rbd/Shell.h"
#include "tools/rbd/Utils.h"
#include "common/errno.h"
#include <libcryptsetup.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <boost/program_options.hpp>

namespace rbd {
namespace action {
namespace encryption_luks {

namespace at = argument_types;
namespace po = boost::program_options;

namespace {

int read_file(const std::string& path, std::string* content) {
  std::ifstream file(path, std::ios::in | std::ios::binary);
  if (file.fail()) {
    std::cerr << "rbd: unable to open file '" << path << "': "
              << cpp_strerror(errno) << std::endl;
    return -errno;
  }
  content->assign((std::istreambuf_iterator<char>(file)),
                  std::istreambuf_iterator<char>());
  return 0;
}

bool in_use(crypt_keyslot_info status) {
  return status == CRYPT_SLOT_ACTIVE || status == CRYPT_SLOT_ACTIVE_LAST;
}

// An image's LUKS header, staged by librbd and loaded with libcryptsetup.
class StagedHeader {
public:
  ~StagedHeader() {
    if (m_cd != nullptr) {
      crypt_free(m_cd);
    }
    if (m_header != nullptr) {
      m_image.encryption_luks_header_close(m_header);
    }
    if (m_fd != -1) {
      ::close(m_fd);
    }
  }

  int open(const po::variables_map &vm, size_t *arg_index, bool read_only) {
    std::string pool_name;
    std::string namespace_name;
    std::string image_name;
    std::string snap_name;
    int r = utils::get_pool_image_snapshot_names(
      vm, at::ARGUMENT_MODIFIER_NONE, arg_index, &pool_name, &namespace_name,
      &image_name, &snap_name, true, utils::SNAPSHOT_PRESENCE_NONE,
      utils::SPEC_VALIDATION_NONE);
    if (r < 0) {
      return r;
    }

    r = utils::init_and_open_image(pool_name, namespace_name, image_name, "",
                                   "", read_only, &m_rados, &m_io_ctx,
                                   &m_image);
    if (r < 0) {
      return r;
    }

    r = m_image.encryption_luks_header_open(&m_header, &m_fd);
    if (r < 0) {
      std::cerr << "rbd: unable to stage the LUKS header: " << cpp_strerror(r)
                << std::endl;
      return r;
    }

    auto path = "/proc/self/fd/" + std::to_string(m_fd);
    r = crypt_init(&m_cd, path.c_str());
    if (r == 0) {
      r = crypt_load(m_cd, CRYPT_LUKS, nullptr);
    }
    if (r < 0) {
      std::cerr << "rbd: unable to load the LUKS header: " << cpp_strerror(r)
                << std::endl;
    }
    return r;
  }

  // libcryptsetup lets go of the file first, then librbd writes it back
  int commit() {
    crypt_free(m_cd);
    m_cd = nullptr;

    // Keep the exclusive lock while the header is written. Other clients
    // then wait for the release instead of taking the lock between two
    // writes.
    int r = m_image.lock_acquire(RBD_LOCK_MODE_EXCLUSIVE_TRANSIENT);
    bool locked = (r == 0);
    if (r < 0 && r != -EINVAL) {  // -EINVAL: no exclusive-lock feature
      std::cerr << "rbd: unable to take the exclusive lock: "
                << cpp_strerror(r) << std::endl;
      return r;
    }

    r = m_image.encryption_luks_header_commit(m_header);
    if (r < 0) {
      std::cerr << "rbd: unable to write the LUKS header back: "
                << cpp_strerror(r) << std::endl;
    }
    if (locked) {
      int lr = m_image.lock_release();
      if (lr < 0) {
        std::cerr << "rbd: unable to release the exclusive lock: "
                  << cpp_strerror(lr) << std::endl;
      }
    }
    return r;
  }

  struct crypt_device *cd() {
    return m_cd;
  }

private:
  librados::Rados m_rados;
  librados::IoCtx m_io_ctx;
  librbd::Image m_image;
  librbd::encryption_luks_header_t m_header = nullptr;
  int m_fd = -1;
  struct crypt_device *m_cd = nullptr;
};

// The next new keyslot gets the KDF settings of a keyslot in use, the given
// one or the lowest, instead of what a benchmark of this host would pick.
int copy_pbkdf(struct crypt_device *cd, int keyslot) {
  if (keyslot == CRYPT_ANY_SLOT) {
    int max = crypt_keyslot_max(crypt_get_type(cd));
    for (int slot = 0; slot < max; ++slot) {
      if (in_use(crypt_keyslot_status(cd, slot))) {
        keyslot = slot;
        break;
      }
    }
  }
  if (keyslot == CRYPT_ANY_SLOT) {
    std::cerr << "rbd: no keyslot in use to copy the KDF settings from"
              << std::endl;
    return -ENOENT;
  }

  struct crypt_pbkdf_type pbkdf = {};
  int r = crypt_keyslot_get_pbkdf(cd, keyslot, &pbkdf);
  if (r == 0) {
    pbkdf.flags = CRYPT_PBKDF_NO_BENCHMARK;
    r = crypt_set_pbkdf_type(cd, &pbkdf);
  }
  if (r < 0) {
    std::cerr << "rbd: unable to copy the KDF settings of keyslot " << keyslot
              << ": " << cpp_strerror(r) << std::endl;
  }
  return r;
}

int get_key_file(const po::variables_map &vm, std::string *passphrase) {
  if (!vm.count("key-file")) {
    std::cerr << "rbd: must specify --key-file." << std::endl;
    return -EINVAL;
  }
  return read_file(vm["key-file"].as<std::string>(), passphrase);
}

int get_key_slot(const po::variables_map &vm) {
  return vm.count("key-slot") ? vm["key-slot"].as<int>() : CRYPT_ANY_SLOT;
}

void add_key_file_option(po::options_description *options,
                         const char *description) {
  options->add_options()
    ("key-file", po::value<std::string>(), description);
}

} // anonymous namespace

void get_dump_arguments(po::options_description *positional,
                        po::options_description *options) {
  at::add_image_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
}

int execute_dump(const po::variables_map &vm,
                 const std::vector<std::string> &ceph_global_init_args) {
  size_t arg_index = 0;
  StagedHeader header;
  int r = header.open(vm, &arg_index, true);
  if (r < 0) {
    return r;
  }

  return crypt_dump(header.cd());
}

void get_open_arguments(po::options_description *positional,
                        po::options_description *options) {
  at::add_image_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
  add_key_file_option(options, "path of file containing the passphrase");
  options->add_options()
    ("key-slot", po::value<int>(), "keyslot to try [default: all]")
    ("test-passphrase", po::bool_switch(),
     "only check that the passphrase unlocks a keyslot (required)");
}

int execute_open(const po::variables_map &vm,
                 const std::vector<std::string> &ceph_global_init_args) {
  if (!vm["test-passphrase"].as<bool>()) {
    std::cerr << "rbd: only --test-passphrase is supported, use rbd device "
              << "map to open an image." << std::endl;
    return -EINVAL;
  }
  std::string passphrase;
  int r = get_key_file(vm, &passphrase);
  if (r < 0) {
    return r;
  }

  size_t arg_index = 0;
  StagedHeader header;
  r = header.open(vm, &arg_index, true);
  if (r < 0) {
    return r;
  }

  r = crypt_activate_by_passphrase(header.cd(), nullptr, get_key_slot(vm),
                                   passphrase.data(), passphrase.size(), 0);
  if (r < 0) {
    std::cerr << "rbd: no key available with this passphrase: "
              << cpp_strerror(r) << std::endl;
    return r;
  }

  std::cout << "Key slot " << r << " unlocked." << std::endl;
  return 0;
}

void get_add_key_arguments(po::options_description *positional,
                           po::options_description *options) {
  at::add_image_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
  positional->add_options()
    ("new-key-file", "path of file containing the new passphrase");
  add_key_file_option(options,
                      "path of file containing a passphrase in use");
  options->add_options()
    ("key-slot", po::value<int>(),
     "keyslot for the new passphrase [default: first free keyslot]");
}

int execute_add_key(const po::variables_map &vm,
                    const std::vector<std::string> &ceph_global_init_args) {
  std::string passphrase;
  int r = get_key_file(vm, &passphrase);
  if (r < 0) {
    return r;
  }

  size_t arg_index = 0;
  StagedHeader header;
  r = header.open(vm, &arg_index, false);
  if (r < 0) {
    return r;
  }

  std::string new_key_file = utils::get_positional_argument(vm, arg_index++);
  if (new_key_file.empty()) {
    std::cerr << "rbd: must specify new-key-file." << std::endl;
    return -EINVAL;
  }
  std::string new_passphrase;
  r = read_file(new_key_file, &new_passphrase);
  if (r < 0) {
    return r;
  }

  r = copy_pbkdf(header.cd(), CRYPT_ANY_SLOT);
  if (r < 0) {
    return r;
  }
  r = crypt_keyslot_add_by_passphrase(
    header.cd(), get_key_slot(vm), passphrase.data(), passphrase.size(),
    new_passphrase.data(), new_passphrase.size());
  if (r < 0) {
    std::cerr << "rbd: encryption luksAddKey error: " << cpp_strerror(r)
              << std::endl;
    return r;
  }
  int keyslot = r;

  r = header.commit();
  if (r < 0) {
    return r;
  }

  std::cout << "Key slot " << keyslot << " created." << std::endl;
  return 0;
}

void get_change_key_arguments(po::options_description *positional,
                              po::options_description *options) {
  at::add_image_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
  positional->add_options()
    ("new-key-file", "path of file containing the new passphrase");
  add_key_file_option(options,
                      "path of file containing the passphrase to replace");
  options->add_options()
    ("key-slot", po::value<int>(),
     "keyslot to change [default: the one the passphrase unlocks]");
}

int execute_change_key(const po::variables_map &vm,
                       const std::vector<std::string> &ceph_global_init_args) {
  std::string passphrase;
  int r = get_key_file(vm, &passphrase);
  if (r < 0) {
    return r;
  }

  size_t arg_index = 0;
  StagedHeader header;
  r = header.open(vm, &arg_index, false);
  if (r < 0) {
    return r;
  }

  std::string new_key_file = utils::get_positional_argument(vm, arg_index++);
  if (new_key_file.empty()) {
    std::cerr << "rbd: must specify new-key-file." << std::endl;
    return -EINVAL;
  }
  std::string new_passphrase;
  r = read_file(new_key_file, &new_passphrase);
  if (r < 0) {
    return r;
  }

  int keyslot = get_key_slot(vm);
  r = copy_pbkdf(header.cd(), keyslot);
  if (r < 0) {
    return r;
  }
  // libcryptsetup stores the new passphrase in a free keyslot when there
  // is one, then swaps the numbers and removes the old keyslot
  r = crypt_keyslot_change_by_passphrase(
    header.cd(), keyslot, keyslot, passphrase.data(), passphrase.size(),
    new_passphrase.data(), new_passphrase.size());
  if (r < 0) {
    std::cerr << "rbd: encryption luksChangeKey error: " << cpp_strerror(r)
              << std::endl;
    return r;
  }
  keyslot = r;

  r = header.commit();
  if (r < 0) {
    return r;
  }

  std::cout << "Key slot " << keyslot << " changed." << std::endl;
  return 0;
}

void get_kill_slot_arguments(po::options_description *positional,
                             po::options_description *options) {
  at::add_image_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
  positional->add_options()
    ("key-slot", "keyslot to remove");
  add_key_file_option(
    options, "path of file containing a passphrase of another keyslot");
}

int execute_kill_slot(const po::variables_map &vm,
                      const std::vector<std::string> &ceph_global_init_args) {
  std::string passphrase;
  int r = get_key_file(vm, &passphrase);
  if (r < 0) {
    return r;
  }

  size_t arg_index = 0;
  StagedHeader header;
  r = header.open(vm, &arg_index, false);
  if (r < 0) {
    return r;
  }

  std::string keyslot_arg = utils::get_positional_argument(vm, arg_index++);
  int keyslot;
  try {
    keyslot = std::stoi(keyslot_arg);
  } catch (const std::exception&) {
    std::cerr << "rbd: must specify key-slot as a number." << std::endl;
    return -EINVAL;
  }

  auto cd = header.cd();
  switch (crypt_keyslot_status(cd, keyslot)) {
  case CRYPT_SLOT_INVALID:
    std::cerr << "rbd: keyslot " << keyslot << " is invalid." << std::endl;
    return -EINVAL;
  case CRYPT_SLOT_INACTIVE:
    std::cerr << "rbd: keyslot " << keyslot << " is not in use." << std::endl;
    return -ENOENT;
  case CRYPT_SLOT_ACTIVE_LAST:
    std::cerr << "rbd: refusing to remove the last keyslot." << std::endl;
    return -EBUSY;
  default:
    break;
  }

  // as cryptsetup does, the passphrase has to unlock one of the keyslots
  // that stay
  int max = crypt_keyslot_max(crypt_get_type(cd));
  r = -EPERM;
  for (int slot = 0; slot < max && r == -EPERM; ++slot) {
    if (slot != keyslot && in_use(crypt_keyslot_status(cd, slot))) {
      r = crypt_activate_by_passphrase(cd, nullptr, slot, passphrase.data(),
                                       passphrase.size(), 0);
    }
  }
  if (r < 0) {
    std::cerr << "rbd: no remaining keyslot opens with this passphrase: "
              << cpp_strerror(r) << std::endl;
    return r;
  }

  r = crypt_keyslot_destroy(cd, keyslot);
  if (r < 0) {
    std::cerr << "rbd: encryption luksKillSlot error: " << cpp_strerror(r)
              << std::endl;
    return r;
  }

  r = header.commit();
  if (r < 0) {
    return r;
  }

  std::cout << "Key slot " << keyslot << " removed." << std::endl;
  return 0;
}

Shell::Action action_dump(
  {"encryption", "luksDump"}, {},
  "Print the LUKS header of an image.", "",
  &get_dump_arguments, &execute_dump);
Shell::Action action_open(
  {"encryption", "luksOpen"}, {},
  "Check a passphrase against the LUKS header of an image.", "",
  &get_open_arguments, &execute_open);
Shell::Action action_add_key(
  {"encryption", "luksAddKey"}, {},
  "Add a passphrase to a LUKS image.", "",
  &get_add_key_arguments, &execute_add_key);
Shell::Action action_change_key(
  {"encryption", "luksChangeKey"}, {},
  "Replace a passphrase of a LUKS image.", "",
  &get_change_key_arguments, &execute_change_key);
Shell::Action action_kill_slot(
  {"encryption", "luksKillSlot"}, {},
  "Remove a keyslot of a LUKS image.", "",
  &get_kill_slot_arguments, &execute_kill_slot);

} // namespace encryption_luks
} // namespace action
} // namespace rbd
