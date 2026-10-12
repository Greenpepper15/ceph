// -*- mode:C++; tab-width:8; c-basic-offset:2; indent-tabs-mode:nil -*-
// vim: ts=8 sw=2 sts=2 expandtab

#include "include/compat.h"
#include "include/scope_guard.h"
#include "include/stringify.h"
#include "include/types.h" // for byte_u_t
#include "tools/rbd/ArgumentTypes.h"
#include "tools/rbd/Shell.h"
#include "tools/rbd/Utils.h"
#include "common/errno.h"
#include "common/Formatter.h"
#include "common/safe_io.h"
#include "common/TextTable.h"
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fstream>
#include <iostream>
#include <boost/program_options.hpp>

namespace rbd {
namespace action {
namespace encryption {

namespace at = argument_types;
namespace po = boost::program_options;

namespace {

// reads a passphrase, a volume key or a header dump
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

// writes a volume key or a header dump, readable by its owner only: an
// existing file is truncated and gets that mode too, a symlink is refused
int write_private_file(const std::string& path, const std::string& content) {
  int fd = ::open(path.c_str(),
                  O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
  int r;
  if (fd < 0) {
    r = -errno;
  } else {
    r = ::fchmod(fd, 0600) < 0 ? -errno : 0;
    if (r == 0) {
      r = safe_write(fd, content.data(), content.size());
    }
    if (r == 0) {
      r = ::close(fd) < 0 ? -errno : 0;
    } else {
      ::close(fd);
    }
  }
  if (r < 0) {
    std::cerr << "rbd: unable to write file '" << path << "': "
              << cpp_strerror(r) << std::endl;
  }
  return r;
}

} // anonymous namespace

void get_arguments(po::options_description *positional,
                   po::options_description *options) {
  at::add_image_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
  positional->add_options()
    ("format", "encryption format [possible values: luks1, luks2]")
    ("passphrase-file",
      "path of file containing passphrase for unlocking the image");
  options->add_options()
    ("cipher-alg", po::value<at::EncryptionAlgorithm>(),
     "encryption algorithm [possible values: aes-128, aes-256 (default)]");
}

int execute(const po::variables_map &vm,
            const std::vector<std::string> &ceph_global_init_args) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string namespace_name;
  std::string image_name;
  std::string snap_name;
  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_NONE, &arg_index, &pool_name, &namespace_name,
    &image_name, &snap_name, true, utils::SNAPSHOT_PRESENCE_NONE,
    utils::SPEC_VALIDATION_NONE);
  if (r < 0) {
    return r;
  }

  std::string format_str = utils::get_positional_argument(vm, arg_index++);
  if (format_str.empty()) {
    std::cerr << "rbd: must specify format." << std::endl;
    return -EINVAL;
  }

  std::string passphrase_file =
          utils::get_positional_argument(vm, arg_index++);
  if (passphrase_file.empty()) {
    std::cerr << "rbd: must specify passphrase-file." << std::endl;
    return -EINVAL;
  }

  auto alg = RBD_ENCRYPTION_ALGORITHM_AES256;
  if (vm.count("cipher-alg")) {
    alg = vm["cipher-alg"].as<librbd::encryption_algorithm_t>();
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;
  librbd::Image image;
  r = utils::init_and_open_image(pool_name, namespace_name, image_name, "", "",
                                 false, &rados, &io_ctx, &image);
  if (r < 0) {
    return r;
  }

  std::string passphrase;
  r = read_file(passphrase_file, &passphrase);
  if (r < 0) {
    return r;
  }

  if (format_str == "luks1") {
    librbd::encryption_luks1_format_options_t opts = {
        alg, std::move(passphrase)};
    r = image.encryption_format(
            RBD_ENCRYPTION_FORMAT_LUKS1, &opts, sizeof(opts));
    ceph_memzero_s(opts.passphrase.data(), opts.passphrase.size(),
                   opts.passphrase.size());
  } else if (format_str == "luks2") {
    librbd::encryption_luks2_format_options_t opts = {
        alg, std::move(passphrase)};
    r = image.encryption_format(
            RBD_ENCRYPTION_FORMAT_LUKS2, &opts, sizeof(opts));
    ceph_memzero_s(opts.passphrase.data(), opts.passphrase.size(),
                   opts.passphrase.size());
  } else {
    std::cerr << "rbd: unsupported encryption format" << std::endl;
    return -ENOTSUP;
  }

  if (r < 0) {
    std::cerr << "rbd: encryption format error: " << cpp_strerror(r)
              << std::endl;
  }
  return r;
}

Shell::Action action(
  {"encryption", "format"}, {}, "Format image to an encrypted format.", "",
  &get_arguments, &execute);

void get_keyslot_add_arguments(po::options_description *positional,
                               po::options_description *options) {
  at::add_image_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
  positional->add_options()
    ("volume-key-file",
     "path of file containing the volume key, as written by volume-key get")
    ("passphrase-file",
     "path of file containing the passphrase for the new keyslot");
  options->add_options()
    ("keyslot", po::value<int>(),
     "LUKS keyslot to add [default: first free keyslot]")
    ("pbkdf", po::value<std::string>(),
     "key derivation function: pbkdf2, argon2i or argon2id "
     "[default: the settings of the lowest keyslot in use]")
    ("hash", po::value<std::string>(), "hash for pbkdf2")
    ("pbkdf-force-iterations", po::value<uint32_t>(),
     "iterations, the time cost for argon2")
    ("pbkdf-memory", po::value<uint32_t>(), "argon2 memory cost in KiB")
    ("pbkdf-parallel", po::value<uint32_t>(), "argon2 threads");
}

int execute_keyslot_add(const po::variables_map &vm,
                        const std::vector<std::string> &ceph_global_init_args) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string namespace_name;
  std::string image_name;
  std::string snap_name;
  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_NONE, &arg_index, &pool_name, &namespace_name,
    &image_name, &snap_name, true, utils::SNAPSHOT_PRESENCE_NONE,
    utils::SPEC_VALIDATION_NONE);
  if (r < 0) {
    return r;
  }

  std::string volume_key_file =
          utils::get_positional_argument(vm, arg_index++);
  if (volume_key_file.empty()) {
    std::cerr << "rbd: must specify volume-key-file." << std::endl;
    return -EINVAL;
  }

  std::string passphrase_file =
          utils::get_positional_argument(vm, arg_index++);
  if (passphrase_file.empty()) {
    std::cerr << "rbd: must specify passphrase-file." << std::endl;
    return -EINVAL;
  }

  int keyslot = RBD_ENCRYPTION_LUKS_ANY_KEYSLOT;
  if (vm.count("keyslot")) {
    keyslot = vm["keyslot"].as<int>();
  }

  std::string volume_key;
  std::string passphrase;
  r = read_file(volume_key_file, &volume_key);
  if (r < 0) {
    return r;
  }
  r = read_file(passphrase_file, &passphrase);
  if (r < 0) {
    return r;
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;
  librbd::Image image;
  r = utils::init_and_open_image(pool_name, namespace_name, image_name, "", "",
                                 false, &rados, &io_ctx, &image);
  if (r < 0) {
    return r;
  }

  librbd::encryption_luks_keyslot_add_options_t opts = {
      keyslot, std::move(volume_key), std::move(passphrase)};
  if (vm.count("pbkdf")) {
    opts.kdf = vm["pbkdf"].as<std::string>();
  }
  if (vm.count("hash")) {
    opts.hash = vm["hash"].as<std::string>();
  }
  if (vm.count("pbkdf-force-iterations")) {
    opts.kdf_iterations = vm["pbkdf-force-iterations"].as<uint32_t>();
  }
  if (vm.count("pbkdf-memory")) {
    opts.kdf_memory_kb = vm["pbkdf-memory"].as<uint32_t>();
  }
  if (vm.count("pbkdf-parallel")) {
    opts.kdf_threads = vm["pbkdf-parallel"].as<uint32_t>();
  }
  r = image.encryption_luks_keyslot_add(&opts, sizeof(opts));
  ceph_memzero_s(opts.volume_key.data(), opts.volume_key.size(),
                 opts.volume_key.size());
  ceph_memzero_s(opts.passphrase.data(), opts.passphrase.size(),
                 opts.passphrase.size());
  if (r < 0) {
    std::cerr << "rbd: encryption keyslot add error: " << cpp_strerror(r)
              << std::endl;
    return r;
  }

  std::cout << "added keyslot " << r << std::endl;
  return 0;
}

Shell::Action action_keyslot_add(
  {"encryption", "keyslot", "add"}, {},
  "Add a LUKS keyslot that stores the volume key under a passphrase.", "",
  &get_keyslot_add_arguments, &execute_keyslot_add);

void get_keyslot_remove_arguments(po::options_description *positional,
                                  po::options_description *options) {
  at::add_image_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
  options->add_options()
    ("keyslot", po::value<int>(), "LUKS keyslot to remove (required)");
}

int execute_keyslot_remove(
    const po::variables_map &vm,
    const std::vector<std::string> &ceph_global_init_args) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string namespace_name;
  std::string image_name;
  std::string snap_name;
  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_NONE, &arg_index, &pool_name, &namespace_name,
    &image_name, &snap_name, true, utils::SNAPSHOT_PRESENCE_NONE,
    utils::SPEC_VALIDATION_NONE);
  if (r < 0) {
    return r;
  }

  if (!vm.count("keyslot")) {
    std::cerr << "rbd: must specify --keyslot." << std::endl;
    return -EINVAL;
  }
  int keyslot = vm["keyslot"].as<int>();

  librados::Rados rados;
  librados::IoCtx io_ctx;
  librbd::Image image;
  r = utils::init_and_open_image(pool_name, namespace_name, image_name, "", "",
                                 false, &rados, &io_ctx, &image);
  if (r < 0) {
    return r;
  }

  librbd::encryption_luks_keyslot_remove_options_t opts = {keyslot};
  r = image.encryption_luks_keyslot_remove(&opts, sizeof(opts));
  if (r < 0) {
    std::cerr << "rbd: encryption keyslot remove error: " << cpp_strerror(r)
              << std::endl;
    return r;
  }

  return 0;
}

Shell::Action action_keyslot_remove(
  {"encryption", "keyslot", "remove"},
  {"encryption", "keyslot", "rm"}, "Remove a LUKS keyslot.", "",
  &get_keyslot_remove_arguments, &execute_keyslot_remove);

void get_keyslot_list_arguments(po::options_description *positional,
                                po::options_description *options) {
  at::add_image_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
  at::add_format_options(options);
}

int execute_keyslot_list(const po::variables_map &vm,
                         const std::vector<std::string> &ceph_global_init_args) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string namespace_name;
  std::string image_name;
  std::string snap_name;
  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_NONE, &arg_index, &pool_name, &namespace_name,
    &image_name, &snap_name, true, utils::SNAPSHOT_PRESENCE_NONE,
    utils::SPEC_VALIDATION_NONE);
  if (r < 0) {
    return r;
  }

  at::Format::Formatter formatter;
  r = utils::get_formatter(vm, &formatter);
  if (r < 0) {
    return r;
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;
  librbd::Image image;
  r = utils::init_and_open_image(pool_name, namespace_name, image_name, "", "",
                                 true, &rados, &io_ctx, &image);
  if (r < 0) {
    return r;
  }

  std::vector<librbd::encryption_luks_keyslot_info_t> keyslots;
  r = image.encryption_luks_keyslot_list(
      &keyslots, sizeof(librbd::encryption_luks_keyslot_info_t));
  if (r < 0) {
    std::cerr << "rbd: encryption keyslot list error: " << cpp_strerror(r)
              << std::endl;
    return r;
  }

  ceph::Formatter *f = formatter.get();
  if (f) {
    f->open_array_section("keyslots");
    for (auto& k : keyslots) {
      f->open_object_section("keyslot");
      f->dump_int("keyslot", k.keyslot);
      f->dump_bool("last", k.last);
      f->dump_unsigned("key_size", k.key_size);
      f->dump_string("kdf", k.kdf);
      f->dump_string("hash", k.hash);
      f->dump_unsigned("kdf_iterations", k.kdf_iterations);
      f->dump_unsigned("kdf_memory_kb", k.kdf_memory_kb);
      f->dump_unsigned("kdf_threads", k.kdf_threads);
      f->close_section();
    }
    f->close_section();
    f->flush(std::cout);
    return 0;
  }

  TextTable t;
  t.define_column("KEYSLOT", TextTable::LEFT, TextTable::RIGHT);
  t.define_column("LAST", TextTable::LEFT, TextTable::LEFT);
  t.define_column("KEY SIZE", TextTable::LEFT, TextTable::RIGHT);
  t.define_column("KDF", TextTable::LEFT, TextTable::LEFT);
  t.define_column("HASH", TextTable::LEFT, TextTable::LEFT);
  t.define_column("ITERATIONS", TextTable::LEFT, TextTable::RIGHT);
  t.define_column("MEMORY", TextTable::LEFT, TextTable::RIGHT);
  t.define_column("THREADS", TextTable::LEFT, TextTable::RIGHT);
  for (auto& k : keyslots) {
    // pbkdf2 has no memory or thread cost, so those stay empty for it
    t << k.keyslot << (k.last ? "yes" : "")
      << stringify(byte_u_t(k.key_size)) << k.kdf << k.hash
      << k.kdf_iterations
      << (k.kdf_memory_kb != 0 ?
            stringify(byte_u_t(uint64_t{k.kdf_memory_kb} << 10)) : "")
      << (k.kdf_threads != 0 ? stringify(k.kdf_threads) : "")
      << TextTable::endrow;
  }
  std::cout << t;
  return 0;
}

Shell::Action action_keyslot_list(
  {"encryption", "keyslot", "list"},
  {"encryption", "keyslot", "ls"}, "List the LUKS keyslots in use.", "",
  &get_keyslot_list_arguments, &execute_keyslot_list);

void get_volume_key_get_arguments(po::options_description *positional,
                                  po::options_description *options) {
  at::add_image_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
  positional->add_options()
    ("passphrase-file",
     "path of file containing a passphrase that unlocks the image")
    ("volume-key-file",
     "path of the file to write the volume key to, readable by its owner "
     "only");
}

int execute_volume_key_get(
    const po::variables_map &vm,
    const std::vector<std::string> &ceph_global_init_args) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string namespace_name;
  std::string image_name;
  std::string snap_name;
  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_NONE, &arg_index, &pool_name, &namespace_name,
    &image_name, &snap_name, true, utils::SNAPSHOT_PRESENCE_NONE,
    utils::SPEC_VALIDATION_NONE);
  if (r < 0) {
    return r;
  }

  std::string passphrase_file =
          utils::get_positional_argument(vm, arg_index++);
  if (passphrase_file.empty()) {
    std::cerr << "rbd: must specify passphrase-file." << std::endl;
    return -EINVAL;
  }

  std::string volume_key_file =
          utils::get_positional_argument(vm, arg_index++);
  if (volume_key_file.empty()) {
    std::cerr << "rbd: must specify volume-key-file." << std::endl;
    return -EINVAL;
  }

  std::string passphrase;
  r = read_file(passphrase_file, &passphrase);
  if (r < 0) {
    return r;
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;
  librbd::Image image;
  r = utils::init_and_open_image(pool_name, namespace_name, image_name, "", "",
                                 true, &rados, &io_ctx, &image);
  if (r < 0) {
    return r;
  }

  librbd::encryption_luks_volume_key_get_options_t opts = {
      std::move(passphrase)};
  std::string volume_key;
  int keyslot = -1;
  r = image.encryption_luks_volume_key_get(&opts, sizeof(opts), &volume_key,
                                           &keyslot);
  ceph_memzero_s(opts.passphrase.data(), opts.passphrase.size(),
                 opts.passphrase.size());
  if (r < 0) {
    std::cerr << "rbd: encryption volume-key get error: " << cpp_strerror(r)
              << std::endl;
    return r;
  }

  // the key opens the image without a passphrase
  r = write_private_file(volume_key_file, volume_key);
  ceph_memzero_s(volume_key.data(), volume_key.size(), volume_key.size());
  if (r < 0) {
    return r;
  }

  std::cout << "unlocked keyslot " << keyslot << std::endl;
  return 0;
}

Shell::Action action_volume_key_get(
  {"encryption", "volume-key", "get"}, {},
  "Write the volume key of a LUKS image to a file.", "",
  &get_volume_key_get_arguments, &execute_volume_key_get);

void get_header_dump_arguments(po::options_description *positional,
                               po::options_description *options) {
  at::add_image_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
  positional->add_options()
    ("dump-file",
     "path of the file to write the LUKS header to, readable by its owner "
     "only");
}

int execute_header_dump(const po::variables_map &vm,
                        const std::vector<std::string> &ceph_global_init_args) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string namespace_name;
  std::string image_name;
  std::string snap_name;
  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_NONE, &arg_index, &pool_name, &namespace_name,
    &image_name, &snap_name, true, utils::SNAPSHOT_PRESENCE_NONE,
    utils::SPEC_VALIDATION_NONE);
  if (r < 0) {
    return r;
  }

  std::string dump_file = utils::get_positional_argument(vm, arg_index++);
  if (dump_file.empty()) {
    std::cerr << "rbd: must specify dump-file." << std::endl;
    return -EINVAL;
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;
  librbd::Image image;
  r = utils::init_and_open_image(pool_name, namespace_name, image_name, "", "",
                                 true, &rados, &io_ctx, &image);
  if (r < 0) {
    return r;
  }

  std::string dump;
  r = image.encryption_luks_header_dump(&dump);
  if (r < 0) {
    std::cerr << "rbd: encryption header dump error: " << cpp_strerror(r)
              << std::endl;
    return r;
  }

  // the dump holds every keyslot
  return write_private_file(dump_file, dump);
}

Shell::Action action_header_dump(
  {"encryption", "header", "dump"}, {},
  "Write the LUKS header of an image to a file.", "",
  &get_header_dump_arguments, &execute_header_dump);

void get_header_restore_arguments(po::options_description *positional,
                                  po::options_description *options) {
  at::add_image_spec_options(positional, options, at::ARGUMENT_MODIFIER_NONE);
  positional->add_options()
    ("dump-file", "path of the file written by encryption header dump");
}

int execute_header_restore(
    const po::variables_map &vm,
    const std::vector<std::string> &ceph_global_init_args) {
  size_t arg_index = 0;
  std::string pool_name;
  std::string namespace_name;
  std::string image_name;
  std::string snap_name;
  int r = utils::get_pool_image_snapshot_names(
    vm, at::ARGUMENT_MODIFIER_NONE, &arg_index, &pool_name, &namespace_name,
    &image_name, &snap_name, true, utils::SNAPSHOT_PRESENCE_NONE,
    utils::SPEC_VALIDATION_NONE);
  if (r < 0) {
    return r;
  }

  std::string dump_file = utils::get_positional_argument(vm, arg_index++);
  if (dump_file.empty()) {
    std::cerr << "rbd: must specify dump-file." << std::endl;
    return -EINVAL;
  }

  std::string dump;
  r = read_file(dump_file, &dump);
  if (r < 0) {
    return r;
  }

  librados::Rados rados;
  librados::IoCtx io_ctx;
  librbd::Image image;
  r = utils::init_and_open_image(pool_name, namespace_name, image_name, "", "",
                                 false, &rados, &io_ctx, &image);
  if (r < 0) {
    return r;
  }

  r = image.encryption_luks_header_restore(dump);
  if (r < 0) {
    std::cerr << "rbd: encryption header restore error: " << cpp_strerror(r)
              << std::endl;
    return r;
  }

  return 0;
}

Shell::Action action_header_restore(
  {"encryption", "header", "restore"}, {},
  "Write a LUKS header dump back to an image.", "",
  &get_header_restore_arguments, &execute_header_restore);

} // namespace encryption
} // namespace action
} // namespace rbd
