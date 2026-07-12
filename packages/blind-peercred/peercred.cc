#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <node_api.h>
#include <limits.h>
#include <fcntl.h>
#include <sys/file.h>

#if defined(__linux__)
#include <sys/syscall.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>
#else
#error "blind-peercred supports Linux, macOS, and BSD Unix sockets only"
#endif

#if defined(__linux__) && !defined(RENAME_NOREPLACE)
#define RENAME_NOREPLACE (1 << 0)
#endif

static napi_value throw_errno(napi_env env, const char *operation) {
  napi_value message;
  char buffer[256];
  snprintf(buffer, sizeof(buffer), "%s: %s", operation, strerror(errno));
  napi_create_string_utf8(env, buffer, NAPI_AUTO_LENGTH, &message);
  napi_throw_error(env, "BLIND_PEERCRED_FAILED", buffer);
  return nullptr;
}

static bool set_int64(napi_env env, napi_value object, const char *name, int64_t value) {
  napi_value key;
  napi_value encoded;
  return napi_create_string_utf8(env, name, NAPI_AUTO_LENGTH, &key) == napi_ok &&
    napi_create_int64(env, value, &encoded) == napi_ok &&
    napi_set_property(env, object, key, encoded) == napi_ok;
}

static bool get_fd(napi_env env, napi_callback_info info, const char *operation, int32_t *fd) {
  size_t argc = 1;
  napi_value argv[1];
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok || argc != 1) {
    napi_throw_type_error(env, "BLIND_NATIVE_ARGUMENT", operation);
    return false;
  }
  *fd = -1;
  if (napi_get_value_int32(env, argv[0], fd) != napi_ok || *fd < 0) {
    napi_throw_type_error(env, "BLIND_NATIVE_ARGUMENT", "file descriptor must be a non-negative int32");
    return false;
  }
  return true;
}

static bool get_path(napi_env env, napi_value value, const char *field, char *output, size_t capacity) {
  napi_valuetype type;
  if (napi_typeof(env, value, &type) != napi_ok || type != napi_string) {
    napi_throw_type_error(env, "BLIND_NATIVE_ARGUMENT", field);
    return false;
  }
  size_t length = 0;
  if (napi_get_value_string_utf8(env, value, nullptr, 0, &length) != napi_ok ||
      length == 0 || length + 1 > capacity) {
    napi_throw_range_error(env, "BLIND_NATIVE_ARGUMENT", "path is empty or exceeds PATH_MAX");
    return false;
  }
  size_t copied = 0;
  if (napi_get_value_string_utf8(env, value, output, capacity, &copied) != napi_ok || copied != length) {
    napi_throw_type_error(env, "BLIND_NATIVE_ARGUMENT", "path could not be encoded as UTF-8");
    return false;
  }
  output[copied] = '\0';
  return true;
}

static napi_value rename_file_no_replace(napi_env env, napi_callback_info info) {
  size_t argc = 2;
  napi_value argv[2];
  if (napi_get_cb_info(env, info, &argc, argv, nullptr, nullptr) != napi_ok || argc != 2) {
    napi_throw_type_error(env, "BLIND_NATIVE_ARGUMENT", "renameFileNoReplace requires source and destination paths");
    return nullptr;
  }
  char source[PATH_MAX];
  char destination[PATH_MAX];
  if (!get_path(env, argv[0], "source path must be a string", source, sizeof(source)) ||
      !get_path(env, argv[1], "destination path must be a string", destination, sizeof(destination))) {
    return nullptr;
  }

  int result = -1;
#if defined(__APPLE__)
  result = renamex_np(source, destination, RENAME_EXCL);
#elif defined(__linux__)
#if defined(SYS_renameat2)
  result = static_cast<int>(syscall(SYS_renameat2, AT_FDCWD, source,
    AT_FDCWD, destination, RENAME_NOREPLACE));
#else
  errno = ENOTSUP;
#endif
#else
  errno = ENOTSUP;
#endif
  bool installed = false;
  if (result == 0) {
    installed = true;
  } else if (errno != EEXIST) {
    return throw_errno(env, "rename no-replace");
  }
  napi_value encoded;
  if (napi_get_boolean(env, installed, &encoded) != napi_ok) {
    napi_throw_error(env, "BLIND_RENAME_NOREPLACE_RESULT", "failed to encode no-replace rename result");
    return nullptr;
  }
  return encoded;
}

static napi_value rename_file_no_replace_platform_supported(napi_env env, napi_callback_info info) {
  size_t argc = 0;
  if (napi_get_cb_info(env, info, &argc, nullptr, nullptr, nullptr) != napi_ok || argc != 0) {
    napi_throw_type_error(env, "BLIND_NATIVE_ARGUMENT", "renameFileNoReplacePlatformSupported takes no arguments");
    return nullptr;
  }
  bool supported = false;
#if defined(__APPLE__)
  supported = true;
#elif defined(__linux__) && defined(SYS_renameat2)
  supported = true;
#endif
  napi_value encoded;
  if (napi_get_boolean(env, supported, &encoded) != napi_ok) {
    napi_throw_error(env, "BLIND_RENAME_NOREPLACE_RESULT", "failed to encode no-replace platform support");
    return nullptr;
  }
  return encoded;
}

static napi_value get_peer_credentials(napi_env env, napi_callback_info info) {
  int32_t fd = -1;
  if (!get_fd(env, info, "getPeerCredentials requires one file descriptor", &fd)) return nullptr;

  int64_t pid = -1;
  int64_t uid = -1;
  int64_t gid = -1;
#if defined(__linux__)
  struct ucred credentials;
  socklen_t length = sizeof(credentials);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERCRED, &credentials, &length) != 0 || length != sizeof(credentials)) {
    return throw_errno(env, "getsockopt(SO_PEERCRED)");
  }
  pid = credentials.pid;
  uid = credentials.uid;
  gid = credentials.gid;
#else
  uid_t peer_uid;
  gid_t peer_gid;
  if (getpeereid(fd, &peer_uid, &peer_gid) != 0) return throw_errno(env, "getpeereid");
  uid = peer_uid;
  gid = peer_gid;
#endif

  napi_value result;
  if (napi_create_object(env, &result) != napi_ok ||
      !set_int64(env, result, "pid", pid) ||
      !set_int64(env, result, "uid", uid) ||
      !set_int64(env, result, "gid", gid)) {
    napi_throw_error(env, "BLIND_PEERCRED_RESULT", "failed to create peer credential result");
    return nullptr;
  }
  return result;
}

static napi_value try_exclusive_file_lock(napi_env env, napi_callback_info info) {
  int32_t fd = -1;
  if (!get_fd(env, info, "tryExclusiveFileLock requires one file descriptor", &fd)) return nullptr;
  bool acquired = false;
  if (flock(fd, LOCK_EX | LOCK_NB) == 0) {
    acquired = true;
  } else if (errno != EWOULDBLOCK && errno != EAGAIN) {
    return throw_errno(env, "flock(LOCK_EX|LOCK_NB)");
  }
  napi_value result;
  if (napi_get_boolean(env, acquired, &result) != napi_ok) {
    napi_throw_error(env, "BLIND_FILE_LOCK_RESULT", "failed to create file-lock result");
    return nullptr;
  }
  return result;
}

static napi_value release_exclusive_file_lock(napi_env env, napi_callback_info info) {
  int32_t fd = -1;
  if (!get_fd(env, info, "releaseExclusiveFileLock requires one file descriptor", &fd)) return nullptr;
  if (flock(fd, LOCK_UN) != 0) return throw_errno(env, "flock(LOCK_UN)");
  napi_value result;
  if (napi_get_undefined(env, &result) != napi_ok) {
    napi_throw_error(env, "BLIND_FILE_LOCK_RESULT", "failed to create file-unlock result");
    return nullptr;
  }
  return result;
}

static napi_value initialize(napi_env env, napi_value exports) {
  napi_value function;
  if (napi_create_function(env, "getPeerCredentials", NAPI_AUTO_LENGTH,
      get_peer_credentials, nullptr, &function) != napi_ok ||
      napi_set_named_property(env, exports, "getPeerCredentials", function) != napi_ok) {
    napi_throw_error(env, "BLIND_PEERCRED_INIT", "failed to initialize peer credential binding");
    return nullptr;
  }
  if (napi_create_function(env, "tryExclusiveFileLock", NAPI_AUTO_LENGTH,
      try_exclusive_file_lock, nullptr, &function) != napi_ok ||
      napi_set_named_property(env, exports, "tryExclusiveFileLock", function) != napi_ok ||
      napi_create_function(env, "releaseExclusiveFileLock", NAPI_AUTO_LENGTH,
      release_exclusive_file_lock, nullptr, &function) != napi_ok ||
      napi_set_named_property(env, exports, "releaseExclusiveFileLock", function) != napi_ok) {
    napi_throw_error(env, "BLIND_FILE_LOCK_INIT", "failed to initialize file-lock binding");
    return nullptr;
  }
  if (napi_create_function(env, "renameFileNoReplace", NAPI_AUTO_LENGTH,
      rename_file_no_replace, nullptr, &function) != napi_ok ||
      napi_set_named_property(env, exports, "renameFileNoReplace", function) != napi_ok) {
    napi_throw_error(env, "BLIND_RENAME_NOREPLACE_INIT", "failed to initialize no-replace rename binding");
    return nullptr;
  }
  if (napi_create_function(env, "renameFileNoReplacePlatformSupported", NAPI_AUTO_LENGTH,
      rename_file_no_replace_platform_supported, nullptr, &function) != napi_ok ||
      napi_set_named_property(env, exports, "renameFileNoReplacePlatformSupported", function) != napi_ok) {
    napi_throw_error(env, "BLIND_RENAME_NOREPLACE_INIT", "failed to initialize no-replace platform-support binding");
    return nullptr;
  }
  return exports;
}

NAPI_MODULE(NODE_GYP_MODULE_NAME, initialize)
