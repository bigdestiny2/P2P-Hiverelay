#define _GNU_SOURCE

#include <stdio.h>

#ifndef __linux__

int
main (void)
{
  fputs("pidfd-unavailable\n", stderr);
  return 77;
}

#else

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#ifndef SYS_pidfd_open
#error "pidfd_open syscall number is unavailable"
#endif

#ifndef SYS_pidfd_send_signal
#error "pidfd_send_signal syscall number is unavailable"
#endif

#define EXPECTED_UNIT "hiverelay.service"
#define SYSTEMCTL "/usr/bin/systemctl"
#define SHA256SUM "/usr/bin/sha256sum"
#define OUTPUT_MAX 4096

struct target {
  pid_t pid;
  unsigned long long starttime;
  char executable_sha256[65];
  char cgroup_sha256[65];
  int term_grace_ms;
  int kill_allowed;
};

static int
lower_sha256 (const char *value)
{
  size_t i;
  if (value == NULL || strlen(value) != 64) return 0;
  for (i = 0; i < 64; i++) {
    if (!isdigit((unsigned char) value[i]) &&
        !(value[i] >= 'a' && value[i] <= 'f')) return 0;
  }
  return 1;
}

static int
parse_u64 (const char *value, unsigned long long min,
           unsigned long long max, unsigned long long *output)
{
  char *end = NULL;
  unsigned long long parsed;
  if (value == NULL || *value == '\0' || *value == '+' ||
      isspace((unsigned char) *value)) return -1;
  errno = 0;
  parsed = strtoull(value, &end, 10);
  if (errno != 0 || end == value || *end != '\0' || parsed < min || parsed > max) return -1;
  *output = parsed;
  return 0;
}

static int
read_child_output (const char *program, char *const argv[], char *output, size_t capacity)
{
  int pipefd[2] = { -1, -1 };
  pid_t child;
  size_t used = 0;
  int status = 0;
  int result = -1;

  if (capacity < 2 || pipe2(pipefd, O_CLOEXEC) != 0) return -1;
  child = fork();
  if (child < 0) goto done;
  if (child == 0) {
    if (dup2(pipefd[1], STDOUT_FILENO) < 0) _exit(126);
    if (dup2(pipefd[1], STDERR_FILENO) < 0) _exit(126);
    close(pipefd[0]);
    close(pipefd[1]);
    clearenv();
    setenv("LANG", "C", 1);
    setenv("LC_ALL", "C", 1);
    setenv("PATH", "/usr/sbin:/usr/bin:/sbin:/bin", 1);
    execv(program, argv);
    _exit(127);
  }
  close(pipefd[1]);
  pipefd[1] = -1;
  while (used < capacity - 1) {
    ssize_t count = read(pipefd[0], output + used, capacity - 1 - used);
    if (count > 0) {
      used += (size_t) count;
      continue;
    }
    if (count == 0) break;
    if (errno == EINTR) continue;
    goto wait;
  }
  {
    char extra;
    ssize_t count = read(pipefd[0], &extra, 1);
    if (count > 0) goto wait;
    if (count < 0 && errno != EINTR) goto wait;
  }
  output[used] = '\0';

wait:
  while (waitpid(child, &status, 0) < 0) {
    if (errno != EINTR) goto done;
  }
  if (WIFEXITED(status) && WEXITSTATUS(status) == 0 && output[used] == '\0') result = 0;

done:
  if (pipefd[0] >= 0) close(pipefd[0]);
  if (pipefd[1] >= 0) close(pipefd[1]);
  return result;
}

static int
pidfd_exited (int pidfd)
{
  struct pollfd item;
  int result;
  memset(&item, 0, sizeof(item));
  item.fd = pidfd;
  item.events = POLLIN;
  do {
    result = poll(&item, 1, 0);
  } while (result < 0 && errno == EINTR);
  if (result < 0) return -1;
  return result > 0 ? 1 : 0;
}

static int
wait_pidfd (int pidfd, int timeout_ms)
{
  struct pollfd item;
  int result;
  memset(&item, 0, sizeof(item));
  item.fd = pidfd;
  item.events = POLLIN;
  do {
    result = poll(&item, 1, timeout_ms);
  } while (result < 0 && errno == EINTR);
  if (result < 0) return -1;
  return result > 0 ? 1 : 0;
}

static int
read_main_pid (pid_t *output)
{
  char text[OUTPUT_MAX] = { 0 };
  char *argv[] = {
    (char *) SYSTEMCTL,
    (char *) "show",
    (char *) EXPECTED_UNIT,
    (char *) "--property=MainPID",
    (char *) "--value",
    (char *) "--no-pager",
    NULL
  };
  unsigned long long parsed;
  size_t length;
  if (read_child_output(SYSTEMCTL, argv, text, sizeof(text)) != 0) return -1;
  length = strlen(text);
  while (length > 0 && (text[length - 1] == '\n' || text[length - 1] == '\r')) text[--length] = '\0';
  if (parse_u64(text, 1, INT_MAX, &parsed) != 0) return -1;
  *output = (pid_t) parsed;
  return 0;
}

static int
read_starttime (pid_t pid, unsigned long long *output)
{
  char path[64];
  char buffer[OUTPUT_MAX];
  ssize_t count;
  char *close_paren;
  char *cursor;
  int field = 3;
  int fd;

  if (snprintf(path, sizeof(path), "/proc/%ld/stat", (long) pid) >= (int) sizeof(path)) return -1;
  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return -1;
  do {
    count = read(fd, buffer, sizeof(buffer) - 1);
  } while (count < 0 && errno == EINTR);
  close(fd);
  if (count <= 0 || count >= (ssize_t) sizeof(buffer) - 1) return -1;
  buffer[count] = '\0';
  close_paren = strrchr(buffer, ')');
  if (close_paren == NULL || close_paren[1] != ' ') return -1;
  cursor = close_paren + 2;
  while (field < 22) {
    while (*cursor != '\0' && *cursor != ' ') cursor++;
    while (*cursor == ' ') cursor++;
    field++;
  }
  {
    char *end = cursor;
    char saved;
    while (*end != '\0' && *end != ' ') end++;
    saved = *end;
    *end = '\0';
    if (parse_u64(cursor, 1, ULLONG_MAX, output) != 0) {
      *end = saved;
      return -1;
    }
    *end = saved;
  }
  return 0;
}

static int
sha256_path (const char *path, char output[65])
{
  char text[OUTPUT_MAX] = { 0 };
  char *argv[] = { (char *) SHA256SUM, (char *) "--", (char *) path, NULL };
  if (read_child_output(SHA256SUM, argv, text, sizeof(text)) != 0) return -1;
  if (strlen(text) < 66 || (text[64] != ' ' && text[64] != '\t')) return -1;
  text[64] = '\0';
  if (!lower_sha256(text)) return -1;
  memcpy(output, text, 65);
  return 0;
}

static int
cgroup_has_expected_unit (pid_t pid)
{
  char path[64];
  char buffer[OUTPUT_MAX];
  ssize_t count;
  char *cursor;
  int fd;
  if (snprintf(path, sizeof(path), "/proc/%ld/cgroup", (long) pid) >= (int) sizeof(path)) return 0;
  fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return 0;
  do {
    count = read(fd, buffer, sizeof(buffer) - 1);
  } while (count < 0 && errno == EINTR);
  close(fd);
  if (count <= 0 || count >= (ssize_t) sizeof(buffer) - 1) return 0;
  buffer[count] = '\0';
  cursor = buffer;
  while ((cursor = strstr(cursor, "/" EXPECTED_UNIT)) != NULL) {
    char following = cursor[1 + strlen(EXPECTED_UNIT)];
    if (following == '\0' || following == '\n') return 1;
    cursor++;
  }
  return 0;
}

static int
verify_target (int pidfd, const struct target *target)
{
  char path[64];
  char digest[65];
  pid_t main_pid;
  unsigned long long starttime;
  int exited = pidfd_exited(pidfd);
  if (exited != 0) return -1;
  if (read_main_pid(&main_pid) != 0 || main_pid != target->pid) return -1;
  if (read_starttime(target->pid, &starttime) != 0 || starttime != target->starttime) return -1;

  if (snprintf(path, sizeof(path), "/proc/%ld/exe", (long) target->pid) >= (int) sizeof(path)) return -1;
  if (sha256_path(path, digest) != 0 || strcmp(digest, target->executable_sha256) != 0) return -1;
  if (!cgroup_has_expected_unit(target->pid)) return -1;
  if (snprintf(path, sizeof(path), "/proc/%ld/cgroup", (long) target->pid) >= (int) sizeof(path)) return -1;
  if (sha256_path(path, digest) != 0 || strcmp(digest, target->cgroup_sha256) != 0) return -1;
  return pidfd_exited(pidfd) == 0 ? 0 : -1;
}

static int
pidfd_signal (int pidfd, int signal_number)
{
  return (int) syscall(SYS_pidfd_send_signal, pidfd, signal_number, NULL, 0);
}

static int
parse_args (int argc, char **argv, struct target *target)
{
  int index;
  unsigned long long parsed;
  int seen_unit = 0;
  int seen_pid = 0;
  int seen_starttime = 0;
  int seen_executable = 0;
  int seen_cgroup = 0;
  int seen_grace = 0;
  int seen_kill = 0;

  memset(target, 0, sizeof(*target));
  if (argc != 15) return -1;
  for (index = 1; index < argc; index += 2) {
    const char *name = argv[index];
    const char *value = argv[index + 1];
    if (strcmp(name, "--unit") == 0 && !seen_unit) {
      if (strcmp(value, EXPECTED_UNIT) != 0) return -1;
      seen_unit = 1;
    } else if (strcmp(name, "--pid") == 0 && !seen_pid) {
      if (parse_u64(value, 1, INT_MAX, &parsed) != 0) return -1;
      target->pid = (pid_t) parsed;
      seen_pid = 1;
    } else if (strcmp(name, "--starttime") == 0 && !seen_starttime) {
      if (parse_u64(value, 1, ULLONG_MAX, &target->starttime) != 0) return -1;
      seen_starttime = 1;
    } else if (strcmp(name, "--executable-sha256") == 0 && !seen_executable) {
      if (!lower_sha256(value)) return -1;
      memcpy(target->executable_sha256, value, 65);
      seen_executable = 1;
    } else if (strcmp(name, "--cgroup-sha256") == 0 && !seen_cgroup) {
      if (!lower_sha256(value)) return -1;
      memcpy(target->cgroup_sha256, value, 65);
      seen_cgroup = 1;
    } else if (strcmp(name, "--term-grace-ms") == 0 && !seen_grace) {
      if (parse_u64(value, 5000, 120000, &parsed) != 0) return -1;
      target->term_grace_ms = (int) parsed;
      seen_grace = 1;
    } else if (strcmp(name, "--kill-allowed") == 0 && !seen_kill) {
      if (strcmp(value, "0") != 0 && strcmp(value, "1") != 0) return -1;
      target->kill_allowed = value[0] == '1';
      seen_kill = 1;
    } else {
      return -1;
    }
  }
  return seen_unit && seen_pid && seen_starttime && seen_executable && seen_cgroup &&
    seen_grace && seen_kill ? 0 : -1;
}

int
main (int argc, char **argv)
{
  struct target target;
  int pidfd;
  int waited;

  if (geteuid() != 0) {
    fputs("root-required\n", stderr);
    return 77;
  }
  if (parse_args(argc, argv, &target) != 0) {
    fputs("invalid-arguments\n", stderr);
    return 64;
  }
  pidfd = (int) syscall(SYS_pidfd_open, target.pid, 0);
  if (pidfd < 0) {
    fputs("pidfd-unavailable\n", stderr);
    return 77;
  }
  if (verify_target(pidfd, &target) != 0) {
    fputs("target-drift-before-term\n", stderr);
    close(pidfd);
    return 78;
  }
  if (pidfd_signal(pidfd, SIGTERM) != 0) {
    fputs("pidfd-term-failed\n", stderr);
    close(pidfd);
    return 79;
  }
  waited = wait_pidfd(pidfd, target.term_grace_ms);
  if (waited == 1) {
    close(pidfd);
    return 0;
  }
  if (waited < 0 || !target.kill_allowed) {
    fputs(waited < 0 ? "pidfd-wait-failed\n" : "term-grace-expired-kill-forbidden\n", stderr);
    close(pidfd);
    return 80;
  }
  if (verify_target(pidfd, &target) != 0) {
    fputs("target-drift-before-kill\n", stderr);
    close(pidfd);
    return 78;
  }
  if (pidfd_signal(pidfd, SIGKILL) != 0) {
    fputs("pidfd-kill-failed\n", stderr);
    close(pidfd);
    return 79;
  }
  waited = wait_pidfd(pidfd, 10000);
  close(pidfd);
  if (waited != 1) {
    fputs("pidfd-kill-unconfirmed\n", stderr);
    return 81;
  }
  return 0;
}

#endif
