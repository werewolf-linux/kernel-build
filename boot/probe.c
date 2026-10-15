// SPDX-License-Identifier: GPL-2.0-only
/*
 * probe is the first and only process of a test boot. It checks what the
 * kernel promises werewolf, prints one line per check and a verdict, and
 * powers off. Built with the kernel's own nolibc: no C library, no loader.
 */
#include "nolibc.h"
#include <linux/landlock.h>
#include <linux/reboot.h>
#include <linux/sched.h>

static int failed;

static void check(const char *what, int ok)
{
	printf("probe: %s %s\n", ok ? "ok" : "FAIL", what);
	failed |= !ok;
}

static int refused(long result, int error)
{
	return result == -1 && errno == error;
}

/* Try attempt in a child, so a wrongful success cannot change this process. */
static int refused_in_child(long (*attempt)(void), int error)
{
	int status;
	pid_t child = fork();

	if (child == 0)
		_exit(refused(attempt(), error) ? 0 : 1);
	return child > 0 && waitpid(child, &status, 0) == child &&
	       WIFEXITED(status) && WEXITSTATUS(status) == 0;
}

static long new_user_namespace(void)
{
	return syscall(__NR_unshare, CLONE_NEWUSER);
}

/* The start of a file, as a string; empty if it cannot be read. */
static const char *slurp(const char *path)
{
	static char buf[512];
	ssize_t n;
	int fd = open(path, O_RDONLY);

	n = fd < 0 ? 0 : read(fd, buf, sizeof(buf) - 1);
	if (fd >= 0)
		close(fd);
	buf[n > 0 ? n : 0] = '\0';
	return buf;
}

/* Offer IPE a policy signed by a key it does not trust; it must refuse it. */
static int untrusted_policy_refused(void)
{
	static char buf[8192];
	ssize_t n;
	int in = open("/untrusted.p7b", O_RDONLY), out;

	if (in < 0)
		return 0;
	n = read(in, buf, sizeof(buf));
	close(in);
	out = open("/sys/kernel/security/ipe/new_policy", O_WRONLY);
	if (n <= 0 || out < 0)
		return 0;
	n = write(out, buf, n);
	close(out);
	return n == -1 && (errno == ENOKEY || errno == EKEYREJECTED);
}

int main(void)
{
	struct utsname u = { 0 };
	size_t n;

	mount("proc", "/proc", "proc", 0, NULL);
	mount("sysfs", "/sys", "sysfs", 0, NULL);
	mount("securityfs", "/sys/kernel/security", "securityfs", 0, NULL);

	n = uname(&u) == 0 ? strlen(u.release) : 0;
	check("release ends in -werewolf", n > 9 && strcmp(u.release + n - 9, "-werewolf") == 0);
	check("no module loader", refused(open("/proc/modules", O_RDONLY), ENOENT) &&
	      refused(syscall(__NR_finit_module, -1, "", 0), ENOSYS));
	check("lockdown is confidentiality",
	      strstr(slurp("/sys/kernel/security/lockdown"), "[confidentiality]") != NULL);
	/* In initialization order: lockdown starts early, capability is always there. */
	check("LSMs are exactly lockdown,capability,landlock,yama,ipe",
	      strcmp(slurp("/sys/kernel/security/lsm"), "lockdown,capability,landlock,yama,ipe") == 0);
	check("Landlock ABI 10 or later",
	      syscall(__NR_landlock_create_ruleset, NULL, 0, LANDLOCK_CREATE_RULESET_VERSION) >= 10);
	check("no io_uring", refused(syscall(__NR_io_uring_setup, 1, NULL), ENOSYS));
	check("no bpf", refused(syscall(__NR_bpf, 0, NULL, 0), ENOSYS));
	check("no kexec", refused(syscall(__NR_kexec_file_load, -1, -1, 0, "", 0), ENOSYS));
	check("no user namespaces", refused_in_child(new_user_namespace, EINVAL));
	check("IPE enforces, with no policy until stage0 loads one",
	      strcmp(slurp("/sys/kernel/security/ipe/enforce"), "1") == 0 &&
	      open("/sys/kernel/security/ipe/policies/werewolf_boot", O_RDONLY) < 0);
	check("IPE refuses a policy signed by any other key", untrusted_policy_refused());
	check("running config is readable", open("/proc/config.gz", O_RDONLY) >= 0);

	printf("probe: %s %s\n", failed ? "FAIL" : "PASS", u.release);
	reboot(LINUX_REBOOT_CMD_POWER_OFF);
	printf("probe: power off failed: errno %d\n", errno);
	return 1;
}
