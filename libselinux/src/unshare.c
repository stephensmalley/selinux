#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/mount.h>
#include <sys/vfs.h>
#include <sys/statvfs.h>

#include "selinux_internal.h"
#include "policy.h"

/*
 * Precondition: caller must have already done unshare(CLONE_NEWNS) or
 * been created via clone(CLONE_NEWNS) and mounted a MS_REC|MS_PRIVATE
 * / filesystem so that any pre-existing selinuxfs mount can be
 * modified freely by selinux_unshare(). See ../utils/unshareselinux.c
 * for an example.
 */
int selinux_unshare(void)
{
	struct statfs fs;
	int ret, fd;
	char buf[3] = "1\n";

	ret = statfs(SELINUXMNT, &fs);
	if (ret < 0) {
		/*
		 * Should we try to handle this gracefully?
		 * If it fails due to /sys not being mounted, then we could
		 * mount sysfs and try to continue here.
		 */
		return ret;
	}

	if ((uint32_t) fs.f_type == (uint32_t) SELINUX_MAGIC) {
		if (fs.f_flags & ST_RDONLY) {
			/*
			 * selinuxfs is mounted read-only; try re-mounting
			 * read-write temporarily so that we can unshare it.
			 */
			ret = mount(SELINUXFS, SELINUXMNT, SELINUXFS,
				    MS_REMOUNT | MS_BIND | MS_NOEXEC |
				    MS_NOSUID, 0);
			if (ret < 0)
				return -1;
		}
	} else {
		/*
		 * selinuxfs is not mounted; try mounting it temporarily so
		 * that we can unshare it.
		 */
		ret = mount(SELINUXFS, SELINUXMNT, SELINUXFS,
			    MS_NOEXEC | MS_NOSUID, 0);
		if (ret < 0)
			return -1;
	}

	/*
	 * Unshare SELinux namespace
	 */
	fd = open(SELINUXMNT "/unshare", O_WRONLY);
	if (fd < 0)
		return -1;
	ret = write(fd, buf, sizeof(buf));
	if (ret != sizeof(buf)) {
		int sv_errno = errno;
		close(fd);
		errno = sv_errno;
		return -1;
	}
	close(fd);

	/*
	 * Now unmount the old selinuxfs which refers to the old/parent namespace
	 */
	ret = umount(SELINUXMNT);
	if (ret < 0)
		return ret;

	return 0;
}
