#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <getopt.h>
#include <unistd.h>
#include <fcntl.h>
#include <selinux/selinux.h>

#define MODE_LOAD 1
#define MODE_UNLOAD 2
#define MODE_LIST 3

#define SELINUXFS_SANDBOX_LOAD "/sys/fs/selinux/sandbox/sandbox_load"
#define SELINUXFS_SANDBOX_UNLOAD "/sys/fs/selinux/sandbox/sandbox_unload"

extern char *selinux_mnt;

static __attribute__((__noreturn__)) void usage(const char *prog)
{
	printf("Usage: %s [OPTIONS]...\n", prog);
	printf("  %s --load FILE\n", prog);
	printf("  %s --unload FILE\n", prog);
	printf("  %s --list\n", prog);
	printf("\n");
	printf("Options\n");
	printf("  -l, --load=<file>              load sandbox policy\n");
	printf("  -u, --unload=<file>            unload sandbox policy\n");
	printf("  -L, --list                     list installed sandboxes\n");
	printf("  -v  --verbose                  verbose\n");
	printf("  -h, --help                     display usage information\n");
	exit(1);
}

int main(int argc, char **argv)
{
	int opt = 0;
	int opt_index = 0;
	int verbose = 0;
	int mode = 0;
	char *filepath = NULL;
	FILE *file = NULL;
	struct stat filedata;
	ssize_t datalen = 0;
	char *data = NULL;
	int fd = -1;
	ssize_t written = 0;
	static struct option long_opts[] = {
		{"help", no_argument, 0, 'h'},
		{"verbose", no_argument, 0, 'v'},
		{"load", required_argument, 0, 'l'},
		{"unload", required_argument, 0, 'u'},
		{"list", no_argument, 0, 'L'},
		{0, 0, 0, 0}
	};
	int rc = 0;

	while (1) {

		opt = getopt_long(argc, argv, "hvl:u:L", long_opts, &opt_index);

		if (opt == -1)
			break;

		switch (opt) {
		case 'v':
			verbose = 1;
			break;
		case 'l':
			if (mode) {
				fprintf(stderr, "Only one action at a time!\n");
				usage(argv[0]);
			}
			mode = MODE_LOAD;
			filepath = strdup(optarg);
			break;
		case 'u':
			if (mode) {
				fprintf(stderr, "Only one action at a time!\n");
				usage(argv[0]);
			}
			mode = MODE_UNLOAD;
			filepath = strdup(optarg);
			break;
		case 'L':
			if (mode) {
				fprintf(stderr, "Only one action at a time!\n");
				usage(argv[0]);
			}
			mode = MODE_LIST;
			break;
		case 'h':
			usage(argv[0]);
			break;
		default:
			fprintf(stderr, "Unsupported option %s\n", optarg);
			usage(argv[0]);
		}

	}

	if (!mode) {
		printf("Please specify an action (load/unload/list)\n");
		return -1;
	}

	/* make sure selinux is enabled */
	rc = is_selinux_enabled();
	if (rc != 1) {
		printf("SELinux is not enabled\n");
		printf("Please enable selinux to use sandboxing\n");
		return -1;
	}

	/* confirm selinuxfs is mounted */
	if (selinux_mnt == NULL) {
		printf("SELinuxfs not mounted\n");
		printf("Please mount selinuxfs for proper results\n");
		return -1;
	}

	/* MODE_LIST doesn't require any input files, handle it first */
	if (mode == MODE_LIST) {
		printf("under construction\n");
		return 0;
	}

	/* read in file data */
	file = fopen(filepath, "r");
	if (!file) {
		fprintf(stderr, "Could not open file: %s\n", filepath);
		return -1;
	}

	rc = stat(filepath, &filedata);
	if (rc == -1) {
		fprintf(stderr, "Could not stat file: %s\n", filepath);
		rc = -1;
		goto exit;
	}
	datalen = filedata.st_size;

	data = malloc(datalen);
	rc = fread(data, datalen, 1, file);
	if (rc != 1) {
		fprintf(stderr, "Failure reading file: %s\n", filepath);
		rc = -1;
		goto exit;
	}
	fclose(file);
	file = NULL;

	/* open selinux fs node for writing */
	if (mode == MODE_LOAD) {

		fd = open(SELINUXFS_SANDBOX_LOAD, O_WRONLY);
		if (fd < 0) {
			fprintf(stderr, "Could not open selinuxfs node: %s\n",
				SELINUXFS_SANDBOX_LOAD);
			rc = -1;
			goto exit;
		}

	} else {

		fd = open(SELINUXFS_SANDBOX_UNLOAD, O_WRONLY);
		if (fd < 0) {
			fprintf(stderr, "Could not open selinuxfs node: %s\n",
				SELINUXFS_SANDBOX_UNLOAD);
			rc = -1;
			goto exit;
		}

	}

	written = write(fd, data, datalen);
	if (written != datalen) {
		fprintf(stderr, "Failure writing to selinuxfs node: %s\n",
			SELINUXFS_SANDBOX_LOAD);
		rc = -1;
		goto exit;
	}
	close(fd);
	fd = -1;

	if (verbose)
		printf("done\n");

	rc = 0;

exit:
	if (file)
		fclose(file);
	if (fd)
		close(fd);
	free(data);
	return rc;
}
