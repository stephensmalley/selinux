/*
 * String representation support for classes and permissions.
 */
#include <sys/stat.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include "selinux_internal.h"
#include "policy.h"
#include "mapping.h"

#define MAXVECTORS (8 * sizeof(access_vector_t))

struct discover_class_node {
	char *name;
	security_class_t value;
	char **perms;

	struct discover_class_node *next;
};

static pthread_mutex_t discover_class_lock = PTHREAD_MUTEX_INITIALIZER;
static struct discover_class_node *discover_class_cache = NULL;
static struct discover_class_node *discover_class_retired = NULL;

static struct discover_class_node *get_class_cache_entry_name(const char *s)
{
	struct discover_class_node *node = discover_class_cache;

	for (; node != NULL && strcmp(s, node->name) != 0; node = node->next)
		;

	return node;
}

static struct discover_class_node *
get_class_cache_entry_value(security_class_t c)
{
	struct discover_class_node *node = discover_class_cache;

	for (; node != NULL && c != node->value; node = node->next)
		;

	return node;
}

static struct discover_class_node *discover_class(const char *s)
{
	int fd, ret;
	char path[PATH_MAX];
	char buf[20];
	DIR *dir;
	struct dirent *dentry;
	size_t i;

	struct discover_class_node *node;

	if (!selinux_mnt) {
		errno = ENOENT;
		return NULL;
	}

	if (strchr(s, '/') != NULL)
		return NULL;

	/* allocate a node */
	node = malloc(sizeof(struct discover_class_node));
	if (node == NULL)
		return NULL;

	/* allocate array for perms */
	node->perms = calloc(MAXVECTORS, sizeof(char *));
	if (node->perms == NULL)
		goto err1;

	/* load up the name */
	node->name = strdup(s);
	if (node->name == NULL)
		goto err2;

	/* load up class index */
	ret = snprintf(path, sizeof path, "%s/class/%s/index", selinux_mnt, s);
	if (ret < 0 || (size_t)ret >= sizeof path)
		goto err3;

	fd = open(path, O_RDONLY | O_CLOEXEC);
	if (fd < 0)
		goto err3;

	memset(buf, 0, sizeof(buf));
	ret = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (ret < 0)
		goto err3;

	if (sscanf(buf, "%hu", &node->value) != 1)
		goto err3;

	/* load up permission indices */
	ret = snprintf(path, sizeof path, "%s/class/%s/perms", selinux_mnt, s);
	if (ret < 0 || (size_t)ret >= sizeof path)
		goto err3;

	dir = opendir(path);
	if (dir == NULL)
		goto err3;

	dentry = readdir(dir);
	while (dentry != NULL) {
		unsigned int value;
		struct stat m;

		ret = snprintf(path, sizeof path, "%s/class/%s/perms/%s",
			       selinux_mnt, s, dentry->d_name);
		if (ret < 0 || (size_t)ret >= sizeof path)
			goto err4;

		fd = open(path, O_RDONLY | O_CLOEXEC);
		if (fd < 0)
			goto err4;

		if (fstat(fd, &m) < 0) {
			close(fd);
			goto err4;
		}

		if (m.st_mode & S_IFDIR) {
			close(fd);
			dentry = readdir(dir);
			continue;
		}

		memset(buf, 0, sizeof(buf));
		ret = read(fd, buf, sizeof(buf) - 1);
		close(fd);
		if (ret < 0)
			goto err4;

		if (sscanf(buf, "%u", &value) != 1)
			goto err4;

		if (value == 0 || value > MAXVECTORS)
			goto err4;

		node->perms[value - 1] = strdup(dentry->d_name);
		if (node->perms[value - 1] == NULL)
			goto err4;

		dentry = readdir(dir);
	}
	closedir(dir);

	return node;

err4:
	closedir(dir);
	for (i = 0; i < MAXVECTORS; i++)
		free(node->perms[i]);
err3:
	free(node->name);
err2:
	free(node->perms);
err1:
	free(node);
	return NULL;
}

void selinux_flush_class_cache(void)
{
	struct discover_class_node *head, *tail;

	__pthread_mutex_lock(&discover_class_lock);
	head = discover_class_cache;
	discover_class_cache = NULL;

	/*
	 * Move old list to the retired chain rather than
	 * freeing it; other threads may hold pointers to
	 * class/perm strings within it returned by
	 * security_class_to_string() and
	 * security_av_perm_to_string(). This incurs a small
	 * memory cost but given the infrequency of policy
	 * reloads, it should never be significant. If
	 * required, a new interface could be introduced to
	 * allow the application to safely drain the retired
	 * list when it knows it is safe to do so.
	 */
	if (head) {
		tail = head;
		while (tail->next)
			tail = tail->next;
		tail->next = discover_class_retired;
		discover_class_retired = head;
	}
	__pthread_mutex_unlock(&discover_class_lock);
}

security_class_t string_to_security_class(const char *s)
{
	struct discover_class_node *node, *retry;
	security_class_t value;
	size_t i;

	__pthread_mutex_lock(&discover_class_lock);
	node = get_class_cache_entry_name(s);
	if (node) {
		value = node->value;
		__pthread_mutex_unlock(&discover_class_lock);
		return map_class(value);
	}
	__pthread_mutex_unlock(&discover_class_lock);

	/* Discover outside of lock; reads selinuxfs */
	node = discover_class(s);
	if (node == NULL) {
		errno = EINVAL;
		return 0;
	}
	value = node->value;

	/*
	 * Retry cache lookup with lock held in case
	 * another thread raced with us. If we don't
	 * find it, add the new one; else use
	 * the old one and free the new one.
	 */
	__pthread_mutex_lock(&discover_class_lock);
	retry = get_class_cache_entry_name(s);
	if (!retry) {
		node->next = discover_class_cache;
		discover_class_cache = node;
	} else {
		value = retry->value;
		/*
		 * We can only safely free node here
		 * because it wasn't yet added to the cache.
		 */
		free(node->name);
		for (i = 0; i < MAXVECTORS; i++)
			free(node->perms[i]);
		free(node->perms);
		free(node);
		node = NULL;
	}
	__pthread_mutex_unlock(&discover_class_lock);

	return map_class(value);
}

security_class_t mode_to_security_class(mode_t m)
{
	if (S_ISREG(m))
		return string_to_security_class("file");
	if (S_ISDIR(m))
		return string_to_security_class("dir");
	if (S_ISCHR(m))
		return string_to_security_class("chr_file");
	if (S_ISBLK(m))
		return string_to_security_class("blk_file");
	if (S_ISFIFO(m))
		return string_to_security_class("fifo_file");
	if (S_ISLNK(m))
		return string_to_security_class("lnk_file");
	if (S_ISSOCK(m))
		return string_to_security_class("sock_file");

	errno = EINVAL;
	return 0;
}

access_vector_t string_to_av_perm(security_class_t tclass, const char *s)
{
	struct discover_class_node *node;
	security_class_t kclass = unmap_class(tclass);

	__pthread_mutex_lock(&discover_class_lock);
	node = get_class_cache_entry_value(kclass);
	if (node != NULL) {
		size_t i;
		for (i = 0; i < MAXVECTORS && node->perms[i] != NULL; i++)
			if (strcmp(node->perms[i], s) == 0) {
				__pthread_mutex_unlock(&discover_class_lock);
				return map_perm(tclass, UINT32_C(1) << i);
			}
	}
	__pthread_mutex_unlock(&discover_class_lock);

	errno = EINVAL;
	return 0;
}

const char *security_class_to_string(security_class_t tclass)
{
	struct discover_class_node *node;
	const char *name;

	tclass = unmap_class(tclass);

	__pthread_mutex_lock(&discover_class_lock);
	node = get_class_cache_entry_value(tclass);
	name = node ? node->name : NULL;
	__pthread_mutex_unlock(&discover_class_lock);

	return name;
}

const char *security_av_perm_to_string(security_class_t tclass,
				       access_vector_t av)
{
	struct discover_class_node *node;
	size_t i;
	const char *name;

	av = unmap_perm(tclass, av);
	tclass = unmap_class(tclass);

	__pthread_mutex_lock(&discover_class_lock);
	node = get_class_cache_entry_value(tclass);
	if (av && node)
		for (i = 0; i < MAXVECTORS; i++)
			if ((UINT32_C(1) << i) & av) {
				name = node->perms[i];
				__pthread_mutex_unlock(&discover_class_lock);
				return name;
			}

	__pthread_mutex_unlock(&discover_class_lock);
	return NULL;
}

int security_av_string(security_class_t tclass, access_vector_t av, char **res)
{
	unsigned int i;
	size_t len = 5;
	access_vector_t tmp = av;
	int rc = 0;
	const char *str;
	char *ptr;

	/* first pass computes the required length */
	for (i = 0; tmp; tmp >>= 1, i++) {
		if (tmp & 1) {
			str = security_av_perm_to_string(
				tclass, av & (UINT32_C(1) << i));
			if (str)
				len += strlen(str) + 1;
		}
	}

	*res = malloc(len);
	if (!*res) {
		rc = -1;
		goto out;
	}

	/* second pass constructs the string */
	tmp = av;
	ptr = *res;

	if (!av) {
		sprintf(ptr, "null");
		goto out;
	}

	ptr += sprintf(ptr, "{ ");
	for (i = 0; tmp; tmp >>= 1, i++) {
		if (tmp & 1) {
			str = security_av_perm_to_string(
				tclass, av & (UINT32_C(1) << i));
			if (str)
				ptr += sprintf(ptr, "%s ", str);
		}
	}
	sprintf(ptr, "}");
out:
	return rc;
}

void print_access_vector(security_class_t tclass, access_vector_t av)
{
	const char *permstr;
	access_vector_t bit = 1;

	if (av == 0) {
		printf(" null");
		return;
	}

	printf(" {");

	for (;;) {
		if (av & bit) {
			permstr = security_av_perm_to_string(tclass, bit);
			if (!permstr)
				break;
			printf(" %s", permstr);
			av &= ~bit;
			if (!av)
				break;
		}
		bit <<= 1;
	}

	if (av)
		printf(" 0x%x", av);
	printf(" }");
}
