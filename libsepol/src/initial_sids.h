#ifndef _SEPOL_INITIAL_SIDS_H_
#define _SEPOL_INITIAL_SIDS_H_

/*
 * Initial SID (isid) name tables, indexed by SID value. Initial SID names
 * aren't actually stored in the binary/pp policy files, so callers that
 * need to print or look up an initial SID by name (kernel_to_common.c's
 * CIL/conf writers, and the sepol_isid_iter_t public API in ocontext.c)
 * share this single mapping, taken from the Linux kernel.
 */
static const char *const selinux_sid_to_str[] = {
	NULL,	"kernel", "security",	"unlabeled", NULL,    "file",
	NULL,	"init",	  "any_socket", "port",	     "netif", "netmsg",
	"node", NULL,	  NULL,		NULL,	     NULL,    NULL,
	NULL,	NULL,	  NULL,		NULL,	     NULL,    NULL,
	NULL,	NULL,	  NULL,		"devnull",
};

#define SELINUX_SID_SZ \
	(sizeof(selinux_sid_to_str) / sizeof(selinux_sid_to_str[0]))

static const char *const xen_sid_to_str[] = {
	"null",	  "xen",   "dom0", "domio",  "domxen", "unlabeled", "security",
	"ioport", "iomem", "irq",  "device", "domU",   "domDM",
};

#define XEN_SID_SZ (sizeof(xen_sid_to_str) / sizeof(xen_sid_to_str[0]))

#endif /* _SEPOL_INITIAL_SIDS_H_ */
