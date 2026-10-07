// SPDX-License-Identifier: GPL-2.0
/*
 * svc-classify - attach the prefix classifier to the RPC services of this
 * network namespace and manage its prefix map.
 *
 *   svc-classify [-p DIR] load             attach; pin the link and the map
 *   svc-classify [-p DIR] replace          replace the program, keep the map
 *   svc-classify [-p DIR] unload           detach
 *   svc-classify [-p DIR] add PREFIX CLASS
 *   svc-classify [-p DIR] del PREFIX
 *   svc-classify [-p DIR] list
 *   svc-classify [-p DIR] status
 *
 * PREFIX is a.b.c.d[/len], x:y::z[/len], any, any4 or any6.  CLASS is N
 * (one client for every peer that matches), N+addr (one client per peer
 * address within class N), addr (the same as 0+addr) or 0 (the anonymous
 * client).  DIR, where the link and the map are pinned, defaults to
 * /sys/fs/bpf/svc_classify.
 */
#include <arpa/inet.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "svc_classify.skel.h"

#define PIN_DIR_DEFAULT	"/sys/fs/bpf/svc_classify"
#define SVC_CLASS_PER_ADDR	(1U << 31)

struct prefix_key {
	__u32 prefixlen;
	__u8 family;
	__u8 addr[16];
};

static const char *progname;
static char pin_link[PATH_MAX], pin_map[PATH_MAX];
static const char *pin_dir = PIN_DIR_DEFAULT;

static void usage(void)
{
	fprintf(stderr,
		"usage: %s [-p DIR] load | replace | unload | list | status |\n"
		"       add PREFIX CLASS | del PREFIX\n"
		"PREFIX: a.b.c.d[/len], x:y::z[/len], any, any4, any6\n"
		"CLASS:  N, N+addr, addr, 0\n", progname);
	exit(2);
}

static int do_load(void)
{
	struct svc_classify *skel;
	struct bpf_link *link;
	int err;

	if (access(pin_link, F_OK) == 0) {
		fprintf(stderr, "%s: already loaded (%s exists)\n", progname,
			pin_link);
		return 1;
	}
	mkdir(pin_dir, 0700);

	skel = svc_classify__open_and_load();
	if (!skel) {
		fprintf(stderr, "%s: load: %s\n", progname, strerror(errno));
		rmdir(pin_dir);
		return 1;
	}
	link = bpf_map__attach_struct_ops(skel->maps.prefix);
	if (!link) {
		fprintf(stderr, "%s: attach: %s\n", progname, strerror(errno));
		rmdir(pin_dir);
		return 1;
	}
	err = bpf_link__pin(link, pin_link);
	if (!err)
		err = bpf_map__pin(skel->maps.prefixes, pin_map);
	if (err) {
		fprintf(stderr, "%s: pin: %s\n", progname, strerror(-err));
		bpf_link__destroy(link);
		unlink(pin_link);
		rmdir(pin_dir);
		return 1;
	}
	return 0;
}

static int do_replace(void)
{
	struct svc_classify *skel;
	struct bpf_link *link;
	int link_fd, err;

	link_fd = bpf_obj_get(pin_link);
	if (link_fd < 0) {
		fprintf(stderr, "%s: not loaded (%s)\n", progname,
			strerror(errno));
		return 1;
	}
	skel = svc_classify__open();
	if (!skel) {
		fprintf(stderr, "%s: open: %s\n", progname, strerror(errno));
		return 1;
	}
	/*
	 * Reuse the pinned map so the entries survive.  A build whose map
	 * definition differs fails here; unload and load then.
	 */
	err = bpf_map__set_pin_path(skel->maps.prefixes, pin_map);
	if (!err)
		err = svc_classify__load(skel);
	if (err) {
		fprintf(stderr, "%s: load: %s\n", progname, strerror(-err));
		return 1;
	}
	/*
	 * bpf_link__update_map() wants the link that attached the map, not
	 * one reopened from a pin.  bpf_map__attach_struct_ops() writes the
	 * program into the new map's value before it tries to create a link,
	 * and the link is refused with EBUSY while the old one is attached;
	 * the written map is what the link update needs.
	 */
	link = bpf_map__attach_struct_ops(skel->maps.prefix);
	if (link) {
		bpf_link__destroy(link);
		fprintf(stderr, "%s: nothing attached in this namespace; unload and load\n",
			progname);
		return 1;
	}
	if (errno != EBUSY) {
		fprintf(stderr, "%s: attach: %s\n", progname, strerror(errno));
		return 1;
	}
	err = bpf_link_update(link_fd, bpf_map__fd(skel->maps.prefix), NULL);
	if (err) {
		fprintf(stderr, "%s: replace: %s\n", progname, strerror(errno));
		return 1;
	}
	return 0;
}

static int do_unload(void)
{
	int ret = 0;

	if (unlink(pin_link) && errno != ENOENT) {
		perror(pin_link);
		ret = 1;
	}
	if (unlink(pin_map) && errno != ENOENT) {
		perror(pin_map);
		ret = 1;
	}
	rmdir(pin_dir);
	return ret;
}

static int parse_prefix(const char *s, struct prefix_key *key)
{
	char buf[64], *slash;
	int bits, max;

	memset(key, 0, sizeof(*key));
	if (!strcmp(s, "any"))
		return 0;
	if (!strcmp(s, "any4")) {
		key->family = AF_INET;
		key->prefixlen = 8;
		return 0;
	}
	if (!strcmp(s, "any6")) {
		key->family = AF_INET6;
		key->prefixlen = 8;
		return 0;
	}
	if (strlen(s) >= sizeof(buf))
		return -1;
	strcpy(buf, s);
	slash = strchr(buf, '/');
	if (slash)
		*slash++ = '\0';
	if (inet_pton(AF_INET, buf, key->addr) == 1) {
		key->family = AF_INET;
		max = 32;
	} else if (inet_pton(AF_INET6, buf, key->addr) == 1) {
		key->family = AF_INET6;
		max = 128;
	} else {
		return -1;
	}
	bits = max;
	if (slash) {
		char *end;

		if (*slash < '0' || *slash > '9')
			return -1;
		bits = strtoul(slash, &end, 10);
		if (*end || bits > max)
			return -1;
	}
	key->prefixlen = 8 + bits;
	return 0;
}

static int parse_class(const char *s, __u32 *class)
{
	unsigned long n;
	char *end;

	if (!strcmp(s, "addr")) {
		*class = SVC_CLASS_PER_ADDR;
		return 0;
	}
	n = strtoul(s, &end, 0);
	if (end == s || n >= SVC_CLASS_PER_ADDR)
		return -1;
	*class = n;
	if (!strcmp(end, "+addr"))
		*class |= SVC_CLASS_PER_ADDR;
	else if (*end)
		return -1;
	return 0;
}

static void print_entry(const struct prefix_key *key, __u32 class)
{
	char addr[INET6_ADDRSTRLEN];

	if (key->prefixlen == 0)
		printf("any");
	else if (key->prefixlen == 8)
		printf("any%d", key->family == AF_INET ? 4 : 6);
	else
		printf("%s/%u", inet_ntop(key->family, key->addr, addr,
					  sizeof(addr)), key->prefixlen - 8);
	printf(" -> %u%s\n", class & ~SVC_CLASS_PER_ADDR,
	       class & SVC_CLASS_PER_ADDR ? "+addr" : "");
}

static int open_map(void)
{
	int fd = bpf_obj_get(pin_map);

	if (fd < 0) {
		fprintf(stderr, "%s: not loaded (%s: %s)\n", progname, pin_map,
			strerror(errno));
		exit(1);
	}
	return fd;
}

static int do_add(const char *prefix, const char *cls)
{
	struct prefix_key key;
	__u32 class;

	if (parse_prefix(prefix, &key) || parse_class(cls, &class))
		usage();
	if (bpf_map_update_elem(open_map(), &key, &class, BPF_ANY)) {
		fprintf(stderr, "%s: add: %s\n", progname, strerror(errno));
		return 1;
	}
	return 0;
}

static int do_del(const char *prefix)
{
	struct prefix_key key;

	if (parse_prefix(prefix, &key))
		usage();
	if (bpf_map_delete_elem(open_map(), &key)) {
		fprintf(stderr, "%s: del: %s\n", progname, strerror(errno));
		return 1;
	}
	return 0;
}

static int do_list(void)
{
	struct prefix_key key, next;
	__u32 class;
	int fd;

	fd = open_map();
	if (bpf_map_get_next_key(fd, NULL, &next))
		return 0;
	do {
		key = next;
		if (!bpf_map_lookup_elem(fd, &key, &class))
			print_entry(&key, class);
	} while (!bpf_map_get_next_key(fd, &key, &next));
	return 0;
}

static int do_status(void)
{
	struct bpf_link_info info = {};
	__u32 len = sizeof(info);
	int fd;

	fd = bpf_obj_get(pin_link);
	if (fd < 0) {
		printf("not loaded\n");
		return 1;
	}
	if (bpf_link_get_info_by_fd(fd, &info, &len))
		printf("loaded\n");
	else
		printf("loaded, link id %u, struct_ops map id %u\n", info.id,
		       info.struct_ops.map_id);
	return 0;
}

int main(int argc, char **argv)
{
	const char *cmd;
	int opt;

	progname = argv[0];
	while ((opt = getopt(argc, argv, "p:")) != -1) {
		if (opt != 'p')
			usage();
		pin_dir = optarg;
	}
	argc -= optind;
	argv += optind;
	if (argc < 1)
		usage();
	cmd = argv[0];
	snprintf(pin_link, sizeof(pin_link), "%s/link", pin_dir);
	snprintf(pin_map, sizeof(pin_map), "%s/prefixes", pin_dir);

	if (!strcmp(cmd, "load") && argc == 1)
		return do_load();
	if (!strcmp(cmd, "replace") && argc == 1)
		return do_replace();
	if (!strcmp(cmd, "unload") && argc == 1)
		return do_unload();
	if (!strcmp(cmd, "add") && argc == 3)
		return do_add(argv[1], argv[2]);
	if (!strcmp(cmd, "del") && argc == 2)
		return do_del(argv[1]);
	if (!strcmp(cmd, "list") && argc == 1)
		return do_list();
	if (!strcmp(cmd, "status") && argc == 1)
		return do_status();
	usage();
	return 2;
}
