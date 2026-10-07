// SPDX-License-Identifier: GPL-2.0
/*
 * The svc_classifier struct_ops: one per network namespace, bound to
 * the attaching task's namespace; replace by link update; detach by
 * link close; a namespace that exits leaves its link empty.
 */
#include <test_progs.h>
#include "bpf_svc_classifier.skel.h"

static struct bpf_svc_classifier *load(void)
{
	struct bpf_svc_classifier *skel;

	skel = bpf_svc_classifier__open_and_load();
	if (!skel && (errno == ENOENT || errno == EINVAL || errno == EOPNOTSUPP)) {
		test__skip();
		return NULL;
	}
	ASSERT_OK_PTR(skel, "bpf_svc_classifier__open_and_load");
	return skel;
}

static void test_attach(void)
{
	struct bpf_svc_classifier *one, *two;
	struct bpf_link *link, *busy;
	int err;

	one = load();
	if (!one)
		return;
	two = load();
	if (!two)
		goto out_one;

	link = bpf_map__attach_struct_ops(one->maps.prefix);
	if (!ASSERT_OK_PTR(link, "attach"))
		goto out_two;

	busy = bpf_map__attach_struct_ops(two->maps.prefix);
	ASSERT_ERR_PTR(busy, "second attach");
	ASSERT_EQ(errno, EBUSY, "second attach errno");

	err = bpf_link__update_map(link, two->maps.prefix);
	ASSERT_OK(err, "replace");

	/* the replaced instance can be attached again once released */
	bpf_link__destroy(link);
	link = bpf_map__attach_struct_ops(one->maps.prefix);
	ASSERT_OK_PTR(link, "attach after detach");
	bpf_link__destroy(link);
out_two:
	bpf_svc_classifier__destroy(two);
out_one:
	bpf_svc_classifier__destroy(one);
}

static void test_netns(void)
{
	struct bpf_svc_classifier *inner, *outer;
	struct netns_obj *ns;
	struct bpf_link *link, *link2;

	inner = load();
	if (!inner)
		return;
	outer = load();
	if (!outer)
		goto out_inner;

	ns = netns_new("svc_classifier_ns", true);
	if (!ASSERT_OK_PTR(ns, "netns_new"))
		goto out_outer;

	/* attached inside the namespace */
	link = bpf_map__attach_struct_ops(inner->maps.prefix);
	if (!ASSERT_OK_PTR(link, "attach in netns"))
		goto out_ns;

	/* the initial namespace is free */
	netns_free(ns);
	ns = NULL;
	link2 = bpf_map__attach_struct_ops(outer->maps.prefix);
	ASSERT_OK_PTR(link2, "attach in init_net");
	bpf_link__destroy(link2);

	/* the link of the dead namespace detaches into nothing */
	bpf_link__destroy(link);
out_ns:
	if (ns)
		netns_free(ns);
out_outer:
	bpf_svc_classifier__destroy(outer);
out_inner:
	bpf_svc_classifier__destroy(inner);
}

void test_svc_classifier(void)
{
	if (test__start_subtest("attach"))
		test_attach();
	if (test__start_subtest("netns"))
		test_netns();
}
