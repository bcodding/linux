// SPDX-License-Identifier: GPL-2.0-only
/*
 * BPF struct_ops classification of accepted RPC service transports.
 */

#include <linux/bpf.h>
#include <linux/bpf_verifier.h>
#include <linux/btf.h>
#include <linux/nsproxy.h>
#include <linux/sunrpc/svc.h>
#include <linux/sunrpc/svc_xprt.h>

#include "netns.h"

/* Orders attach, detach and replacement against namespace exit. */
static DEFINE_SPINLOCK(svc_classifier_lock);

/**
 * svc_classify - ask the namespace's classifier for a transport's class
 * @xprt: an accepted transport, peer and local addresses set
 *
 * Return: an SVC_CLASS_* value; %SVC_CLASS_NONE when no classifier is
 * attached in the transport's network namespace.
 */
u32 svc_classify(const struct svc_xprt *xprt)
{
	struct sunrpc_net *sn = net_generic(xprt->xpt_net, sunrpc_net_id);
	struct svc_classifier *c;
	u32 class = SVC_CLASS_NONE;

	rcu_read_lock();
	c = rcu_dereference(sn->svc_classifier);
	if (c)
		class = c->classify(xprt);
	rcu_read_unlock();
	return class;
}

/* Caller holds svc_classifier_lock; the static key is dropped after. */
static bool svc_classifier_detach(struct svc_classifier *c)
{
	struct sunrpc_net *sn;

	if (!c->net)
		return false;
	sn = net_generic(c->net, sunrpc_net_id);
	RCU_INIT_POINTER(sn->svc_classifier, NULL);
	c->net = NULL;
	return true;
}

/**
 * svc_classifier_exit_net - forget the classifier of a dying namespace
 * @net: the network namespace being torn down
 *
 * The attached link, if any, survives with nothing behind it.
 */
void svc_classifier_exit_net(struct net *net)
{
	struct sunrpc_net *sn = net_generic(net, sunrpc_net_id);
	struct svc_classifier *c;
	bool detached = false;

	spin_lock(&svc_classifier_lock);
	c = rcu_dereference_protected(sn->svc_classifier,
				      lockdep_is_held(&svc_classifier_lock));
	if (c)
		detached = svc_classifier_detach(c);
	spin_unlock(&svc_classifier_lock);
	if (detached)
		static_branch_dec(&svc_classify_key);
}

static int svc_classifier_reg(void *kdata, struct bpf_link *link)
{
	struct svc_classifier *c = kdata;
	struct net *net = current->nsproxy->net_ns;
	struct sunrpc_net *sn = net_generic(net, sunrpc_net_id);
	int err = 0;

	if (!link)
		return -EOPNOTSUPP;

	spin_lock(&svc_classifier_lock);
	/* one namespace per classifier, one classifier per namespace */
	if (c->net || rcu_access_pointer(sn->svc_classifier)) {
		err = -EBUSY;
	} else {
		c->net = net;
		rcu_assign_pointer(sn->svc_classifier, c);
	}
	spin_unlock(&svc_classifier_lock);
	if (!err)
		static_branch_inc(&svc_classify_key);
	return err;
}

static void svc_classifier_unreg(void *kdata, struct bpf_link *link)
{
	bool detached;

	spin_lock(&svc_classifier_lock);
	detached = svc_classifier_detach(kdata);
	spin_unlock(&svc_classifier_lock);
	if (detached)
		static_branch_dec(&svc_classify_key);
	synchronize_rcu();
}

static int svc_classifier_update(void *kdata, void *old_kdata,
				 struct bpf_link *link)
{
	struct svc_classifier *c = kdata, *old = old_kdata;
	struct sunrpc_net *sn;
	int err = 0;

	if (c == old)
		return 0;

	spin_lock(&svc_classifier_lock);
	if (c->net) {
		err = -EBUSY;
	} else if (!old->net) {
		err = -ENOENT;
	} else {
		c->net = old->net;
		old->net = NULL;
		sn = net_generic(c->net, sunrpc_net_id);
		rcu_assign_pointer(sn->svc_classifier, c);
	}
	spin_unlock(&svc_classifier_lock);
	if (!err)
		synchronize_rcu();
	return err;
}

static int svc_classifier_validate(void *kdata)
{
	struct svc_classifier *c = kdata;

	return c->classify ? 0 : -EINVAL;
}

/* classify() runs under rcu_read_lock() */
static int svc_classifier_check_member(const struct btf_type *t,
				       const struct btf_member *member,
				       const struct bpf_prog *prog)
{
	return prog->sleepable ? -EINVAL : 0;
}

static int svc_classifier_init_member(const struct btf_type *t,
				      const struct btf_member *member,
				      void *kdata, const void *udata)
{
	const struct svc_classifier *uc = udata;
	struct svc_classifier *kc = kdata;
	u32 moff = __btf_member_bit_offset(t, member) / 8;

	if (moff == offsetof(struct svc_classifier, name)) {
		if (bpf_obj_name_cpy(kc->name, uc->name, sizeof(uc->name)) <= 0)
			return -EINVAL;
		return 1;
	}
	return 0;
}

static int svc_classifier_init(struct btf *btf)
{
	return 0;
}

static u32 __svc_classifier_stub_classify(const struct svc_xprt *xprt)
{
	return SVC_CLASS_NONE;
}

static struct svc_classifier __svc_classifier_stubs = {
	.classify	= __svc_classifier_stub_classify,
};

static const struct bpf_func_proto *
svc_classifier_func_proto(enum bpf_func_id func_id, const struct bpf_prog *prog)
{
	return bpf_base_func_proto(func_id, prog);
}

static const struct bpf_verifier_ops svc_classifier_verifier_ops = {
	.get_func_proto		= svc_classifier_func_proto,
	.is_valid_access	= bpf_tracing_btf_ctx_access,
};

static struct bpf_struct_ops bpf_svc_classifier_ops = {
	.verifier_ops	= &svc_classifier_verifier_ops,
	.init		= svc_classifier_init,
	.check_member	= svc_classifier_check_member,
	.init_member	= svc_classifier_init_member,
	.reg		= svc_classifier_reg,
	.unreg		= svc_classifier_unreg,
	.update		= svc_classifier_update,
	.validate	= svc_classifier_validate,
	.cfi_stubs	= &__svc_classifier_stubs,
	.name		= "svc_classifier",
	.owner		= THIS_MODULE,
};

int __init svc_classifier_init_module(void)
{
	return register_bpf_struct_ops(&bpf_svc_classifier_ops, svc_classifier);
}
