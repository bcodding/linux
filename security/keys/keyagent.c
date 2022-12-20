// SPDX-License-Identifier: GPL-2.0-or-later
/* Key Agent handling
 *
 * Copyright (C) 2022 Red Hat Inc. All Rights Reserved.
 * Written by Benjamin Coddington (bcodding@redhat.com)
 */

#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/key.h>
#include <linux/key-type.h>
#include <linux/sched/signal.h>
#include <linux/sched/task.h>

#include <keys/user-type.h>
#include <keys/request_key_auth-type.h>

/*
 * Keyagent key payload.
 */
struct keyagent {
	struct pid *pid;
	int sig;
};

struct key_type key_type_keyagent;

/*
 * Given a key representing a keyagent and a target_key to construct, link
 * the the authkey into the keyagent's process_keyring and signal the
 * keyagent to construct the target_key.
 */
static int keyagent_signal(struct key *ka_key, struct key *target_key,
							struct key *authkey)
{
	struct keyagent *ka = ka_key->payload.data[0];
	struct task_struct *task;
	const struct cred *cred;
	kernel_siginfo_t info = {
		.si_code = SI_KEYAGENT,
		.si_signo = ka->sig,
		.si_int = target_key->serial,
	};
	int ret = -ENOKEY;

	task = get_pid_task(ka->pid, PIDTYPE_PID);
	/* If the task is gone, should we revoke the keyagent key? */
	if (!task) {
		key_revoke(ka_key);
		goto out;
	}

	/* We're expecting valid keyagents to have a process keyring,
	 * if not, should we warn? */
	cred = get_cred(task->cred);
	if (!cred->process_keyring)
		goto out_nolink;

	/* Link the autkey to the keyagent's process_keyring */
	ret = key_link(cred->process_keyring, authkey);
	if (ret < 0)
		goto out_nolink;

	ret = send_sig_info(ka->sig, &info, task);

out_nolink:
	put_cred(cred);
	put_task_struct(task);
out:
	return ret;
}

/*
 * Search the calling process' keyrings for a keyagent that
 * matches the requested key type.  If found, signal the keyagent
 * to construct and link the key, else return -ENOKEY.
 */
int keyagent_request_key(struct key *authkey, void *aux)
{
	struct key *ka_key, *target_key;
	struct request_key_auth *rka;
	key_ref_t ka_ref;
	const struct cred *cred = current_cred();
	int ret;

	if (!cred->session_keyring)
		return -ENOKEY;

	/* We must be careful not to touch authkey and aux if
	 * returning -ENOKEY, since it will be reused.   */
	rka = get_request_key_auth(authkey);
	target_key = rka->target_key;

	/* Does the calling process have a keyagent in its session keyring? */
	ka_ref = keyring_search(
					make_key_ref(cred->session_keyring, 1),
					&key_type_keyagent,
					target_key->type->name, false);

	if (IS_ERR(ka_ref))
		return -ENOKEY;

	/* We found a keyagent, let's call out to it. */
	ka_key = key_ref_to_ptr(ka_ref);
	ret = keyagent_signal(ka_key, target_key, authkey);
	key_put(key_ref_to_ptr(ka_ref));

	return ret;
}

/*
 * Instantiate takes a reference to the current task's struct pid
 * and the requested realtime signal number.
 */
static int
keyagent_instantiate(struct key *key, struct key_preparsed_payload *prep)
{
	struct keyagent *ka;
	__be16 sig = *(__be16 *)prep->data;

	/* Only real-time signals numbers allowed */
	if (sig < SIGRTMIN || sig > SIGRTMAX)
		return -EINVAL;

	ka = kzalloc(sizeof(struct keyagent), GFP_KERNEL);
	if (!ka)
		return -ENOMEM;

	ka->pid = get_task_pid(current, PIDTYPE_PID);
	ka->sig = sig;
	key->payload.data[0] = ka;

	return 0;
}

static void keyagent_destroy(struct key *key)
{
	struct keyagent *ka = key->payload.data[0];

	put_pid(ka->pid);
	kfree(ka);
}

/*
 * keyagent keys represent userland processes waiting on signals from the
 * kernel to respond to request-key callouts
 */
struct key_type key_type_keyagent = {
	.name			= "keyagent",
	.instantiate	= keyagent_instantiate,
	.def_datalen	= sizeof(struct keyagent),
	.destroy		= keyagent_destroy,
	.describe		= user_describe,
};

static int __init keyagent_init(void)
{
	return register_key_type(&key_type_keyagent);
}

late_initcall(keyagent_init);
