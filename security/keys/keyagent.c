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

#include <keys/user-type.h>

/*
 * Keyagent key payload.
 */
struct keyagent {
	struct pid *pid;
	int sig;
};

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
