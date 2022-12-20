// SPDX-License-Identifier: GPL-2.0-or-later
/*
 * Copyright (C) 2021-2022 Red Hat, Inc. All Rights Reserved.
 * Written by Benjamin Coddington (bcodding@redhat.com)
 *
 * Author: Chuck Lever <chuck.lever@oracle.com>
 * Copyright (c) 2021, Oracle and/or its affiliates.
 *
 */

#include <linux/inet.h>
#include <linux/net.h>
#include <linux/file.h>
#include <linux/key-type.h>
#include <linux/siphash.h>
#include <keys/user-type.h>
#include <keys/request_key_auth-type.h>
#include <net/sock.h>
#include <net/tls_keys.h>
#include <uapi/linux/tls.h>

DEFINE_XARRAY(sfd_auth_array);
static siphash_key_t sfd_auth_ptr_key;

/**
 * tls_socket_fd_request_key() - handle request_key() for
 * key_type_tls_socket_fd.
 * @authkey: The authorization key for the request
 * @aux: auxiliary data - unused
 *
 * Look up a saved struct file * from the sfd_auth_array using the
 * callout_info token.  If found, install the file in the calling process'
 * file table, and instantiate the key with a payload of the fd number of
 * the installed file.
 */
int tls_socket_fd_request_key(struct key *authkey, void *aux)
{
	int ret = -ENOKEY;
	char *callout;
	size_t callout_len;
	struct file *socket_file;
	unsigned long file_ptr_hash;
	struct key *socket_fd_key;
	struct request_key_auth *rka;

	rka = get_request_key_auth(authkey);
	callout = rka->callout_info;
	callout_len = rka->callout_len;
	socket_fd_key = rka->target_key;

	/* The request_key() syscall uses kmemdup(,strlen(),) to copy the
	 * callout string, so we lose the nul-termination.  Send a patch, meantime:
	 */
	callout = kmemdup_nul(rka->callout_info, rka->callout_len, GFP_NOFS);
	ret = kstrtoul(callout, 16, &file_ptr_hash);

	socket_file = xa_load(&sfd_auth_array, file_ptr_hash);
	if (!socket_file) {
		ret = -ENOKEY;
		goto out;
	}

	/* should we pass O_CLOEXEC: ? */
	ret = receive_fd(socket_file, 0);
	if (ret > 0)
		ret = key_instantiate_and_link(socket_fd_key, &ret, sizeof(ret),
										rka->dest_keyring, authkey);
out:
	complete_request_key(authkey, ret);
	kfree(callout);
	return ret;
}

/* tls_session key type are serviced through user-space request-key() */
struct key_type key_type_tls_session = {
	.name			= "tls_session",
	.instantiate	= generic_key_instantiate,
};

/* tls_socket_fd key types install socket fd on userspace processes */
struct key_type key_type_tls_socket_fd = {
	.name		= "tls_socket_fd",
	.preparse	= user_preparse,
	.free_preparse	= user_free_preparse,
	.read		= user_read,
	.request_key = &tls_socket_fd_request_key,
	.instantiate = generic_key_instantiate,
};

static inline unsigned long tls_ptr_hash(const void *ptr)
{
#ifdef CONFIG_64BIT
	return (unsigned long)siphash_1u64((u64)ptr, &sfd_auth_ptr_key);
#else
	return (unsigned long)siphash_1u32((u32)ptr, &sfd_auth_ptr_key);
#endif
}

/**
 * tls_key_client_hello_anon - start a TLS handshake via a user mode helper
 * @socket: connected socket on which to perform the handshake
 * @peername: name of the remote peer
 * @priorities: GnuTLS TLS priorities string
 *
 * Given a socket with initialized socket->file, stash the file pointer in
 * the sfd_auth_array, and use request_key() for a tls_session key to allow
 * the keys infrastructure to materialize a process that can:
 *
 * 	- use the passed token to receive the socket_fd (via tls_socket_fd)
 * 	- perform a TLS handshake on that socket
 * 	- instantiate the tls_session key so we can continue
 *
 * Return values:
 *   %0: Success
 *   %-ENOENT: No user agent is available
 *   %-ENOMEM: Memory allocation failed
 */
int tls_keys_client_hello_anon(struct socket *socket,
		const char *peername, const char *priorities)
{
	struct key *tls_key;
	struct tls_keys_tls_session_info *info;
	unsigned long file_ptr_hash;
	int socket_fd, err = 0;
	char key_desc[73];

	/* we have socket->file already from xs_create_sock */
	socket_fd = get_unused_fd_flags(O_CLOEXEC);
	if (socket_fd < 0)
		return socket_fd;

	fd_install(socket_fd, get_file(socket->file));

	file_ptr_hash = tls_ptr_hash(socket->file);

	info = kzalloc(sizeof(*info), GFP_NOFS);
	if (!info)
		return -ENOMEM;

	if (!peername || strlen(peername) == 0)
		return -EINVAL;

	strncpy(info->peername, peername, sizeof(info->peername));

	if (priorities)
		strncpy(info->priorities, priorities, sizeof(info->priorities));

	info->operation = TLSK_OP_CLIENTHELLO;
	info->operation_arg = TLSH_TYPE_CLIENTHELLO_ANON;

	/* When userspace calls request_key() for the socket's fd, it can only
	 * send a "const char *" as callout info.  Let's just do the conversion
	 * for the socket_token here.
	 */
	snprintf(info->socket_token, sizeof(info->socket_token), "%lx", file_ptr_hash);

	xa_store(&sfd_auth_array, file_ptr_hash, socket->file, GFP_NOFS);

	/* We want a non-colliding key description: */
	snprintf(key_desc, 73, "%lx:%s", file_ptr_hash & 0xffffffff, peername);

	tls_key = request_key_with_auxdata(&key_type_tls_session, key_desc,
						NULL, info, sizeof(*info), NULL);
	if (IS_ERR(tls_key))
		err = PTR_ERR(tls_key);
	else
		key_put(tls_key);

	xa_erase(&sfd_auth_array, file_ptr_hash);

	if (err)
		sock_orphan(socket->sk);

	kfree(info);
	return err;
}
EXPORT_SYMBOL_GPL(tls_keys_client_hello_anon);

int __init tls_keys_init(void)
{
	int err = 0;

	/* uniquify our tls_ptr_hash function */
	get_random_bytes(&sfd_auth_ptr_key, sizeof(sfd_auth_ptr_key));

	err = register_key_type(&key_type_tls_session);
	if (err < 0)
		return err;

	err = register_key_type(&key_type_tls_socket_fd);
	if (err < 0)
		unregister_key_type(&key_type_tls_session);

	return err;
}

int __exit tls_keys_exit(void)
{
	unregister_key_type(&key_type_tls_socket_fd);
	unregister_key_type(&key_type_tls_session);
	return 0;
}
