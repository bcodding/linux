// SPDX-License-Identifier: GPL-2.0-only
/*
 * PF_TLSH protocol family socket handler.
 *
 * Author: Chuck Lever <chuck.lever@oracle.com>
 *
 * Copyright (c) 2021, Oracle and/or its affiliates.
 *
 * When a kernel TLS consumer wants to establish a TLS session, it
 * makes an AF_TLSH Listener ready. When user space accepts on that
 * listener, the kernel fabricates a user space socket endpoint on
 * which a user space TLS library can perform the TLS handshake.
 *
 * Closing the user space descriptor signals to the kernel that the
 * library handshake process is complete. If the library has managed
 * to initialize the socket's TLS crypto_info, the kernel marks the
 * handshake as a success.
 */

/*
 * Socket reference counting
 *  A: listener socket initial reference
 *  B: listener socket on the global listener list
 *  C: listener socket while a ready AF_INET(6) socket is enqueued
 *  D: listener socket while its accept queue is drained
 *
 *  I: ready AF_INET(6) socket waiting on a listener's accept queue
 *  J: ready AF_INET(6) socket with a consumer waiting for a completion callback
 */

#include <linux/types.h>
#include <linux/socket.h>
#include <linux/in.h>
#include <linux/kernel.h>
#include <linux/poll.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/skbuff.h>
#include <linux/inet.h>

#include <net/ip.h>
#include <net/ipv6.h>
#include <net/tcp.h>
#include <net/protocol.h>
#include <net/sock.h>
#include <net/inet_common.h>
#include <net/net_namespace.h>
#include <net/tls.h>
#include <net/tlsh.h>

#include "tls.h"
#include "trace.h"


struct tlsh_sock_info {
	enum tlsh_hs_type	tsi_handshake_type;

	void			(*tsi_handshake_done)(void *data, int status);
	void			*tsi_handshake_data;
	char			*tsi_tls_priorities;
	key_serial_t		tsi_peerid;
	key_serial_t		tsi_certificate;
	key_serial_t		tsi_privkey;

	struct socket_wq	*tsi_saved_wq;
	struct socket		*tsi_saved_socket;
	kuid_t			tsi_saved_uid;
};

static void tlsh_sock_info_destroy(struct tlsh_sock_info *info)
{
	kfree_sensitive(info->tsi_tls_priorities);
	kfree_sensitive(info);
}

static DEFINE_RWLOCK(tlsh_listener_lock);
static HLIST_HEAD(tlsh_listeners);

static void tlsh_register_listener(struct sock *sk)
{
	write_lock_bh(&tlsh_listener_lock);
	sk_add_node(sk, &tlsh_listeners);	/* Ref: B */
	write_unlock_bh(&tlsh_listener_lock);
}

static void tlsh_unregister_listener(struct sock *sk)
{
	write_lock_bh(&tlsh_listener_lock);
	sk_del_node_init(sk);			/* Ref: B */
	write_unlock_bh(&tlsh_listener_lock);
}

/**
 * tlsh_find_listener - find listener that matches an incoming connection
 * @net: net namespace to match
 * @family: address family to match
 *
 * Return values:
 *   On success, address of a listening AF_TLSH socket
 *   %NULL: No matching listener found
 */
static struct sock *tlsh_find_listener(struct net *net, unsigned short family)
{
	struct sock *listener;

	read_lock(&tlsh_listener_lock);

	sk_for_each(listener, &tlsh_listeners) {
		if (sock_net(listener) != net)
			continue;
		if (tlsh_sk(listener)->th_bind_family != AF_UNSPEC &&
		    tlsh_sk(listener)->th_bind_family != family)
			continue;

		sock_hold(listener);	/* Ref: C */
		goto out;
	}
	listener = NULL;

out:
	read_unlock(&tlsh_listener_lock);
	return listener;
}

/**
 * tlsh_accept_enqueue - add a socket to a listener's accept_q
 * @listener: listening socket
 * @sk: socket to enqueue on @listener
 *
 * Return values:
 *   On success, returns 0
 *   %-ENOMEM: Memory for skbs has been exhausted
 */
static int tlsh_accept_enqueue(struct sock *listener, struct sock *sk)
{
	struct sk_buff *skb;

	skb = alloc_skb(0, GFP_KERNEL);
	if (!skb)
		return -ENOMEM;

	sock_hold(sk);	/* Ref: I */
	skb->sk = sk;
	skb_queue_tail(&listener->sk_receive_queue, skb);
	sk_acceptq_added(listener);
	listener->sk_data_ready(listener);
	return 0;
}

/**
 * tlsh_accept_dequeue - remove a socket from a listener's accept_q
 * @listener: listener socket to check
 *
 * Caller guarantees that @listener won't disappear.
 *
 * Return values:
 *   On success, return a TCP socket waiting for TLS service
 *   %NULL: No sockets on the accept queue
 */
static struct sock *tlsh_accept_dequeue(struct sock *listener)
{
	struct sk_buff *skb;
	struct sock *sk;

	skb = skb_dequeue(&listener->sk_receive_queue);
	if (!skb)
		return NULL;
	sk_acceptq_removed(listener);
	sock_put(listener);	/* Ref: C */

	sk = skb->sk;
	skb->sk = NULL;
	kfree_skb(skb);
	sock_put(sk);	/* Ref: I */
	return sk;
}

static void tlsh_sock_save(struct sock *sk,
			   struct tlsh_sock_info *info)
{
	sock_hold(sk);	/* Ref: J */

	write_lock_bh(&sk->sk_callback_lock);
	info->tsi_saved_wq = sk->sk_wq_raw;
	info->tsi_saved_socket = sk->sk_socket;
	info->tsi_saved_uid = sk->sk_uid;
	sk->sk_tlsh_priv = info;
	write_unlock_bh(&sk->sk_callback_lock);
}

static void tlsh_sock_clear(struct sock *sk)
{
	struct tlsh_sock_info *info = sk->sk_tlsh_priv;

	write_lock_bh(&sk->sk_callback_lock);
	sk->sk_tlsh_priv = NULL;
	write_unlock_bh(&sk->sk_callback_lock);
	tlsh_sock_info_destroy(info);
	sock_put(sk);	/* Ref: J (err) */
}

static void tlsh_sock_restore_locked(struct sock *sk)
{
	struct tlsh_sock_info *info = sk->sk_tlsh_priv;

	sk->sk_wq_raw = info->tsi_saved_wq;
	sk->sk_socket = info->tsi_saved_socket;
	sk->sk_uid = info->tsi_saved_uid;
	sk->sk_tlsh_priv = NULL;
}

static bool tlsh_crypto_info_initialized(struct sock *sk)
{
	struct tls_context *ctx = tls_get_ctx(sk);

	return ctx != NULL &&
		TLS_CRYPTO_INFO_READY(&ctx->crypto_send.info) &&
		TLS_CRYPTO_INFO_READY(&ctx->crypto_recv.info);
}

/**
 * tlsh_handshake_done - call the registered "done" callback for @sk.
 * @sk: socket that was requesting a handshake
 *
 * Return values:
 *   %true:  Handshake callback was called
 *   %false: No handshake callback was set, no-op
 */
static bool tlsh_handshake_done(struct sock *sk)
{
	struct tlsh_sock_info *info;
	void (*done)(void *data, int status);
	void *data;

	write_lock_bh(&sk->sk_callback_lock);
	info = sk->sk_tlsh_priv;
	if (info) {
		done = info->tsi_handshake_done;
		data = info->tsi_handshake_data;

		tlsh_sock_restore_locked(sk);

		if (tlsh_crypto_info_initialized(sk)) {
			done(data, 0);
		} else {
			done(data, -EACCES);
		}
	}
	write_unlock_bh(&sk->sk_callback_lock);

	if (info) {
		tlsh_sock_info_destroy(info);
		sock_put(sk);	/* Ref: J */
		return true;
	}
	return false;
}

/**
 * tlsh_accept_drain - clean up children queued for accept
 * @listener: listener socket to drain
 *
 */
static void tlsh_accept_drain(struct sock *listener)
{
	struct sock *sk;

	while ((sk = tlsh_accept_dequeue(listener)))
		tlsh_handshake_done(sk);
}

/**
 * tlsh_release - free an AF_TLSH socket
 * @sock: socket to release
 *
 * Return values:
 *   %0: success
 */
static int tlsh_release(struct socket *sock)
{
	struct sock *sk = sock->sk;
	struct tlsh_sock *tsk = tlsh_sk(sk);

	if (!sk)
		return 0;

	switch (sk->sk_family) {
	case AF_INET:
		if (!tlsh_handshake_done(sk))
			return inet_release(sock);
		return 0;
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		if (!tlsh_handshake_done(sk))
			return inet6_release(sock);
		return 0;
#endif
	case AF_TLSH:
		break;
	default:
		return 0;
	}

	sock_hold(sk);	/* Ref: D */
	sock_orphan(sk);
	lock_sock(sk);

	tlsh_unregister_listener(sk);
	tlsh_accept_drain(sk);

	sk->sk_state = TCP_CLOSE;
	sk->sk_shutdown |= SEND_SHUTDOWN;
	sk->sk_state_change(sk);

	tsk->th_bind_family = AF_UNSPEC;
	sock->sk = NULL;
	release_sock(sk);
	sock_put(sk);	/* Ref: D */

	sock_put(sk);	/* Ref: A */
	return 0;
}

/**
 * tlsh_bind - bind a name to an AF_TLSH socket
 * @sock: socket to be bound
 * @uaddr: address to bind to
 * @addrlen: length in bytes of @uaddr
 *
 * Binding an AF_TLSH socket defines the family of addresses that
 * are able to be accept(2)'d. So, AF_INET for ipv4, AF_INET6 for
 * ipv6.
 *
 * Return values:
 *   %0: binding was successful.
 *   %-EPERM: Caller not privileged
 *   %-EINVAL: Family of @sock or @uaddr not supported
 */
static int tlsh_bind(struct socket *sock, struct sockaddr *uaddr, int addrlen)
{
	struct sock *listener, *sk = sock->sk;
	struct tlsh_sock *tsk = tlsh_sk(sk);

	if (!capable(CAP_NET_BIND_SERVICE))
		return -EPERM;

	switch (uaddr->sa_family) {
	case AF_INET:
		if (addrlen != sizeof(struct sockaddr_in))
			return -EINVAL;
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		if (addrlen != sizeof(struct sockaddr_in6))
			return -EINVAL;
		break;
#endif
	default:
		return -EAFNOSUPPORT;
	}

	listener = tlsh_find_listener(sock_net(sk), uaddr->sa_family);
	if (listener) {
		sock_put(listener);	/* Ref: C */
		return -EADDRINUSE;
	}

	tsk->th_bind_family = uaddr->sa_family;
	return 0;
}

/**
 * tlsh_accept - return a connection waiting for a TLS handshake
 * @listener: listener socket which connection requests arrive on
 * @newsock: socket to move incoming connection to
 * @flags: SOCK_NONBLOCK and/or SOCK_CLOEXEC
 * @kern: "boolean": 1 for kernel-internal sockets
 *
 * Return values:
 *   %0: @newsock has been initialized.
 *   %-EPERM: caller is not privileged
 */
static int tlsh_accept(struct socket *listener, struct socket *newsock, int flags,
		       bool kern)
{
	struct sock *sk = listener->sk, *newsk;
	DECLARE_WAITQUEUE(wait, current);
	long timeo;
	int rc;

	rc = -EPERM;
	if (!capable(CAP_NET_BIND_SERVICE))
		goto out;

	lock_sock(sk);

	if (sk->sk_state != TCP_LISTEN) {
		rc = -EBADF;
		goto out_release;
	}

	timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);

	rc = 0;
	add_wait_queue_exclusive(sk_sleep(sk), &wait);
	while (!(newsk = tlsh_accept_dequeue(sk))) {
		set_current_state(TASK_INTERRUPTIBLE);
		if (!timeo) {
			rc = -EAGAIN;
			break;
		}
		release_sock(sk);

		timeo = schedule_timeout(timeo);

		lock_sock(sk);
		if (sk->sk_state != TCP_LISTEN) {
			rc = -EBADF;
			break;
		}
		if (signal_pending(current)) {
			rc = sock_intr_errno(timeo);
			break;
		}
	}
	set_current_state(TASK_RUNNING);
	remove_wait_queue(sk_sleep(sk), &wait);
	if (rc) {
		tlsh_handshake_done(sk);
		goto out_release;
	}

	sock_graft(newsk, newsock);

out_release:
	release_sock(sk);
out:
	return rc;
}

/**
 * tlsh_getname - retrieve src/dst address information from an AF_TLSH socket
 * @sock: socket to query
 * @uaddr: buffer to fill in
 * @peer: value indicates which address to retrieve
 *
 * Return values:
 *   On success, a positive length of the address in @uaddr
 *   On error, a negative errno
 */
static int tlsh_getname(struct socket *sock, struct sockaddr *uaddr, int peer)
{
	struct sock *sk = sock->sk;

	switch (sk->sk_family) {
	case AF_INET:
		return inet_getname(sock, uaddr, peer);
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		return inet6_getname(sock, uaddr, peer);
#endif
	default:
		return -EOPNOTSUPP;
	}
}

/**
 * tlsh_poll - check for data ready on an AF_TLSH socket
 * @file: file to check for work
 * @sock: socket associated with @file
 * @wait: poll table
 *
 * Return values:
 *    A mask of flags indicating what type of I/O is ready
 */
static __poll_t tlsh_poll(struct file *file, struct socket *sock,
			  poll_table *wait)
{
	struct sock *sk = sock->sk;
	__poll_t mask;

	sock_poll_wait(file, sock, wait);

	mask = 0;

	if (sk->sk_state == TCP_LISTEN) {
		if (!skb_queue_empty_lockless(&sk->sk_receive_queue))
			mask |= EPOLLIN | EPOLLRDNORM;
		if (sk_is_readable(sk))
			mask |= EPOLLIN | EPOLLRDNORM;
		return mask;
	}

	if (sk->sk_shutdown == SHUTDOWN_MASK || sk->sk_state == TCP_CLOSE)
		mask |= EPOLLHUP;
	if (sk->sk_shutdown & RCV_SHUTDOWN)
		mask |= EPOLLIN | EPOLLRDNORM | EPOLLRDHUP;

	if (!skb_queue_empty_lockless(&sk->sk_receive_queue))
		mask |= EPOLLIN | EPOLLRDNORM;
	if (sk_is_readable(sk))
		mask |= EPOLLIN | EPOLLRDNORM;

	/* This barrier is coupled with smp_wmb() in tcp_reset() */
	smp_rmb();
	if (sk->sk_err || !skb_queue_empty_lockless(&sk->sk_error_queue))
		mask |= EPOLLERR;

	return mask;
}

/**
 * tlsh_listen - move an AF_TLSH socket into a listening state
 * @sock: socket to transition to listening state
 * @backlog: size of backlog queue
 *
 * Return values:
 *   %0: @sock is now in a listening state
 *   %-EPERM: caller is not privileged
 *   %-EOPNOTSUPP: @sock is not of a type that supports the listen() operation
 */
static int tlsh_listen(struct socket *sock, int backlog)
{
	struct sock *sk = sock->sk;
	unsigned char old_state;
	int rc;

	if (!capable(CAP_NET_BIND_SERVICE))
		return -EPERM;

	lock_sock(sk);

	rc = -EOPNOTSUPP;
	if (sock->state != SS_UNCONNECTED || sock->type != SOCK_STREAM)
		goto out;
	old_state = sk->sk_state;
	if (!((1 << old_state) & (TCPF_CLOSE | TCPF_LISTEN)))
		goto out;

	sk->sk_max_ack_backlog = backlog;
	sk->sk_state = TCP_LISTEN;
	tlsh_register_listener(sk);

	rc = 0;

out:
	release_sock(sk);
	return rc;
}

/**
 * tlsh_shutdown - Shutdown an AF_TLSH socket
 * @sock: socket to shut down
 * @how: mask
 *
 * Return values:
 *   %0: Success
 *   %-EINVAL: @sock is not of a type that supports a shutdown
 */
static int tlsh_shutdown(struct socket *sock, int how)
{
	struct sock *sk = sock->sk;

	switch (sk->sk_family) {
	case AF_INET:
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		break;
#endif
	default:
		return -EINVAL;
	}

	return inet_shutdown(sock, how);
}

/**
 * tlsh_setsockopt - Set a socket option on an AF_TLSH socket
 * @sock: socket to act upon
 * @level: which network layer to act upon
 * @optname: which option to set
 * @optval: new value to set
 * @optlen: the size of the new value, in bytes
 *
 * Return values:
 *   %0: Success
 *   %-ENOPROTOOPT: The option is unknown at the level indicated.
 */
static int tlsh_setsockopt(struct socket *sock, int level, int optname,
			   sockptr_t optval, unsigned int optlen)
{
	struct sock *sk = sock->sk;

	switch (sk->sk_family) {
	case AF_INET:
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		break;
#endif
	default:
		return -ENOPROTOOPT;
	}

	return sock_common_setsockopt(sock, level, optname, optval, optlen);
}

static int tlsh_getsockopt_priorities(struct sock *sk, char __user *optval,
				      int __user *optlen)
{
	struct tlsh_sock_info *info;
	int outlen, len, ret;
	const char *val;

	if (get_user(len, optlen))
		return -EFAULT;
	if (!optval)
		return -EINVAL;

	ret = 0;

	sock_hold(sk);
	write_lock_bh(&sk->sk_callback_lock);

	info = sk->sk_tlsh_priv;
	if (info) {
		val = info->tsi_tls_priorities;
	} else {
		write_unlock_bh(&sk->sk_callback_lock);
		ret = -EBUSY;
		goto out_put;
	}

	write_unlock_bh(&sk->sk_callback_lock);

	if (val) {
		outlen = strlen(val);
		if (len < outlen)
			ret = -EINVAL;
		else if (copy_to_user(optval, val, outlen))
			ret = -EFAULT;
	} else {
		outlen = 0;
	}


	if (put_user(outlen, optlen))
		ret = -EFAULT;

out_put:
	sock_put(sk);
	return ret;
}

static int tlsh_getsockopt_peerid(struct sock *sk, char __user *optval,
				  int __user *optlen)
{
	struct tlsh_sock_info *info;
	int len, val;

	if (get_user(len, optlen))
		return -EFAULT;
	if (!optval || (len < sizeof(key_serial_t)))
		return -EINVAL;

	write_lock_bh(&sk->sk_callback_lock);
	info = sk->sk_tlsh_priv;
	if (info) {
		val = info->tsi_peerid;
	} else {
		write_unlock_bh(&sk->sk_callback_lock);
		return -EBUSY;
	}
	write_unlock_bh(&sk->sk_callback_lock);

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;
	return 0;
}

static int tlsh_getsockopt_type(struct sock *sk, char __user *optval,
				int __user *optlen)
{
	struct tlsh_sock_info *info;
	int len, val;

	if (get_user(len, optlen))
		return -EFAULT;
	if (!optval || (len < sizeof(key_serial_t)))
		return -EINVAL;

	write_lock_bh(&sk->sk_callback_lock);
	info = sk->sk_tlsh_priv;
	if (info) {
		val = info->tsi_handshake_type;
	} else {
		write_unlock_bh(&sk->sk_callback_lock);
		return -EBUSY;
	}
	write_unlock_bh(&sk->sk_callback_lock);

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;
	return 0;
}

static int tlsh_getsockopt_cert(struct sock *sk, char __user *optval,
				int __user *optlen)
{
	struct tlsh_sock_info *info;
	int len, val;

	if (get_user(len, optlen))
		return -EFAULT;
	if (!optval || (len < sizeof(key_serial_t)))
		return -EINVAL;

	write_lock_bh(&sk->sk_callback_lock);
	info = sk->sk_tlsh_priv;
	if (info) {
		val = info->tsi_certificate;
	} else {
		write_unlock_bh(&sk->sk_callback_lock);
		return -EBUSY;
	}
	write_unlock_bh(&sk->sk_callback_lock);

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;
	return 0;
}

static int tlsh_getsockopt_privkey(struct sock *sk, char __user *optval,
				   int __user *optlen)
{
	struct tlsh_sock_info *info;
	int len, val;

	if (get_user(len, optlen))
		return -EFAULT;
	if (!optval || (len < sizeof(key_serial_t)))
		return -EINVAL;

	write_lock_bh(&sk->sk_callback_lock);
	info = sk->sk_tlsh_priv;
	if (info) {
		val = info->tsi_privkey;
	} else {
		write_unlock_bh(&sk->sk_callback_lock);
		return -EBUSY;
	}
	write_unlock_bh(&sk->sk_callback_lock);

	if (put_user(len, optlen))
		return -EFAULT;
	if (copy_to_user(optval, &val, len))
		return -EFAULT;
	return 0;
}

/**
 * tlsh_getsockopt - Retrieve a socket option from an AF_TLSH socket
 * @sock: socket to act upon
 * @level: which network layer to act upon
 * @optname: which option to retrieve
 * @optval: a buffer into which to receive the option's value
 * @optlen: the size of the receive buffer, in bytes
 *
 * Return values:
 *   %0: Success
 *   %-ENOPROTOOPT: The option is unknown at the level indicated.
 *   %-EINVAL: Invalid argument
 *   %-EFAULT: Output memory not write-able
 *   %-EBUSY: Option value not available
 */
static int tlsh_getsockopt(struct socket *sock, int level, int optname,
			   char __user *optval, int __user *optlen)
{
	struct sock *sk = sock->sk;
	int ret;

	switch (sk->sk_family) {
	case AF_INET:
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		break;
#endif
	default:
		return -ENOPROTOOPT;
	}

	if (level != SOL_TLSH)
		return sock_common_getsockopt(sock, level, optname, optval, optlen);

	switch (optname) {
	case TLSH_PRIORITIES:
		ret = tlsh_getsockopt_priorities(sk, optval, optlen);
		break;
	case TLSH_PEERID:
		ret = tlsh_getsockopt_peerid(sk, optval, optlen);
		break;
	case TLSH_HANDSHAKE_TYPE:
		ret = tlsh_getsockopt_type(sk, optval, optlen);
		break;
	case TLSH_X509_CERTIFICATE:
		ret = tlsh_getsockopt_cert(sk, optval, optlen);
		break;
	case TLSH_X509_PRIVKEY:
		ret = tlsh_getsockopt_privkey(sk, optval, optlen);
		break;
	default:
		ret = -ENOPROTOOPT;
	}

	return ret;
}

/**
 * tlsh_sendmsg - Send a message on an AF_TLSH socket
 * @sock: socket to send on
 * @msg: message to send
 * @size: size of message, in bytes
 *
 * Return values:
 *   %0: Success
 *   %-EOPNOTSUPP: Address family does not support this operation
 */
static int tlsh_sendmsg(struct socket *sock, struct msghdr *msg, size_t size)
{
	struct sock *sk = sock->sk;

	switch (sk->sk_family) {
	case AF_INET:
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		break;
#endif
	default:
		return -EOPNOTSUPP;
	}

	if (unlikely(inet_send_prepare(sk)))
		return -EAGAIN;
	return sk->sk_prot->sendmsg(sk, msg, size);
}

/**
 * tlsh_recvmsg - Receive a message from an AF_TLSH socket
 * @sock: socket to receive from
 * @msg: buffer into which to receive
 * @size: size of buffer, in bytes
 * @flags: control settings
 *
 * Return values:
 *   %0: Success
 *   %-EOPNOTSUPP: Address family does not support this operation
 */
static int tlsh_recvmsg(struct socket *sock, struct msghdr *msg, size_t size,
			int flags)
{
	struct sock *sk = sock->sk;

	switch (sk->sk_family) {
	case AF_INET:
		break;
#if IS_ENABLED(CONFIG_IPV6)
	case AF_INET6:
		break;
#endif
	default:
		return -EOPNOTSUPP;
	}

	if (likely(!(flags & MSG_ERRQUEUE)))
		sock_rps_record_flow(sk);
	return sock_common_recvmsg(sock, msg, size, flags);
}

static const struct proto_ops tlsh_proto_ops = {
	.family		= PF_TLSH,
	.owner		= THIS_MODULE,

	.release	= tlsh_release,
	.bind		= tlsh_bind,
	.connect	= sock_no_connect,
	.socketpair	= sock_no_socketpair,
	.accept		= tlsh_accept,
	.getname	= tlsh_getname,
	.poll		= tlsh_poll,
	.ioctl		= sock_no_ioctl,
	.gettstamp	= sock_gettstamp,
	.listen		= tlsh_listen,
	.shutdown	= tlsh_shutdown,
	.setsockopt	= tlsh_setsockopt,
	.getsockopt	= tlsh_getsockopt,
	.sendmsg	= tlsh_sendmsg,
	.recvmsg	= tlsh_recvmsg,
	.mmap		= sock_no_mmap,
	.sendpage	= sock_no_sendpage,
};

static struct proto tlsh_prot = {
	.name			= "TLSH",
	.owner			= THIS_MODULE,
	.obj_size		= sizeof(struct tlsh_sock),
};

/**
 * tlsh_pf_create - create an AF_TLSH socket
 * @net: network namespace to own the new socket
 * @sock: socket to initialize
 * @protocol: IP protocol number (ignored)
 * @kern: "boolean": 1 for kernel-internal sockets
 *
 * Return values:
 *   %0: @sock was initialized, and module ref count incremented.
 *   Negative errno values indicate initialization failed.
 */
int tlsh_pf_create(struct net *net, struct socket *sock, int protocol, int kern)
{
	struct sock *sk;
	int rc;

	if (protocol != IPPROTO_TCP)
		return -EPROTONOSUPPORT;

	/* only stream sockets are supported */
	if (sock->type != SOCK_STREAM)
		return -ESOCKTNOSUPPORT;

	sock->state = SS_UNCONNECTED;
	sock->ops = &tlsh_proto_ops;

	/* Ref: A */
	sk = sk_alloc(net, PF_TLSH, GFP_KERNEL, &tlsh_prot, kern);
	if (!sk)
		return -ENOMEM;

	sock_init_data(sock, sk);
	if (sk->sk_prot->init) {
		rc = sk->sk_prot->init(sk);
		if (rc)
			goto err_sk_put;
	}

	tlsh_sk(sk)->th_bind_family = AF_UNSPEC;
	return 0;

err_sk_put:
	sock_orphan(sk);
	sk_free(sk);	/* Ref: A (err) */
	return rc;
}

/**
 * tls_client_hello_anon - request an anonymous TLS handshake on a socket
 * @sock: connected socket on which to perform the handshake
 * @done: function to call when the handshake has completed
 * @data: token to pass back to @done
 * @priorities: GnuTLS TLS priorities string
 *
 * Return values:
 *   %0: Handshake request enqueue; ->done will be called when complete
 *   %-ENOENT: No user agent is available
 *   %-ENOMEM: Memory allocation failed
 */
int tls_client_hello_anon(struct socket *sock, void (*done)(void *data, int status),
			  void *data, const char *priorities)
{
	struct sock *listener, *sk = sock->sk;
	struct tlsh_sock_info *info;
	int rc;

	listener = tlsh_find_listener(sock_net(sk), sk->sk_family);
	if (!listener)
		return -ENOENT;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		sock_put(listener);	/* Ref: C (err) */
		return -ENOMEM;
	}

	info->tsi_handshake_done = done;
	info->tsi_handshake_data = data;
	if (priorities && strlen(priorities)) {
		info->tsi_tls_priorities = kstrdup(priorities, GFP_KERNEL);
		if (!info->tsi_tls_priorities) {
			tlsh_sock_info_destroy(info);
			sock_put(listener);	/* Ref: C (err) */
			return -ENOMEM;
		}
	}
	info->tsi_peerid = TLSH_NO_PEERID;
	info->tsi_certificate = TLSH_NO_CERT;
	info->tsi_privkey = TLSH_NO_KEY;
	info->tsi_handshake_type = TLSH_TYPE_CLIENTHELLO_ANON;
	tlsh_sock_save(sk, info);

	rc = tlsh_accept_enqueue(listener, sk);
	if (rc) {
		tlsh_sock_clear(sk);
		sock_put(listener);	/* Ref: C (err) */
	}

	return rc;
}
EXPORT_SYMBOL_GPL(tls_client_hello_anon);

/**
 * tls_client_hello_x509 - request an x.509-based TLS handshake on a socket
 * @sock: connected socket on which to perform the handshake
 * @done: function to call when the handshake has completed
 * @data: token to pass back to @done
 * @priorities: GnuTLS TLS priorities string
 * @cert: serial number of key containing client's x.509 certificate
 * @privkey: serial number of key containing client's private key
 *
 * Return values:
 *   %0: Handshake request enqueue; ->done will be called when complete
 *   %-ENOENT: No user agent is available
 *   %-ENOMEM: Memory allocation failed
 */
int tls_client_hello_x509(struct socket *sock, void (*done)(void *data, int status),
			  void *data, const char *priorities,
			  key_serial_t cert, key_serial_t privkey)
{
	struct sock *listener, *sk = sock->sk;
	struct tlsh_sock_info *info;
	int rc;

	listener = tlsh_find_listener(sock_net(sk), sk->sk_family);
	if (!listener)
		return -ENOENT;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		sock_put(listener);	/* Ref: C (err) */
		return -ENOMEM;
	}

	info->tsi_handshake_done = done;
	info->tsi_handshake_data = data;
	if (priorities && strlen(priorities)) {
		info->tsi_tls_priorities = kstrdup(priorities, GFP_KERNEL);
		if (!info->tsi_tls_priorities) {
			tlsh_sock_info_destroy(info);
			sock_put(listener);	/* Ref: C (err) */
			return -ENOMEM;
		}
	}
	info->tsi_peerid = TLSH_NO_PEERID;
	info->tsi_certificate = cert;
	info->tsi_privkey = privkey;
	info->tsi_handshake_type = TLSH_TYPE_CLIENTHELLO_X509;
	tlsh_sock_save(sk, info);

	rc = tlsh_accept_enqueue(listener, sk);
	if (rc) {
		tlsh_sock_clear(sk);
		sock_put(listener);	/* Ref: C (err) */
	}

	return rc;
}
EXPORT_SYMBOL_GPL(tls_client_hello_x509);

/**
 * tls_client_hello_psk - request a PSK-based TLS handshake on a socket
 * @sock: connected socket on which to perform the handshake
 * @done: function to call when the handshake has completed
 * @data: token to pass back to @done
 * @priorities: GnuTLS TLS priorities string
 * @peerid: serial number of key containing TLS identity
 *
 * Return values:
 *   %0: Handshake request enqueue; ->done will be called when complete
 *   %-ENOENT: No user agent is available
 *   %-ENOMEM: Memory allocation failed
 */
int tls_client_hello_psk(struct socket *sock, void (*done)(void *data, int status),
			 void *data, const char *priorities, key_serial_t peerid)
{
	struct sock *listener, *sk = sock->sk;
	struct tlsh_sock_info *info;
	int rc;

	listener = tlsh_find_listener(sock_net(sk), sk->sk_family);
	if (!listener)
		return -ENOENT;

	info = kzalloc(sizeof(*info), GFP_KERNEL);
	if (!info) {
		sock_put(listener);	/* Ref: C (err) */
		return -ENOMEM;
	}

	info->tsi_handshake_done = done;
	info->tsi_handshake_data = data;
	if (priorities && strlen(priorities)) {
		info->tsi_tls_priorities = kstrdup(priorities, GFP_KERNEL);
		if (!info->tsi_tls_priorities) {
			tlsh_sock_info_destroy(info);
			sock_put(listener);	/* Ref: C (err) */
			return -ENOMEM;
		}
	}
	info->tsi_peerid = peerid;
	info->tsi_certificate = TLSH_NO_CERT;
	info->tsi_privkey = TLSH_NO_KEY;
	info->tsi_handshake_type = TLSH_TYPE_CLIENTHELLO_PSK;
	tlsh_sock_save(sk, info);

	rc = tlsh_accept_enqueue(listener, sk);
	if (rc) {
		tlsh_sock_clear(sk);
		sock_put(listener);	/* Ref: C (err) */
	}

	return rc;
}
EXPORT_SYMBOL_GPL(tls_client_hello_psk);
