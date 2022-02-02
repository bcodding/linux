/* SPDX-License-Identifier: (GPL-2.0-only OR BSD-2-Clause) */
/* Copyright (C) 2019 Netronome Systems, Inc. */

#undef TRACE_SYSTEM
#define TRACE_SYSTEM tls

#if !defined(_TLS_TRACE_H_) || defined(TRACE_HEADER_MULTI_READ)
#define _TLS_TRACE_H_

#include <asm/unaligned.h>
#include <linux/tracepoint.h>

struct sock;

#define show_af_family(family)					\
	__print_symbolic(family,				\
		{ AF_INET,		"AF_INET" },		\
		{ AF_INET6,		"AF_INET6" },		\
		{ AF_TLSH,		"AF_TLSH" })

TRACE_DEFINE_ENUM(TCP_ESTABLISHED);
TRACE_DEFINE_ENUM(TCP_SYN_SENT);
TRACE_DEFINE_ENUM(TCP_SYN_RECV);
TRACE_DEFINE_ENUM(TCP_FIN_WAIT1);
TRACE_DEFINE_ENUM(TCP_FIN_WAIT2);
TRACE_DEFINE_ENUM(TCP_TIME_WAIT);
TRACE_DEFINE_ENUM(TCP_CLOSE);
TRACE_DEFINE_ENUM(TCP_CLOSE_WAIT);
TRACE_DEFINE_ENUM(TCP_LAST_ACK);
TRACE_DEFINE_ENUM(TCP_LISTEN);
TRACE_DEFINE_ENUM(TCP_CLOSING);
TRACE_DEFINE_ENUM(TCP_NEW_SYN_RECV);

#define show_tcp_state(state)					\
	__print_symbolic(state,					\
		{ TCP_ESTABLISHED,	"ESTABLISHED" },	\
		{ TCP_SYN_SENT,		"SYN_SENT" },		\
		{ TCP_SYN_RECV,		"SYN_RECV" },		\
		{ TCP_FIN_WAIT1,	"FIN_WAIT1" },		\
		{ TCP_FIN_WAIT2,	"FIN_WAIT2" },		\
		{ TCP_TIME_WAIT,	"TIME_WAIT" },		\
		{ TCP_CLOSE,		"CLOSE" },		\
		{ TCP_CLOSE_WAIT,	"CLOSE_WAIT" },		\
		{ TCP_LAST_ACK,		"LAST_ACK" },		\
		{ TCP_LISTEN,		"LISTEN" },		\
		{ TCP_CLOSING,		"CLOSING" },		\
		{ TCP_NEW_SYN_RECV,	"NEW_SYN_RECV" })

#define show_poll_event_mask(mask)				\
	__print_flags(mask, "|",				\
		{ EPOLLIN,		"IN" },			\
		{ EPOLLPRI,		"PRI" },		\
		{ EPOLLOUT,		"OUT" },		\
		{ EPOLLERR,		"ERR" },		\
		{ EPOLLHUP,		"HUP" },		\
		{ EPOLLNVAL,		"NVAL" },		\
		{ EPOLLRDNORM,		"RDNORM" },		\
		{ EPOLLRDBAND,		"RDBAND" },		\
		{ EPOLLWRNORM,		"WRNORM" },		\
		{ EPOLLWRBAND,		"WRBAND" },		\
		{ EPOLLMSG,		"MSG" },		\
		{ EPOLLRDHUP,		"RDHUP" })


TRACE_EVENT(tls_device_offload_set,

	TP_PROTO(struct sock *sk, int dir, u32 tcp_seq, u8 *rec_no, int ret),

	TP_ARGS(sk, dir, tcp_seq, rec_no, ret),

	TP_STRUCT__entry(
		__field(	struct sock *,	sk		)
		__field(	u64,		rec_no		)
		__field(	int,		dir		)
		__field(	u32,		tcp_seq		)
		__field(	int,		ret		)
	),

	TP_fast_assign(
		__entry->sk = sk;
		__entry->rec_no = get_unaligned_be64(rec_no);
		__entry->dir = dir;
		__entry->tcp_seq = tcp_seq;
		__entry->ret = ret;
	),

	TP_printk(
		"sk=%p direction=%d tcp_seq=%u rec_no=%llu ret=%d",
		__entry->sk, __entry->dir, __entry->tcp_seq, __entry->rec_no,
		__entry->ret
	)
);

TRACE_EVENT(tls_device_decrypted,

	TP_PROTO(struct sock *sk, u32 tcp_seq, u8 *rec_no, u32 rec_len,
		 bool encrypted, bool decrypted),

	TP_ARGS(sk, tcp_seq, rec_no, rec_len, encrypted, decrypted),

	TP_STRUCT__entry(
		__field(	struct sock *,	sk		)
		__field(	u64,		rec_no		)
		__field(	u32,		tcp_seq		)
		__field(	u32,		rec_len		)
		__field(	bool,		encrypted	)
		__field(	bool,		decrypted	)
	),

	TP_fast_assign(
		__entry->sk = sk;
		__entry->rec_no = get_unaligned_be64(rec_no);
		__entry->tcp_seq = tcp_seq;
		__entry->rec_len = rec_len;
		__entry->encrypted = encrypted;
		__entry->decrypted = decrypted;
	),

	TP_printk(
		"sk=%p tcp_seq=%u rec_no=%llu len=%u encrypted=%d decrypted=%d",
		__entry->sk, __entry->tcp_seq,
		__entry->rec_no, __entry->rec_len,
		__entry->encrypted, __entry->decrypted
	)
);

TRACE_EVENT(tls_device_rx_resync_send,

	TP_PROTO(struct sock *sk, u32 tcp_seq, u8 *rec_no, int sync_type),

	TP_ARGS(sk, tcp_seq, rec_no, sync_type),

	TP_STRUCT__entry(
		__field(	struct sock *,	sk		)
		__field(	u64,		rec_no		)
		__field(	u32,		tcp_seq		)
		__field(	int,		sync_type	)
	),

	TP_fast_assign(
		__entry->sk = sk;
		__entry->rec_no = get_unaligned_be64(rec_no);
		__entry->tcp_seq = tcp_seq;
		__entry->sync_type = sync_type;
	),

	TP_printk(
		"sk=%p tcp_seq=%u rec_no=%llu sync_type=%d",
		__entry->sk, __entry->tcp_seq, __entry->rec_no,
		__entry->sync_type
	)
);

TRACE_EVENT(tls_device_rx_resync_nh_schedule,

	TP_PROTO(struct sock *sk),

	TP_ARGS(sk),

	TP_STRUCT__entry(
		__field(	struct sock *,	sk		)
	),

	TP_fast_assign(
		__entry->sk = sk;
	),

	TP_printk(
		"sk=%p", __entry->sk
	)
);

TRACE_EVENT(tls_device_rx_resync_nh_delay,

	TP_PROTO(struct sock *sk, u32 sock_data, u32 rec_len),

	TP_ARGS(sk, sock_data, rec_len),

	TP_STRUCT__entry(
		__field(	struct sock *,	sk		)
		__field(	u32,		sock_data	)
		__field(	u32,		rec_len		)
	),

	TP_fast_assign(
		__entry->sk = sk;
		__entry->sock_data = sock_data;
		__entry->rec_len = rec_len;
	),

	TP_printk(
		"sk=%p sock_data=%u rec_len=%u",
		__entry->sk, __entry->sock_data, __entry->rec_len
	)
);

TRACE_EVENT(tls_device_tx_resync_req,

	TP_PROTO(struct sock *sk, u32 tcp_seq, u32 exp_tcp_seq),

	TP_ARGS(sk, tcp_seq, exp_tcp_seq),

	TP_STRUCT__entry(
		__field(	struct sock *,	sk		)
		__field(	u32,		tcp_seq		)
		__field(	u32,		exp_tcp_seq	)
	),

	TP_fast_assign(
		__entry->sk = sk;
		__entry->tcp_seq = tcp_seq;
		__entry->exp_tcp_seq = exp_tcp_seq;
	),

	TP_printk(
		"sk=%p tcp_seq=%u exp_tcp_seq=%u",
		__entry->sk, __entry->tcp_seq, __entry->exp_tcp_seq
	)
);

TRACE_EVENT(tls_device_tx_resync_send,

	TP_PROTO(struct sock *sk, u32 tcp_seq, u8 *rec_no),

	TP_ARGS(sk, tcp_seq, rec_no),

	TP_STRUCT__entry(
		__field(	struct sock *,	sk		)
		__field(	u64,		rec_no		)
		__field(	u32,		tcp_seq		)
	),

	TP_fast_assign(
		__entry->sk = sk;
		__entry->rec_no = get_unaligned_be64(rec_no);
		__entry->tcp_seq = tcp_seq;
	),

	TP_printk(
		"sk=%p tcp_seq=%u rec_no=%llu",
		__entry->sk, __entry->tcp_seq, __entry->rec_no
	)
);

DECLARE_EVENT_CLASS(tlsh_listener_class,
	TP_PROTO(
		const struct socket *sock
	),
	TP_ARGS(sock),
	TP_STRUCT__entry(
		__field(const struct socket *, sock)
		__field(const struct sock *, sk)
		__field(int, refcount)
		__field(unsigned long, family)
	),
	TP_fast_assign(
		const struct sock *sk = sock->sk;

		__entry->sock = sock;
		__entry->sk = sk;
		__entry->refcount = refcount_read(&sk->sk_refcnt);
		__entry->family = tlsh_sk((struct sock *)sk)->th_bind_family;
	),

	TP_printk("listener=%p sk=%p(%d) family=%s",
		__entry->sock, __entry->sk,
		__entry->refcount, show_af_family(__entry->family)
	)
);

#define DEFINE_TLSH_LISTENER_EVENT(name)			\
	DEFINE_EVENT(tlsh_listener_class, name,			\
		TP_PROTO(					\
			const struct socket *sock		\
		),						\
		TP_ARGS(sock))

DEFINE_TLSH_LISTENER_EVENT(tlsh_bind);
DEFINE_TLSH_LISTENER_EVENT(tlsh_accept);
DEFINE_TLSH_LISTENER_EVENT(tlsh_listen);
DEFINE_TLSH_LISTENER_EVENT(tlsh_pf_create);

TRACE_EVENT(tlsh_newsock,
	TP_PROTO(
		const struct socket *newsock,
		const struct sock *newsk
	),
	TP_ARGS(newsock, newsk),
	TP_STRUCT__entry(
		__field(const struct socket *, newsock)
		__field(const struct sock *, newsk)
		__field(int, refcount)
		__field(unsigned long, family)
	),
	TP_fast_assign(
		__entry->newsock = newsock;
		__entry->newsk = newsk;
		__entry->refcount = refcount_read(&newsk->sk_refcnt);
		__entry->family = newsk->sk_family;
	),

	TP_printk("newsock=%p newsk=%p(%d) family=%s",
		__entry->newsock, __entry->newsk,
		__entry->refcount, show_af_family(__entry->family)
	)
);

DECLARE_EVENT_CLASS(tlsh_proto_op_class,
	TP_PROTO(
		const struct socket *sock
	),
	TP_ARGS(sock),
	TP_STRUCT__entry(
		__field(const struct socket *, sock)
		__field(const struct sock *, sk)
		__field(int, refcount)
		__field(unsigned long, family)
		__field(unsigned long, state)
	),
	TP_fast_assign(
		const struct sock *sk = sock->sk;

		__entry->sock = sock;
		__entry->sk = sk;
		__entry->refcount = refcount_read(&sk->sk_refcnt);
		__entry->family = sk->sk_family;
		__entry->state = sk->sk_state;
	),

	TP_printk("sock=%p sk=%p(%d) family=%s state=%s",
		__entry->sock, __entry->sk, __entry->refcount,
		show_af_family(__entry->family),
		show_tcp_state(__entry->state)
	)
);

#define DEFINE_TLSH_PROTO_OP_EVENT(name)			\
	DEFINE_EVENT(tlsh_proto_op_class, name,			\
		TP_PROTO(					\
			const struct socket *sock		\
		),						\
		TP_ARGS(sock))

DEFINE_TLSH_PROTO_OP_EVENT(tlsh_release);
DEFINE_TLSH_PROTO_OP_EVENT(tlsh_getname);
DEFINE_TLSH_PROTO_OP_EVENT(tlsh_shutdown);
DEFINE_TLSH_PROTO_OP_EVENT(tlsh_setsockopt);
DEFINE_TLSH_PROTO_OP_EVENT(tlsh_getsockopt);

TRACE_EVENT(tlsh_sendmsg_start,
	TP_PROTO(
		const struct socket *sock,
		size_t size
	),
	TP_ARGS(sock, size),
	TP_STRUCT__entry(
		__field(const struct socket *, sock)
		__field(const struct sock *, sk)
		__field(int, refcount)
		__field(unsigned long, family)
		__field(unsigned long, state)
		__field(const void *, op)
		__field(size_t, size)
	),
	TP_fast_assign(
		const struct sock *sk = sock->sk;

		__entry->sock = sock;
		__entry->sk = sk;
		__entry->refcount = refcount_read(&sk->sk_refcnt);
		__entry->family = sk->sk_family;
		__entry->state = sk->sk_state;
		__entry->op = sk->sk_prot->sendmsg;
		__entry->size = size;
	),

	TP_printk("sock=%p sk=%p(%d) family=%s state=%s size=%zu op=%pS",
		__entry->sock, __entry->sk, __entry->refcount,
		show_af_family(__entry->family),
		show_tcp_state(__entry->state),
		__entry->size, __entry->op
	)
);

TRACE_EVENT(tlsh_recvmsg_start,
	TP_PROTO(
		const struct socket *sock,
		size_t size
	),
	TP_ARGS(sock, size),
	TP_STRUCT__entry(
		__field(const struct socket *, sock)
		__field(const struct sock *, sk)
		__field(int, refcount)
		__field(unsigned long, family)
		__field(unsigned long, state)
		__field(const void *, op)
		__field(size_t, size)
	),
	TP_fast_assign(
		const struct sock *sk = sock->sk;

		__entry->sock = sock;
		__entry->sk = sk;
		__entry->refcount = refcount_read(&sk->sk_refcnt);
		__entry->family = sk->sk_family;
		__entry->state = sk->sk_state;
		__entry->op = sk->sk_prot->recvmsg;
		__entry->size = size;
	),

	TP_printk("sock=%p sk=%p(%d) family=%s state=%s size=%zu op=%pS",
		__entry->sock, __entry->sk, __entry->refcount,
		show_af_family(__entry->family),
		show_tcp_state(__entry->state),
		__entry->size, __entry->op
	)
);

DECLARE_EVENT_CLASS(tlsh_opmsg_result_class,
	TP_PROTO(
		const struct socket *sock,
		int result
	),
	TP_ARGS(sock, result),
	TP_STRUCT__entry(
		__field(const struct socket *, sock)
		__field(const struct sock *, sk)
		__field(int, refcount)
		__field(unsigned long, family)
		__field(unsigned long, state)
		__field(int, result)
	),
	TP_fast_assign(
		const struct sock *sk = sock->sk;

		__entry->sock = sock;
		__entry->sk = sk;
		__entry->refcount = refcount_read(&sk->sk_refcnt);
		__entry->family = sk->sk_family;
		__entry->state = sk->sk_state;
		__entry->result = result;
	),

	TP_printk("sock=%p sk=%p(%d) family=%s state=%s result=%d",
		__entry->sock, __entry->sk, __entry->refcount,
		show_af_family(__entry->family),
		show_tcp_state(__entry->state),
		__entry->result
	)
);

#define DEFINE_TLSH_OPMSG_RESULT_EVENT(name)			\
	DEFINE_EVENT(tlsh_opmsg_result_class, name,		\
		TP_PROTO(					\
			const struct socket *sock,		\
			int result				\
		),						\
		TP_ARGS(sock, result))

DEFINE_TLSH_OPMSG_RESULT_EVENT(tlsh_sendmsg_result);
DEFINE_TLSH_OPMSG_RESULT_EVENT(tlsh_recvmsg_result);

TRACE_EVENT(tlsh_poll,
	TP_PROTO(
		const struct socket *sock,
		__poll_t mask
	),
	TP_ARGS(sock, mask),
	TP_STRUCT__entry(
		__field(const struct socket *, sock)
		__field(const struct sock *, sk)
		__field(int, refcount)
		__field(unsigned long, mask)
	),
	TP_fast_assign(
		const struct sock *sk = sock->sk;

		__entry->sock = sock;
		__entry->sk = sk;
		__entry->refcount = refcount_read(&sk->sk_refcnt);
		__entry->mask = mask;
	),

	TP_printk("sock=%p sk=%p(%d) mask=%s",
		__entry->sock, __entry->sk, __entry->refcount,
		show_poll_event_mask(__entry->mask)
	)
);

TRACE_EVENT(tlsh_poll_listener,
	TP_PROTO(
		const struct socket *sock,
		__poll_t mask
	),
	TP_ARGS(sock, mask),
	TP_STRUCT__entry(
		__field(const struct socket *, sock)
		__field(const struct sock *, sk)
		__field(int, refcount)
		__field(unsigned long, mask)
	),
	TP_fast_assign(
		const struct sock *sk = sock->sk;

		__entry->sock = sock;
		__entry->sk = sk;
		__entry->refcount = refcount_read(&sk->sk_refcnt);
		__entry->mask = mask;
	),

	TP_printk("sock=%p sk=%p(%d) mask=%s",
		__entry->sock, __entry->sk, __entry->refcount,
		show_poll_event_mask(__entry->mask)
	)
);

DECLARE_EVENT_CLASS(tlsh_handshake_done_class,
	TP_PROTO(
		const struct sock *sk
	),
	TP_ARGS(sk),
	TP_STRUCT__entry(
		__field(const struct sock *, sk)
		__field(int, refcount)
		__field(unsigned long, family)
	),
	TP_fast_assign(
		__entry->sk = sk;
		__entry->refcount = refcount_read(&sk->sk_refcnt);
		__entry->family = sk->sk_family;
	),

	TP_printk("sk=%p(%d) family=%s",
		__entry->sk, __entry->refcount,
		show_af_family(__entry->family)
	)
);

#define DEFINE_TLSH_HANDSHAKE_DONE_EVENT(name)			\
	DEFINE_EVENT(tlsh_handshake_done_class, name,		\
		TP_PROTO(					\
			const struct sock *sk			\
		),						\
		TP_ARGS(sk))

DEFINE_TLSH_HANDSHAKE_DONE_EVENT(tlsh_handshake_ok);
DEFINE_TLSH_HANDSHAKE_DONE_EVENT(tlsh_handshake_failed);

#endif /* _TLS_TRACE_H_ */

#undef TRACE_INCLUDE_PATH
#define TRACE_INCLUDE_PATH .
#undef TRACE_INCLUDE_FILE
#define TRACE_INCLUDE_FILE trace

#include <trace/define_trace.h>
