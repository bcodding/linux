/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Copyright (C) 2021-2022 Red Hat, Inc. All Rights Reserved.
 * Written by Benjamin Coddington (bcodding@redhat.com)
 *
 */

#ifndef _TLS_KEYS_H
#define _TLS_KEYS_H

int __init tls_keys_init(void);
int __exit tls_keys_exit(void);

extern int tls_keys_client_hello_anon(struct socket *socket,
				const char *peername, const char *priorities);

#endif /* _TLS_KEYS_H */
