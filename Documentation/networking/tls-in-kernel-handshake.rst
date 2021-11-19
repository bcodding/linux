.. _kernel_tls:

=======================
In-Kernel TLS Handshake
=======================

Overview
========

Transport Layer Security (TLS) is a Upper Layer Protocol (ULP) that runs over
TCP. TLS provides end-to-end data integrity and confidentiality.

kTLS handles the TLS record subprotocol, but does not handle the TLS handshake
subprotocol, used to establish a TLS session. In user space, a TLS library
performs the handshake on a socket which is converted to kTLS operation. In
the kernel it is much the same. The TLS handshake is done in user space by a
library TLS implementation.


User handshake agent
====================

With the current implementation, a user agent is started in each network
namespace where a kernel consumer might require a TLS handshake. This agent
listens on an AF_TLSH socket for requests from the kernel to perform a
handshake on an open and connected TCP socket.

The open socket is passed to user space via accept(), which creates a file
descriptor. If the handshake completes successfully, the user agent promotes
the socket to use the TLS ULP and sets the session information using the
SOL_TLS socket options. The user agent returns the socket to the kernel by
closing the accepted file descriptor.


Kernel Handshake API
====================

A kernel consumer initiates a client-side TLS handshake on an open
socket by invoking one of the tls_client_hello() functions. For
example:

.. code-block:: c

  ret = tls_client_hello_x509(sock, done_func, cookie, priorities,
                              cert, privkey);

The function returns zero when the handshake request is under way. A
zero return guarantees the callback function @done_func will be invoked
for this socket.

The function returns a negative errno if the handshake could not be
started. A negative errno guarantees the callback function @done_func
will not be invoked on this socket.

The @sock argument is an open and connected IPPROTO_TCP socket. The
caller must hold a reference on the socket to prevent it from being
destroyed while the handshake is in progress.

@done_func and @cookie are a callback function that is invoked when the
handshake has completed (either successfully or not). The success status
of the handshake is returned via the @status parameter of the callback
function. A good practice is to close and destroy the socket immediately
if the handshake has failed.

@priorities is a GnuTLS priorities string that controls the handshake.
The special value TLSH_DEFAULT_PRIORITIES causes the handshake to
operate using user space configured default TLS priorities. However,
the caller can use the string to (for example) adjust the handshake to
use a restricted set of ciphers (say, if the kernel is in FIPS mode or
the kernel consumer wants to mandate only a limited set of ciphers).

@cert is the serial number of a key that contains a DER format x.509
certificate that the user agent presents to the remote as the local
peer's identity.

@privkey is the serial number of a key that contains a DER-format
private key associated with the x.509 certificate.


To initiate a client-side TLS handshake with a pre-shared key, use:

.. code-block:: c

  ret = tls_client_hello_psk(sock, done_func, cookie, priorities,
                             peerid);

@peerid is the serial number of a key that contains the pre-shared
key to be used for the handshake.

The other parameters are as above.


To initiate an anonymous client-side TLS handshake use:

.. code-block:: c

  ret = tls_client_hello_anon(sock, done_func, cookie, priorities);

The parameters are as above.

The user agent presents no peer identity information to the remote
during the handshake. Only server authentication is performed
during the handshake. Thus the established session uses encryption
only.


Other considerations
--------------------

While the handshake is under way, the kernel consumer must alter the
socket's sk_data_ready callback function to ignore all incoming data.
Once the handshake completion callback function has been invoked,
normal receive operation can be resumed.

The consumer must provide a buffer for and then examine the control
message (CMSG) that is part of every subsequent sock_recvmsg(). Each
control message indicates whether the received message data is TLS
record data or session metadata.

See tls.rst for details on how a kTLS consumer recognizes incoming
(decrypted) application data, alerts, and handshake packets once the
socket has been promoted to use the TLS ULP.

