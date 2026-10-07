.. SPDX-License-Identifier: GPL-2.0

======================================================
RPC server: per-client dispatch and transport classes
======================================================

An RPC service thread pool serves its ready transports in FIFO order,
one request per turn.  A peer with many connections (``nconnect``, a
deep NFSv4.1 slot table, a data mover with a thread per file) takes a
turn per connection, and a peer with one connection waits behind all
of them.

With a classifier attached, the pool instead serves its *clients* round
robin: each client with work queued gets one request per round, however
many connections it holds.  Which transports form a client is decided
by a BPF program the administrator loads, once per accepted connection.
With no program loaded nothing changes.

This document describes the model, how to install a classifier with
the ``svc-classify`` tool, what some class maps do, and how it works
underneath.

Clients, classes and turns
==========================

A *client* is a set of transports that share one turn.  Every service
(nfsd, lockd, the NFSv4 callback service) keeps its own clients, found
by *class* and network namespace, or by class, namespace and peer
address.

The classifier returns a 32-bit class word for each accepted transport:

``0``
    ``SVC_CLASS_NONE``: the transport stays on the service's *anonymous
    client*.

``N``, 1 to 2^31 - 1
    one client for every transport of class ``N``.

``N | SVC_CLASS_PER_ADDR``
    one client per peer address within class ``N``.  ``N`` may be 0, so
    ``SVC_CLASS_PER_ADDR`` alone means one client per peer address.

``SVC_CLASS_PER_ADDR`` is bit 31.  ``svc-classify`` and this document
write a class word with the bit set as ``N+addr``; ``svc-classify``
also accepts ``addr`` for ``0+addr``.

Dispatch rules:

- A pool serves the clients that have transports queued round robin,
  one request per client per round.
- Within a client, transports are served in FIFO order, except that a
  transport needing a connection accepted, closed, or a TLS handshake
  run goes ahead of transports with data, though not two such turns in
  a row while data waits.
- A client's share of the pool does not grow with its connection count.
  A client with one connection and a client with thirty get the same
  number of turns while both have work queued.

Things that follow from the rules and are easy to get wrong:

- The anonymous client is one client.  Once any classifier is attached,
  every transport whose class is ``0`` shares a single turn with every
  other such transport of that service.  Within that one client the old
  FIFO order applies, so those peers share the turn in proportion to
  their connection counts.  A map that classifies only the hosts it
  cares about and leaves the rest at ``0`` gives "the rest" one turn
  in total (see example 5 below).
- Per-address clients ignore the port.  Only IPv4 and IPv6 peers can be
  keyed by address; a transport whose peer is anything else is left on
  the anonymous client.
- Listeners and UDP sockets are never classified; UDP traffic is served
  from the anonymous client.
- A transport keeps the class it was given when accepted.  Changing the
  map, or replacing or removing the classifier, affects connections
  accepted afterwards.  A connection that must be reclassified has to
  reconnect.
- nfsd has one service per network namespace, so its anonymous client
  is per namespace.  lockd and the NFSv4 callback service are one
  service for all namespaces; their anonymous clients span namespaces.
- With no classifier attached anywhere, the pool uses a single FIFO;
  the per-request cost of the feature is then a static branch on
  enqueue and one empty-queue test on dequeue.
  ``CONFIG_SUNRPC_BPF_CLASSIFY`` (default y) builds the hook; without
  it there is no classification.

Installing a classifier
=======================

There is one tool to do it with: ``svc-classify``, in
``tools/net/sunrpc/svc-classify`` of the kernel source.  It carries the
classifier program inside the binary, attaches it, and manages the
class map by address prefix.  ``bpftool`` is not needed, and its
``struct_ops`` subcommands cannot be used in its place (see "How it
works").

What you need
-------------

- A kernel with ``CONFIG_SUNRPC_BPF_CLASSIFY`` (default y) and BTF:
  ``CONFIG_DEBUG_INFO_BTF``, and ``CONFIG_DEBUG_INFO_BTF_MODULES`` when
  ``sunrpc`` is a module.
- ``/sys/fs/bpf`` mounted (systemd mounts it).
- To build the tool: ``clang``, and the ``libelf`` and ``zlib``
  development files.  The tool builds the libbpf and bpftool it needs
  from the kernel source tree.

Build and install the tool
--------------------------

In the kernel source tree::

    $ make -C tools/net/sunrpc/svc-classify
    # make -C tools/net/sunrpc/svc-classify install

The binary goes to ``/usr/local/sbin/svc-classify`` (``prefix=`` and
``sbindir=`` override that).  At run time it needs only libelf and
zlib.

Attach it
---------

As root, in the network namespace the service runs in (on a host that
is the initial namespace; in a container, ``nsenter`` or
``ip netns exec`` into it first)::

    # svc-classify load
    # svc-classify status
    loaded, link id 46, struct_ops map id 140

The classifier is now attached to every RPC service in the namespace,
with an empty map: every connection accepted from now on returns class
``0`` and stays on the anonymous client, so nothing has changed yet.
One classifier per namespace: a second ``load`` is refused.

Install the class map
---------------------

Add one line per address prefix.  The longest matching prefix wins; a
peer that matches nothing gets class ``0``::

    # svc-classify add 192.0.2.0/24 1
    # svc-classify add any addr
    # svc-classify list
    192.0.2.0/24 -> 1
    any -> 0+addr

``PREFIX`` is ``a.b.c.d[/len]``, ``x:y::z[/len]``, ``any`` (every
address of either family), ``any4`` or ``any6``.  ``CLASS`` is ``N``
(one client for every peer that matches), ``N+addr`` (one client per
peer address, within class ``N``), ``addr`` (one client per peer
address, the same as ``0+addr``), or ``0`` (the anonymous client).

Entries apply to connections accepted after they are added; to
reclassify existing connections, have the clients reconnect (restarting
the service does that for all of them).  ``svc-classify del PREFIX``
removes an entry.

Check it
--------

``svc-classify status`` and ``svc-classify list`` show the link and the
map.  The ``sunrpc:svc_xprt_dequeue`` tracepoint shows the class every
transport is dispatched as (see "Observing"), which is the check that
the map does what was meant.

Change or remove it
-------------------

- ``svc-classify add`` and ``del`` change the map at any time.
- ``svc-classify replace`` installs a new build of the tool's program
  on the attached link and keeps the map, provided the new build's map
  definition is unchanged; otherwise unload and load.
- ``svc-classify unload`` detaches the classifier.  Connections accepted
  afterwards are anonymous; when no classifier is attached in any
  namespace, the service is back on its single FIFO.

Across reboots
--------------

Nothing persists: the link and the map live in ``/sys/fs/bpf`` and are
gone at boot.  Run the ``load`` and ``add`` commands before the service
starts, for example from a unit ordered before ``nfs-server.service``::

    [Unit]
    Description=RPC service transport classifier
    Before=nfs-server.service

    [Service]
    Type=oneshot
    RemainAfterExit=yes
    ExecStart=/usr/local/sbin/svc-classify load
    ExecStart=/usr/local/sbin/svc-classify add 192.0.2.0/24 1
    ExecStart=/usr/local/sbin/svc-classify add any addr
    ExecStop=/usr/local/sbin/svc-classify unload

    [Install]
    WantedBy=nfs-server.service

Loading after the service is up works too; it only misses the
connections already accepted.

Examples
========

Each example gives the ``svc-classify add`` lines, the hosts they are
applied to, and the share of the pool each client gets while all of
them have work queued.

1. Every host its own client
----------------------------

::

    # svc-classify add any addr

Three hosts: one with eight connections, one with one, one with two.
Each host is a client, and each gets a third of the turns.  Without a
classifier they would be served in proportion to their connections,
8:1:2.

2. A set of movers as one client, everyone else per host
--------------------------------------------------------

::

    # svc-classify add 192.0.2.0/24 1
    # svc-classify add any addr

Three movers in ``192.0.2.0/24`` with four connections each, and two
other hosts, one with one connection and one with two.  The movers are
one client; each of the other hosts is a client of its own.  Each of
the three clients gets a third of the pool; the movers share theirs by
connection count, a ninth each.  Without a classifier the movers'
twelve connections would take twelve fifteenths of the pool and the
one-connection host one fifteenth.

3. Two mover groups, one turn each
----------------------------------

::

    # svc-classify add 192.0.2.0/25 1
    # svc-classify add 192.0.2.128/25 2
    # svc-classify add any addr

Two hosts in ``192.0.2.0/25`` and two in ``192.0.2.128/25``, four
connections each, and one other host with one connection.  Each group
is a client and the other host is a client: three clients, a third
each.  Within a group the two hosts split the group's third by
connection count, a sixth each.

4. Per host inside a campus, the rest of the world as one client
----------------------------------------------------------------

::

    # svc-classify add 198.51.100.0/24 1+addr
    # svc-classify add any 2

Two hosts in ``198.51.100.0/24`` and two hosts outside it.  Each campus
host is a client of its own (class 1, one client per address); the
outside hosts together are one client (class 2).  Three clients, a
third each; the outside hosts split their third by connection count.

5. Leaving hosts unclassified
-----------------------------

::

    # svc-classify add 203.0.113.0/24 0
    # svc-classify add any addr

Two hosts in ``203.0.113.0/24`` and two hosts elsewhere.  The two in
``203.0.113.0/24`` return ``0`` and so share the anonymous client, one
turn between them; the two elsewhere are a client each.  Three
clients, a third each; the anonymous pair split their third by
connection count.

The common mistake is the map with only the movers in it::

    # svc-classify add 192.0.2.0/24 1

Three movers in ``192.0.2.0/24`` and two other hosts, one with one
connection and one with two.  There are exactly two clients: the
movers, and everyone else on the anonymous client.  The movers get
half the pool.  The other half goes to the two other hosts in
proportion to their connections, a sixth and a third of the pool.  Add
``any addr`` to serve them per host.

6. IPv6
-------

::

    # svc-classify add 2001:db8:1::/48 1
    # svc-classify add any addr

Entries are per family; ``any`` covers both families, ``any6`` IPv6
only.  Two hosts in ``2001:db8:1::/48`` and one host elsewhere: the two
are one client, the other is a client of its own, half the pool each.

Observing
=========

The ``sunrpc:svc_xprt_dequeue`` tracepoint reports the class of every
transport as it is dispatched::

    svc_xprt_dequeue: server=127.0.0.1:3049 client=127.0.1.1:38209 xpt_id=1164 flags=BUSY|DATA|TEMP|CACHE_AUTH|LOCAL|CONG_CTRL class=1 wakeup-us=30 qtime-us=4
    svc_xprt_dequeue: server=127.0.0.1:3049 client=127.0.2.1:45965 xpt_id=1162 flags=BUSY|DATA|TEMP|CACHE_AUTH|LOCAL|CONG_CTRL class=0+addr wakeup-us=60 qtime-us=10
    svc_xprt_dequeue: server=[::1]:3049 client=[2001:db8:1::1]:44401 xpt_id=1152 flags=BUSY|DATA|TEMP|CACHE_AUTH|LOCAL|CONG_CTRL class=1 wakeup-us=62 qtime-us=7
    svc_xprt_dequeue: server=[::]:3049 client=(einval) xpt_id=2 flags=BUSY|CONN|CHNGBUF|LISTENER|CACHE_AUTH|CONG_CTRL|RPCB_UNREG class=0 wakeup-us=25 qtime-us=25

``class=0`` is the anonymous client; ``+addr`` marks a per-address
client; listeners show ``class=0`` and ``LISTENER`` in their flags.
``bpftool link show`` lists the attached classifier's link, and
``bpftool map dump pinned /sys/fs/bpf/svc_classify/prefixes`` the map
with its raw keys.

How it works
============

The classifier
--------------

.. kernel-doc:: include/linux/sunrpc/svc.h
   :identifiers: svc_classifier

The callback runs once per accepted transport, in process context,
under ``rcu_read_lock()``; sleepable programs are refused at load.
Only the base BPF helpers are available (map lookups, the usual).  The
program is handed the ``struct svc_xprt`` and may read its fields
directly:

- ``xpt_remote`` and ``xpt_remotelen``: the peer address;
- ``xpt_local``: the address the connection arrived on;
- ``xpt_net``: the network namespace;
- ``xpt_server->sv_name``: which service, ``"nfsd"``, ``"lockd"``,
  ``"NFSv4 callback"``;
- ``xpt_class->xcl_name``: the transport class, ``"tcp"``, ``"rdma"``.

A classifier applies to every service in its namespace.  A program that
wants to treat services differently reads ``xpt_server->sv_name``.

The program ``svc-classify`` carries,
``tools/net/sunrpc/svc-classify/svc_classify.bpf.c``, is the prefix
classifier from the BPF selftests
(``tools/testing/selftests/bpf/progs/bpf_svc_classifier.c``).  Its one
map is an LPM trie keyed by ``{prefixlen, family, addr[16]}`` with
``prefixlen`` counting the family byte plus the address bits, and the
class word as the value; a miss returns ``0``.  Nothing else in the
program is specific to this policy.  A classifier keyed on the local
address, the service name, or anything else the ``svc_xprt`` shows is
the same program with a different lookup, and ``svc-classify replace``
installs a rebuilt one as long as its map definition is unchanged.

Attaching
---------

The classifier is a ``struct_ops`` map.  Creating its link attaches the
classifier to the network namespace of the task that creates the link:

- one classifier per namespace; a second attach fails with ``-EBUSY``;
- ``BPF_LINK_UPDATE`` on the link replaces the program;
- closing or detaching the link, or unpinning its last reference,
  removes the classifier;
- a namespace that exits leaves its link attached to nothing;
  closing it is harmless.

``svc-classify load`` creates the link with
``bpf_map__attach_struct_ops()`` and pins it, with the map, under
``/sys/fs/bpf/svc_classify`` (``-p DIR`` chooses another directory,
for a second namespace); ``replace`` is ``bpf_link__update_map()`` on
the pinned link; ``unload`` unpins both.

``bpftool struct_ops`` (``register``, ``dump``, ``unregister``) resolves
the struct_ops type in the kernel's own BTF only, so when ``sunrpc`` is
a module those subcommands do not find ``svc_classifier`` maps, and
``register`` fails after creating the link.  Use ``svc-classify``.

Limits
======

- A transport cannot move between clients; a client identity that is
  only known after the connection is accepted (an NFSv4.1 client id,
  say) cannot be used.  NFSv4.1 sessions over ``nconnect`` are one
  client by peer address.
- RDMA transports are classified like TCP, by the peer address of the
  connection; UDP is not classified.
- The cost with no classifier attached is a static branch on enqueue
  and one empty-queue test on dequeue.  With one attached, dispatch
  takes two or three more lock-free queue operations per request than
  before: the client's queue, the pool's queue of clients, and a
  requeue when the client has more.
