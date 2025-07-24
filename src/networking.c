/*
networking.c - Network sockets (IPv4/IPv6), Event polling
Copyright (C) 2021  LekKit <github.com/LekKit>

This Source Code Form is subject to the terms of the Mozilla Public
License, v. 2.0. If a copy of the MPL was not distributed with this
file, You can obtain one at https://mozilla.org/MPL/2.0/.
*/

// Make POSIX/GNU/BSD features available in strict C standard mode
// For kqueue(), kevent(), syscall(), etc

#undef _GNU_SOURCE
#define _GNU_SOURCE
#undef _BSD_SOURCE
#define _BSD_SOURCE
#undef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#undef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE

#if defined(_WIN32)

// Override maximum amount of sockets for select()
#define FD_SETSIZE 1024

#include <winsock2.h> // For WSAStartup(), WSAGetLastError(), SetHandleInformation(), closesocket(), ioctlsocket()...
#include <ws2tcpip.h> // For AF_INET6

// Abstract away socket type differences between Win32/POSIX
typedef SOCKET net_handle_t;
typedef int    net_addrlen_t;
#define NET_HANDLE_INVALID (INVALID_SOCKET)

#else

#include <errno.h>       // For errno, EINPROGRESS, EAGAIN, EWOULDBLOCK, EINTR, ECONNRESET
#include <fcntl.h>       // For fcntl(), F_GETFL, F_SETFL, F_SETFD, O_NONBLOCK, FD_CLOEXEC
#include <netinet/in.h>  // For struct sockaddr_in, struct sockaddr_in6, IPPROTO_TCP
#include <netinet/tcp.h> // For TCP_NODELAY
#include <signal.h>      // For signal(), SIGPIPE, SIG_DFL, SIG_IGN
#include <sys/ioctl.h>   // For ioctl()
#include <sys/socket.h>  // For socklen_t, struct sockaddr, socket(), AF_INET, SOCK_DGRAM, SOCK_STREAM, SOL_SOCKET...
#include <sys/time.h>    // For select()
#include <unistd.h>      // For close(), syscall(__NR_accept4)

// Abstract away socket type differences between Win32/POSIX
typedef int       net_handle_t;
typedef socklen_t net_addrlen_t;
#define NET_HANDLE_INVALID (-1)

#if defined(__linux__)
#include <sys/syscall.h> // For __NR_accept4, __NR_epoll_create
#endif

#if !defined(USE_SELECT) && ((defined(__linux__) && defined(__NR_epoll_create)) || defined(__illumos__))
// Use epoll() for net_poll on Linux & Illumos
#include <sys/epoll.h>    // For struct epoll_event, epoll_create(), epoll_ctl(), epoll_wait(), EPOLL_CTL_ADD...
#include <sys/resource.h> // For struct rlimit, getrlimit(), setrlimit(), RLIMIT_NOFILE

#define EPOLL_NET_IMPL 1

#elif !defined(USE_SELECT)                                                                                             \
    && (defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__DragonFly__)                  \
        || (defined(__APPLE__) && __ENVIRONMENT_MAC_OS_X_VERSION_MIN_REQUIRED__ >= 1060))
// Use kqueue() for net_poll on FreeBSD, OpenBSD, NetBSD, DragonFlyBSD and Apple
#include <sys/event.h>    // For struct kevent, kqueue(), kevent(), EV_SET(), EVFILT_READ, EVFILT_WRITE
#include <sys/resource.h> // For struct rlimit, getrlimit(), setrlimit(), RLIMIT_NOFILE

#define KQUEUE_NET_IMPL 1

#endif

#endif

#if !(defined(EPOLL_NET_IMPL) || defined(KQUEUE_NET_IMPL))
// Use select() for net_poll when neither epoll/kqueue are supported
// Scales poorly, but it's a fairly portable fallback. Thread safety & other epoll-like features are well emulated.
#define SELECT_NET_IMPL 1
#endif

#if defined(AF_INET6)
// Compile IPv6 support on systems where it's actually exposed
#define IPV6_NET_IMPL 1
#endif

// Internal headers come after system headers because of safe_free() and winsock
#include "mem_ops.h"
#include "networking.h"
#include "utils.h"

// Pass to send() to prevent SIGPIPE from being delivered (Linux, *BSD, Apple)
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif

#if defined(SELECT_NET_IMPL)

#include "rvtimer.h"
#include "spinlock.h"
#include "vector.h"

typedef struct {
    net_sock_t* sock;
    net_poll_t* poll;
    void*       data;
} net_monitor_t;

#endif

struct net_sock {
#if defined(SELECT_NET_IMPL)
    vector_t(net_monitor_t*) watchers;
#endif
    net_handle_t fd;
    net_addr_t   addr;
};

struct net_poll {
#if defined(EPOLL_NET_IMPL) || defined(KQUEUE_NET_IMPL)
    net_handle_t fd;
#else
    vector_t(net_monitor_t*) events;
    size_t                   consumed;
    fd_set                   r_set, w_set;
    fd_set                   r_ready, w_ready;
    net_sock_t*              wake_sock[2];
    spinlock_t               lock;
    uint32_t                 waiters;
    int                      max_fd;
#endif
};

static bool networking_available = false;

const net_addr_t net_ipv4_any_addr = {
    .type = NET_TYPE_IPV4,
};
const net_addr_t net_ipv4_local_addr = {
    .type  = NET_TYPE_IPV4,
    .ip[0] = 127,
    .ip[3] = 1,
};
const net_addr_t net_ipv6_any_addr = {
    .type = NET_TYPE_IPV6,
};
const net_addr_t net_ipv6_local_addr = {
    .type   = NET_TYPE_IPV6,
    .ip[15] = 1,
};

static void net_init_once(void)
{
#if defined(_WIN32)
    // Try to initialize WinSock 2.2, fallback to 2.1
    WSADATA wsaData = {0};
    if (WSAStartup(0x0202, &wsaData) && WSAStartup(0x0201, &wsaData)) {
        rvvm_error("Failed to initialize WinSock2");
        return;
    }
#elif defined(SIGPIPE)
    // Ignore SIGPIPE (Do not crash on writes to closed socket)
    void* handler = signal(SIGPIPE, SIG_IGN);
    if (handler && handler != (void*)SIG_DFL && handler != (void*)SIG_IGN) {
        // Revert signal handler already set by someone else
        signal(SIGPIPE, handler);
    }
#endif
#if defined(EPOLL_NET_IMPL) || defined(KQUEUE_NET_IMPL)
    struct rlimit rlim = {0};
    if (!getrlimit(RLIMIT_NOFILE, &rlim)) {
        if (rlim.rlim_cur < rlim.rlim_max && rlim.rlim_max > 1024) {
            rlim.rlim_cur = rlim.rlim_max;
            if (!setrlimit(RLIMIT_NOFILE, &rlim)) {
                rvvm_info("Raising RLIMIT_NOFILE to %u", (uint32_t)rlim.rlim_cur);
            }
        }
    }
#endif
    networking_available = true;
}

// Initialize networking automatically
static bool net_init(void)
{
    DO_ONCE(net_init_once());
    return networking_available;
}

/*
 * Internal socket helpers
 */

// Address types conversion (net_addr_t <-> sockaddr_in/sockaddr_in6)
// NOTE: Must operate on a zeroed structure
static void net_sockaddr_from_addr(struct sockaddr_in* sock_addr, const net_addr_t* addr)
{
    sock_addr->sin_family = AF_INET;
    if (addr) {
        write_uint16_be_m(&sock_addr->sin_port, addr->port);
        memcpy(&sock_addr->sin_addr.s_addr, addr->ip, 4);
    }
}

static void net_addr_from_sockaddr(net_addr_t* addr, const struct sockaddr_in* sock_addr)
{
    addr->type = NET_TYPE_IPV4;
    addr->port = read_uint16_be_m(&sock_addr->sin_port);
    memcpy(addr->ip, &sock_addr->sin_addr.s_addr, 4);
}

#if defined(IPV6_NET_IMPL)

static void net_sockaddr6_from_addr(struct sockaddr_in6* sock_addr, const net_addr_t* addr)
{
    sock_addr->sin6_family = AF_INET6;
    write_uint16_be_m(&sock_addr->sin6_port, addr->port);
    memcpy(&sock_addr->sin6_addr.s6_addr, addr->ip, 16);
}

static void net_addr_from_sockaddr6(net_addr_t* addr, const struct sockaddr_in6* sock_addr)
{
    addr->type = NET_TYPE_IPV6;
    addr->port = read_uint16_be_m(&sock_addr->sin6_port);
    memcpy(addr->ip, &sock_addr->sin6_addr.s6_addr, 16);
}

#endif

// Wrappers for generic operations on socket handles
static void net_close_handle(net_handle_t fd)
{
#if defined(_WIN32)
    closesocket(fd);
#else
    close(fd);
#endif
}

static bool net_handle_set_blocking(net_handle_t fd, bool block)
{
#if defined(_WIN32)
    u_long nb = block ? 0 : 1;
    return !ioctlsocket(fd, FIONBIO, &nb);
#elif defined(FIONBIO)
    // Use a single syscall instead of fcntl implementation
    int nb = block ? 0 : 1;
    return !ioctl(fd, FIONBIO, &nb);
#elif defined(F_SETFL) && defined(O_NONBLOCK)
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return false;
    }
    flags = block ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
    return !fcntl(fd, F_SETFL, flags);
#else
    UNUSED(fd);
    if (!block) {
        rvvm_warn("Non-blocking sockets are not supported on this OS");
    }
    return block;
#endif
}

static void net_handle_set_cloexec(net_handle_t fd)
{
#if defined(_WIN32) && !defined(UNDER_CE) && defined(HANDLE_FLAG_INHERIT)
    SetHandleInformation((HANDLE)fd, HANDLE_FLAG_INHERIT, 0);
#elif defined(F_SETFD) && defined(FD_CLOEXEC)
    fcntl(fd, F_SETFD, FD_CLOEXEC);
#else
    UNUSED(fd);
#endif
}

// Set CLOEXEC flag on created sockets to prevent handle leaking
// Optimize nonblocking connects on modern Linux and *BSD
static net_handle_t net_socket_create_ex(int domain, int type, int protocol, bool nonblock)
{
    net_handle_t fd = NET_HANDLE_INVALID;
#if defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
    // Create a blocking/non-blocking CLOEXEC socket in a single syscall (Linux, FreeBSD, OpenBSD, NetBSD...)
    fd = socket(domain, type | SOCK_CLOEXEC | (nonblock ? SOCK_NONBLOCK : 0), protocol);
    if (fd != NET_HANDLE_INVALID) {
        return fd;
    }
#endif
    if (fd == NET_HANDLE_INVALID) {
        // Fallback to separate syscalls for socket & CLOEXEC
        fd = socket(domain, type, protocol);
        if (fd != NET_HANDLE_INVALID) {
            net_handle_set_cloexec(fd);
        }
    }
    // Mark the socket as non-blocking
    if (fd != NET_HANDLE_INVALID && nonblock && !net_handle_set_blocking(fd, false)) {
        // Failed to set non-blocking mode
        net_close_handle(fd);
        return NET_HANDLE_INVALID;
    }
    return fd;
}

// Set CLOEXEC flag on accepted sockets, uniformly propagate blocking mode as on BSD stack
static net_handle_t net_accept_ex(net_handle_t listener, void* sock_addr, net_addrlen_t* addr_len)
{
    net_handle_t fd = NET_HANDLE_INVALID;
#if defined(__linux__)
    // NOTE: Linux accept(2) does not inherit nonblocking flag on accepted socket
    bool nonblock = !!(fcntl(listener, F_GETFL, 0) & O_NONBLOCK);
#if defined(__NR_accept4) && defined(SOCK_CLOEXEC) && defined(SOCK_NONBLOCK)
    // Use accept4() syscall to inherit non-blocking mode & set CLOEXEC at once
    fd = syscall(__NR_accept4, listener, sock_addr, addr_len, SOCK_CLOEXEC | (nonblock ? SOCK_NONBLOCK : 0));
#endif
#endif
    if (fd == NET_HANDLE_INVALID) {
        // Fallback to separate syscalls for accept & CLOEXEC
        fd = accept(listener, sock_addr, addr_len);
        if (fd != NET_HANDLE_INVALID) {
            net_handle_set_cloexec(fd);
#if defined(__linux__)
            // Always inherit non-blocking mode properly
            if (nonblock && !net_handle_set_blocking(fd, false)) {
                // Failed to set non-blocking mode
                net_close_handle(fd);
                return NET_HANDLE_INVALID;
            }
#endif
        }
    }
    return fd;
}

static net_handle_t net_create_handle(int type, int protocol, const net_addr_t* addr, bool nonblock)
{
    net_handle_t fd = NET_HANDLE_INVALID;
    if (!net_init()) {
        // Network subsystem initialization failed
        return fd;
    }

    if (!addr || addr->type == NET_TYPE_IPV4) {
        fd = net_socket_create_ex(AF_INET, type, protocol, nonblock);
#if defined(IPV6_NET_IMPL)
    } else if (addr->type == NET_TYPE_IPV6) {
#if defined(IPPROTO_ICMP) && defined(IPPROTO_ICMPV6)
        int proto = (protocol == IPPROTO_ICMP) ? IPPROTO_ICMPV6 : protocol;
        fd = net_socket_create_ex(AF_INET6, type, proto, nonblock);
#else
        fd = net_socket_create_ex(AF_INET6, type, protocol, nonblock);
#endif
#endif
    }
#if defined(IPPROTO_TCP) && defined(TCP_NODELAY)
    if (fd != NET_HANDLE_INVALID && type == SOCK_STREAM) {
        // Set TCP_NODELAY for low-latency TCP transmission, inherited in accept()
        int nodelay = 1;
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (void*)&nodelay, sizeof(nodelay));
    }
#endif
    return fd;
}

static bool net_bind_handle(net_handle_t fd, const net_addr_t* addr)
{
    if (!addr || addr->type == NET_TYPE_IPV4) {
        struct sockaddr_in sock_addr = {0};
        net_sockaddr_from_addr(&sock_addr, addr);
        return !bind(fd, (void*)&sock_addr, sizeof(sock_addr));
#if defined(IPV6_NET_IMPL)
    } else if (addr->type == NET_TYPE_IPV6) {
#if defined(IPPROTO_IPV6) && defined(IPV6_V6ONLY)
        // Disable dual-stack explicitly (may be configurable in future)
        int v6only = 1;
        setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, (void*)&v6only, sizeof(v6only));
#endif
        struct sockaddr_in6 sock_addr = {0};
        net_sockaddr6_from_addr(&sock_addr, addr);
        return !bind(fd, (void*)&sock_addr, sizeof(sock_addr));
#endif
    }
    return false;
}

static inline bool net_conn_initiated(void)
{
#if defined(_WIN32)
    return WSAGetLastError() == WSAEWOULDBLOCK;
#else
    return errno == EINPROGRESS;
#endif
}

static bool net_connect_handle(net_handle_t fd, const net_addr_t* addr)
{
    if (!addr || addr->type == NET_TYPE_IPV4) {
        struct sockaddr_in sock_addr = {0};
        net_sockaddr_from_addr(&sock_addr, addr);
        return !connect(fd, (struct sockaddr*)&sock_addr, sizeof(sock_addr)) || net_conn_initiated();
#if defined(IPV6_NET_IMPL)
    } else if (addr->type == NET_TYPE_IPV6) {
        struct sockaddr_in6 sock_addr = {0};
        net_sockaddr6_from_addr(&sock_addr, addr);
        return !connect(fd, (struct sockaddr*)&sock_addr, sizeof(sock_addr)) || net_conn_initiated();
#endif
    }
    return false;
}

// Wrap native handles in net_sock_t
static net_sock_t* net_wrap_handle(net_handle_t fd)
{
    if (fd != NET_HANDLE_INVALID) {
        net_sock_t* sock = safe_new_obj(net_sock_t);
        sock->fd         = fd;
        return sock;
    }
    return NULL;
}

// Wrap assigned local address after net_bind_handle()
static net_sock_t* net_init_localaddr(net_sock_t* sock, const net_addr_t* addr)
{
    if (sock) {
        if (!addr || addr->type == NET_TYPE_IPV4) {
            struct sockaddr_in sock_addr = {0};
            net_addrlen_t      addr_len  = sizeof(struct sockaddr_in);
            // Win32 getsockname may not set sin_family/sin_addr...
            net_sockaddr_from_addr(&sock_addr, addr);
            getsockname(sock->fd, (struct sockaddr*)&sock_addr, &addr_len);
            net_addr_from_sockaddr(&sock->addr, &sock_addr);
#if defined(IPV6_NET_IMPL)
        } else if (addr->type == NET_TYPE_IPV6) {
            struct sockaddr_in6 sock_addr = {0};
            net_addrlen_t       addr_len  = sizeof(struct sockaddr_in6);
            net_sockaddr6_from_addr(&sock_addr, addr);
            getsockname(sock->fd, (struct sockaddr*)&sock_addr, &addr_len);
            net_addr_from_sockaddr6(&sock->addr, &sock_addr);
#endif
        }
    }
    return sock;
}

static int32_t net_last_error(void)
{
#if defined(_WIN32)
    int err = WSAGetLastError();
    if (err == WSAEWOULDBLOCK || err == WSAEINTR) {
        return NET_ERR_BLOCK;
    }
    if (err == WSAECONNRESET) {
        return NET_ERR_RESET;
    }
    return NET_ERR_UNKNOWN;
#else
    int err = errno;
    if (err == EAGAIN || err == EWOULDBLOCK || err == EINTR) {
        return NET_ERR_BLOCK;
    }
    if (err == ECONNRESET) {
        return NET_ERR_RESET;
    }
    return NET_ERR_UNKNOWN;
#endif
}

#if defined(SELECT_NET_IMPL)

/*
 * Internal net_poll select() implementation helpers
 */

// Wake up net_poll_wait() loop to update watched sockets
static void net_poll_select_wake(net_poll_t* poll)
{
    if (atomic_load_uint32(&poll->waiters)) {
        char tmp = 0;
        net_tcp_send(poll->wake_sock[1], &tmp, sizeof(tmp));
    }
}

static void net_poll_select_set_flags(net_poll_t* poll, net_sock_t* sock, uint32_t flags)
{
    if (flags & NET_POLL_RECV) {
        FD_SET(sock->fd, &poll->r_set);
    } else {
        FD_CLR(sock->fd, &poll->r_set);
    }
    if (flags & NET_POLL_SEND) {
        FD_SET(sock->fd, &poll->w_set);
    } else {
        FD_CLR(sock->fd, &poll->w_set);
    }
}

// Add socket to net_poll watchlist
static bool net_poll_select_add(net_poll_t* poll, net_sock_t* sock, const net_event_t* event)
{
    bool ret = false;
    scoped_spin_lock (&poll->lock) {
        if (FD_ISSET(sock->fd, &poll->r_set) || FD_ISSET(sock->fd, &poll->w_set)) {
            // Socket already monitored
            break;
        }

#if defined(_WIN32)
        size_t num_sockets = vector_size(poll->events);
#else
        size_t num_sockets = sock->fd;
#endif
        if (num_sockets >= FD_SETSIZE) {
            // Too much sockets on a single net_poll select instance
            DO_ONCE(rvvm_warn("select(): ignoring sockets above FD_SETSIZE (%d)", (uint32_t)FD_SETSIZE));
            break;
        }

#if !defined(_WIN32)
        // Mark max_fd for select() on POSIX
        if (poll->max_fd < sock->fd) {
            poll->max_fd = sock->fd;
        }
#endif

        if (event) {
            // Add new socket monitor
            net_monitor_t* monitor = safe_new_obj(net_monitor_t);
            monitor->poll          = poll;
            monitor->sock          = sock;
            monitor->data          = event->data;
            vector_push_back(poll->events, monitor);
            vector_push_back(sock->watchers, monitor);

            // Watch for event flags (NET_POLL_RECV is mandatory)
            net_poll_select_set_flags(poll, sock, event->flags | NET_POLL_RECV);
        } else {
            // Add internal wakeup socket
            net_poll_select_set_flags(poll, sock, NET_POLL_RECV);
        }
        ret = true;
    }
    if (ret) {
        // Wake up waiters in select() to watch for newly added socket
        net_poll_select_wake(poll);
    }
    return ret;
}

// Modify net_poll socket watch flags / data
static bool net_poll_select_mod(net_poll_t* poll, net_sock_t* sock, const net_event_t* event)
{
    bool ret  = false;
    bool wake = false;
    scoped_spin_lock (&poll->lock) {
        vector_foreach (sock->watchers, i) {
            net_monitor_t* monitor = vector_at(sock->watchers, i);
            if (monitor->poll == poll) {
                wake          = !FD_ISSET(sock->fd, &poll->w_set) && (event->flags & NET_POLL_SEND);
                monitor->data = event->data;
                net_poll_select_set_flags(poll, sock, event->flags | NET_POLL_RECV);
                ret = true;
                break;
            }
        }
    }
    if (wake) {
        // Wake up waiters in select() to watch for modified socket flags
        net_poll_select_wake(poll);
    }
    return ret;
}

// Remove socket from specific net_poll watchlist (Or any net_poll instance if poll == NULL)
static bool net_poll_select_remove(net_poll_t* poll, net_sock_t* sock)
{
    bool ret = false;
    vector_foreach_back (sock->watchers, i) {
        net_monitor_t* monitor = vector_at(sock->watchers, i);
        if (monitor->poll == poll || !poll) {
            net_poll_t* curr_poll = monitor->poll;
            scoped_spin_lock (&curr_poll->lock) {
                // Stop watching events on this socket
                net_poll_select_set_flags(curr_poll, sock, 0);

                // Unlink watcher from net_poll
                vector_foreach_back (curr_poll->events, j) {
                    if (vector_at(curr_poll->events, j) == monitor) {
                        // Skip this socket in events buffer
                        if (curr_poll->consumed > j) {
                            curr_poll->consumed--;
                        }
                        vector_erase(curr_poll->events, j);
                        break;
                    }
                }
            }
            // Unlink watcher from socket
            vector_erase(sock->watchers, i);
            free(monitor);
            ret = true;
            if (poll) {
                // Break if we only wanted to remove socket from specific net_pol
                break;
            }
        }
    }
    return ret;
}

// Pump new net_poll events
// NOTE: Must be called with poll->lock held!
static bool net_poll_select_wait_events(net_poll_t* poll, uint32_t wait_ms)
{
    bool has_events = !!poll->consumed;
    if (has_events) {
        return true;
    } else {
        // No available buffered events to consume, call select()
        rvtimer_t   timer = {0};
        rvtimecmp_t cmp   = {0};
        if (wait_ms != NET_POLL_INF) {
            // Initizlize timeout timer & comparator
            rvtimer_init(&timer, 1000);
            rvtimecmp_init(&cmp, &timer);
            rvtimecmp_set(&cmp, wait_ms);
        }
        do {
            int             nfds   = poll->max_fd + 1;
            struct timeval  tv     = {0};
            struct timeval* tv_ptr = NULL;
            if (wait_ms != NET_POLL_INF) {
                // Use remaining timeout delay, short delay uses fast path without division
                if (wait_ms < 1000) {
                    tv.tv_usec = (wait_ms * 1000);
                } else {
                    tv.tv_sec  = (wait_ms / 1000);
                    tv.tv_usec = (wait_ms % 1000) * 1000;
                }
                tv_ptr = &tv;
            }

            // Copy over read/write socket watchlist to ready bitsets
            poll->r_ready = poll->r_set;
            poll->w_ready = poll->w_set;

            // Unlock data structures during select(), mark this thread as waiting
            spin_unlock(&poll->lock);
            atomic_add_uint32(&poll->waiters, 1);
            has_events = select(nfds, &poll->r_ready, &poll->w_ready, NULL, tv_ptr) > 0;
            atomic_sub_uint32(&poll->waiters, 1);
            spin_lock(&poll->lock);

            if (has_events && FD_ISSET(poll->wake_sock[0]->fd, &poll->r_ready)) {
                // Consume wakeup bytes, retry select()
                char buffer[256] = {0};
                net_tcp_recv(poll->wake_sock[0], buffer, sizeof(buffer));
                has_events = false;
            }
            if (!has_events && wait_ms != NET_POLL_INF) {
                // Update delay
                wait_ms = rvtimecmp_delay(&cmp);
            }
        } while (!has_events && (wait_ms == NET_POLL_INF || wait_ms));
    }
    return has_events;
}

static size_t net_poll_select_wait(net_poll_t* poll, net_event_t* events, size_t size, uint32_t wait_ms)
{
    size_t ret = 0;
    scoped_spin_lock (&poll->lock) {
        if (net_poll_select_wait_events(poll, wait_ms)) {
            // Loop over socket monitors, check fd_set flags
            for (size_t i = poll->consumed; i < vector_size(poll->events); ++i) {
                net_monitor_t* monitor = vector_at(poll->events, i);
                uint32_t       flags   = 0;
                if (FD_ISSET(monitor->sock->fd, &poll->r_ready)) {
                    flags |= NET_POLL_RECV;
                }
                if (FD_ISSET(monitor->sock->fd, &poll->w_ready)) {
                    flags |= NET_POLL_SEND;
                }
                if (flags) {
                    events[ret].data  = monitor->data;
                    events[ret].flags = flags;
                    if (++ret >= size) {
                        // We filled caller event buffer, leave trailing buffered events
                        poll->consumed = i + 1;
                        break;
                    }
                }
                if ((i + 1) == vector_size(poll->events)) {
                    // All events consumed, call select() next time
                    poll->consumed = 0;
                }
            }
        }
    }
    return ret;
}

#endif

/*
 * Public networking socket API
 */

size_t net_parse_ipv6(net_addr_t* addr, const char* str)
{
    net_addr_t  result      = {0};
    const char* parse       = str;
    bool        bracket     = parse[0] == '[';
    bool        skip_colon  = false;
    const char* colon_pair  = rvvm_strfind(parse, "::");
    size_t      bytes       = 0;
    size_t      right_start = 0;
    if (bracket) {
        parse++;
    }
    for (; bytes < 16; bytes += 2) {
        if (parse == colon_pair) {
            // Record location of encountered ::, skip it like a group
            parse       += 2;
            right_start  = bytes;
            skip_colon   = false;
            continue;
        } else if (skip_colon && parse[0] == ':') {
            // If we are beyond first hex group, skip prepending :
            parse++;
        } else if (parse[0] == 0 || (bracket && parse[0] == ']')) {
            // End of IPv6
            break;
        }
        // Parse hex group
        size_t   len = 0;
        uint16_t hex = str_to_uint_base(parse, &len, 16);
        if (!len || len > 4) {
            // Hex parsing failed or pair too long
            return 0;
        }
        write_uint16_be_m(result.ip + bytes, hex);
        parse      += len;
        skip_colon  = true;
    }
    if (colon_pair) {
        // Align fields at the right of colon pair to end of IPv6, zero hole
        memmove(result.ip + 16 - (bytes - right_start), result.ip + right_start, bytes - right_start);
        memset(result.ip + right_start, 0, 16 - bytes);
    } else if (bytes != 16) {
        // Not enough hex groups and no colon pair
        return 0;
    }
    if (bracket) {
        if (parse[0] != ']') {
            // Missing closing ]
            return 0;
        }
        parse++;
    }
    if (addr) {
        memcpy(addr, &result, sizeof(net_addr_t));
        addr->type = NET_TYPE_IPV6;
    }
    return parse - str;
}

size_t net_parse_ipv4(net_addr_t* addr, const char* str)
{
    net_addr_t  result = {0};
    const char* parse  = str;
    for (size_t i = 0; i < 4; ++i) {
        size_t len   = 0;
        result.ip[i] = str_to_uint_base(parse, &len, 10);
        if (!len) {
            // Integer parsing failed
            return 0;
        }
        parse += len;
        if (i < 3 && parse[0] == '.') {
            parse++;
        }
    }
    if (addr) {
        memcpy(addr, &result, sizeof(net_addr_t));
        addr->type = NET_TYPE_IPV4;
    }
    return parse - str;
}

size_t net_parse_addr(net_addr_t* addr, const char* str)
{
    const char* parse      = str;
    const char* colon      = rvvm_strfind(parse, ":");
    bool        ipv6       = colon && rvvm_strfind(colon + 1, ":"); // More than a single :
    bool        ipv4       = !!rvvm_strfind(parse, ".");
    bool        parse_port = false;
    size_t      ip_len     = 0;
    if (ipv6) {
        ip_len = net_parse_ipv6(addr, str);
        if (!ip_len) {
            return 0;
        }
    } else if (ipv4) {
        ip_len = net_parse_ipv4(addr, str);
        if (!ip_len) {
            return 0;
        }
    } else if (rvvm_strfind(parse, "localhost") == parse) {
        ip_len = rvvm_strlen("localhost");
        if (addr) {
            *addr = net_ipv4_local_addr;
        }
    } else {
        parse_port = true;
    }
    parse += ip_len;
    if (ip_len && parse[0] == ':') {
        parse_port = true;
        parse++;
    }
    if (parse_port) {
        size_t   len  = 0;
        uint16_t port = str_to_uint_base(parse, &len, 10);
        if (!len) {
            // Integer parsing failed
            return 0;
        }
        parse += len;
        if (addr) {
            addr->port = port;
        }
    }
    return parse - str;
}

net_sock_t* net_tcp_listen(const net_addr_t* addr)
{
    net_handle_t fd = net_create_handle(SOCK_STREAM, 0, addr, false);
    if (fd == NET_HANDLE_INVALID) {
        return NULL;
    }
#if defined(SOL_SOCKET) && defined(SO_REUSEADDR)
    // Prevent bind errors due to TIME_WAIT
    int reuse = 1;
    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void*)&reuse, sizeof(reuse));
#endif
    // Try backlog of 65535, fallback to 255
    if (!net_bind_handle(fd, addr) || (listen(fd, 65535) && listen(fd, 255))) {
        net_close_handle(fd);
        return NULL;
    }

    return net_init_localaddr(net_wrap_handle(fd), addr);
}

net_sock_t* net_tcp_accept(net_sock_t* listener)
{
    net_sock_t* sock = NULL;
    if (listener == NULL) {
        return NULL;
    }
    if (listener->addr.type == NET_TYPE_IPV4) {
        struct sockaddr_in sock_addr = {0};
        net_addrlen_t      addr_len  = sizeof(struct sockaddr_in);

        sock = net_wrap_handle(net_accept_ex(listener->fd, &sock_addr, &addr_len));
        if (sock) {
            net_addr_from_sockaddr(&sock->addr, &sock_addr);
        }
#if defined(IPV6_NET_IMPL)
    } else if (listener->addr.type == NET_TYPE_IPV6) {
        struct sockaddr_in6 sock_addr = {0};
        net_addrlen_t       addr_len  = sizeof(struct sockaddr_in6);

        sock = net_wrap_handle(net_accept_ex(listener->fd, &sock_addr, &addr_len));
        if (sock) {
            net_addr_from_sockaddr6(&sock->addr, &sock_addr);
        }
#endif
    }
    return sock;
}

net_sock_t* net_tcp_connect(const net_addr_t* dst, const net_addr_t* src, bool block)
{
    if (!dst) {
        return NULL;
    }
    // Create a nonblocking socket if needed
    net_handle_t fd = net_create_handle(SOCK_STREAM, 0, dst, !block);
    if (fd == NET_HANDLE_INVALID) {
        return NULL;
    }
    // Bind to local address if needed
    if (src) {
#if defined(IPPROTO_IP) && defined(IP_BIND_ADDRESS_NO_PORT)
        if (!src->port) {
            // Prevent bind errors due to ephemeral port exhaustion
            // Kernel now knows we won't listen() and allows local 2-tuple reuse
            int noport = 1;
            setsockopt(fd, IPPROTO_IP, IP_BIND_ADDRESS_NO_PORT, (void*)&noport, sizeof(noport));
        }
#endif
#if defined(SOL_SOCKET) && defined(SO_REUSEADDR)
        if (src->port) {
            // Allow connecting to different destinations from a single local port
            int reuse = 1;
            setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, (void*)&reuse, sizeof(reuse));
        }
#endif
        if (!net_bind_handle(fd, src)) {
            net_close_handle(fd);
            return NULL;
        }
    }

    if (!net_connect_handle(fd, dst)) {
        net_close_handle(fd);
        return NULL;
    }

    net_sock_t* sock = net_wrap_handle(fd);
    if (sock) {
        sock->addr = *dst;
    }

    return sock;
}

bool net_tcp_sockpair(net_sock_t* pair[2])
{
    net_sock_t* listener = net_tcp_listen(NET_IPV4_LOCAL);
    pair[0]              = net_tcp_connect(net_sock_addr(listener), NULL, false);
    pair[1]              = net_tcp_accept(listener);
    net_sock_close(listener);
    if (net_tcp_status(pair[0]) && net_tcp_status(pair[1])) {
        return true;
    }
    net_sock_close(pair[0]);
    net_sock_close(pair[1]);
    pair[0] = NULL;
    pair[1] = NULL;
    return false;
}

bool net_tcp_status(net_sock_t* sock)
{
    if (!sock) {
        return false;
    }
    if (sock->addr.type == NET_TYPE_IPV4) {
        struct sockaddr_in sock_addr = {0};
        net_addrlen_t      addr_len  = sizeof(struct sockaddr_in);
        return !getpeername(sock->fd, (struct sockaddr*)&sock_addr, &addr_len);
#if defined(IPV6_NET_IMPL)
    } else if (sock->addr.type == NET_TYPE_IPV6) {
        struct sockaddr_in6 sock_addr = {0};
        net_addrlen_t       addr_len  = sizeof(struct sockaddr_in6);
        return !getpeername(sock->fd, (struct sockaddr*)&sock_addr, &addr_len);
#endif
    }
    return false;
}

bool net_tcp_shutdown(net_sock_t* sock)
{
    return sock && !shutdown(sock->fd, 1);
}

int32_t net_tcp_send(net_sock_t* sock, const void* buffer, size_t size)
{
    if (likely(sock)) {
        int ret = send(sock->fd, buffer, size, MSG_NOSIGNAL);
        if (ret < 0) {
            return net_last_error();
        }
        return ret;
    }
    return NET_ERR_RESET;
}

int32_t net_tcp_recv(net_sock_t* sock, void* buffer, size_t size)
{
    if (likely(sock)) {
        int ret = recv(sock->fd, buffer, size, 0);
        if (ret == 0) {
            return NET_ERR_DISCONNECT;
        }
        if (ret < 0) {
            return net_last_error();
        }
        return ret;
    }
    return NET_ERR_RESET;
}

net_sock_t* net_udp_bind(const net_addr_t* addr)
{
    net_handle_t fd = net_create_handle(SOCK_DGRAM, 0, addr, false);
    if (fd == NET_HANDLE_INVALID) {
        return NULL;
    }
    if (!net_bind_handle(fd, addr)) {
        net_close_handle(fd);
        return NULL;
    }
    return net_init_localaddr(net_wrap_handle(fd), addr);
}

size_t net_udp_send(net_sock_t* sock, const void* buffer, size_t size, const net_addr_t* addr)
{
    if (likely(sock)) {
        int ret = 0;
        if (sock->addr.type == NET_TYPE_IPV4) {
            struct sockaddr_in sock_addr;
            net_sockaddr_from_addr(&sock_addr, addr);
            ret = sendto(sock->fd, buffer, size, 0, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
#if defined(IPV6_NET_IMPL)
        } else if (sock->addr.type == NET_TYPE_IPV6) {
            struct sockaddr_in6 sock_addr;
            net_sockaddr6_from_addr(&sock_addr, addr);
            ret = sendto(sock->fd, buffer, size, 0, (struct sockaddr*)&sock_addr, sizeof(sock_addr));
#endif
        }
        if (ret > 0) {
            return ret;
        }
    }
    return 0;
}

int32_t net_udp_recv(net_sock_t* sock, void* buffer, size_t size, net_addr_t* addr)
{
    if (likely(sock)) {
        int ret = 0;
        if (sock->addr.type == NET_TYPE_IPV4) {
            struct sockaddr_in sock_addr = {0};
            net_addrlen_t      addr_len  = sizeof(struct sockaddr_in);

            ret = recvfrom(sock->fd, buffer, size, 0, (struct sockaddr*)&sock_addr, &addr_len);
            net_addr_from_sockaddr(addr, &sock_addr);
#if defined(IPV6_NET_IMPL)
        } else if (sock->addr.type == NET_TYPE_IPV6) {
            struct sockaddr_in6 sock_addr = {0};
            net_addrlen_t       addr_len  = sizeof(struct sockaddr_in6);

            ret = recvfrom(sock->fd, buffer, size, 0, (struct sockaddr*)&sock_addr, &addr_len);
            net_addr_from_sockaddr6(addr, &sock_addr);
#endif
        }
        if (ret < 0) {
            return net_last_error();
        }
        return ret;
    }
    return NET_ERR_RESET;
}

/*
 * DGRAM ICMP sockets, AFAIK only supported on linux now
 */
net_sock_t* net_icmp_bind(net_addr_t* addr)
{
#ifdef IPPROTO_ICMP
    net_handle_t fd = net_create_handle(SOCK_DGRAM, IPPROTO_ICMP, addr, false);
    uint16_t id = addr->port;
    addr->port = 0;
    if (unlikely(fd == NET_HANDLE_INVALID)) {
        goto eperm;
    }
    if (!net_bind_handle(fd, addr)) {
        net_close_handle(fd);
        goto eperm;
    }
    net_sock_t* sock = net_wrap_handle(fd);
    if (!sock) {
        net_close_handle(fd);
        return NULL;
    }
    sock->addr.port = id;
    return sock;
eperm:
#endif
    UNUSED(addr);
    return NULL;
}

size_t net_icmp_send(net_sock_t* sock, const void* buffer, size_t size, const net_addr_t* addr)
{
    return net_udp_send(sock, buffer, size, addr);
}

int32_t net_icmp_recv(net_sock_t* sock, void* buffer, size_t size, net_addr_t* addr)
{
    return net_udp_recv(sock, buffer, size, addr);
}

uint16_t net_icmp_id(net_sock_t* sock) {
    return sock->addr.port;
}


/*
 * Generic socket operations
 */

net_addr_t* net_sock_addr(net_sock_t* sock)
{
    return sock ? &sock->addr : NULL;
}

uint16_t net_sock_port(net_sock_t* sock)
{
    return sock ? sock->addr.port : 0;
}

bool net_sock_set_blocking(net_sock_t* sock, bool block)
{
    return sock && net_handle_set_blocking(sock->fd, block);
}

void net_sock_close(net_sock_t* sock)
{
    if (likely(sock)) {
#if defined(SELECT_NET_IMPL)
        net_poll_select_remove(NULL, sock);
        vector_free(sock->watchers);
#endif
        net_close_handle(sock->fd);
        free(sock);
    }
}

/*
 * Network event polling
 */

net_poll_t* net_poll_create(void)
{
    if (!net_init()) {
        // Network subsystem initialization failed
        return NULL;
    }
    net_poll_t* poll = safe_new_obj(net_poll_t);
#if defined(EPOLL_NET_IMPL)
    poll->fd = epoll_create(16);
    if (poll->fd < 0) {
        net_poll_close(poll);
        return NULL;
    }
    net_handle_set_cloexec(poll->fd);
#elif defined(KQUEUE_NET_IMPL)
    poll->fd = kqueue();
    if (poll->fd < 0) {
        net_poll_close(poll);
        return NULL;
    }
    net_handle_set_cloexec(poll->fd);
#else
    FD_ZERO(&poll->r_set);
    FD_ZERO(&poll->w_set);
    if (!net_tcp_sockpair(poll->wake_sock) || !net_poll_select_add(poll, poll->wake_sock[0], NULL)) {
        // Failed to register wakeup socket
        net_poll_close(poll);
        return NULL;
    }
#endif
    return poll;
}

bool net_poll_add(net_poll_t* poll, net_sock_t* sock, const net_event_t* event)
{
    if (likely(poll && sock && event)) {
#if defined(EPOLL_NET_IMPL)
        struct epoll_event ev = {
            .events   = EPOLLIN | ((event->flags & NET_POLL_SEND) ? EPOLLOUT : 0),
            .data.ptr = event->data,
        };
        return !epoll_ctl(poll->fd, EPOLL_CTL_ADD, sock->fd, &ev);
#elif defined(KQUEUE_NET_IMPL)
        struct kevent ev[3] = {0};
        EV_SET(&ev[0], sock->fd, EVFILT_READ, EV_ADD, 0, 0, event->data);
        EV_SET(&ev[1], sock->fd, EVFILT_WRITE, EV_ADD, 0, 0, event->data);
        if (event->flags & NET_POLL_SEND) {
            EV_SET(&ev[2], sock->fd, EVFILT_WRITE, EV_ENABLE, 0, 0, event->data);
        } else {
            EV_SET(&ev[2], sock->fd, EVFILT_WRITE, EV_DISABLE, 0, 0, event->data);
        }
        return !kevent(poll->fd, ev, STATIC_ARRAY_SIZE(ev), NULL, 0, NULL);
#else
        return net_poll_select_add(poll, sock, event);
#endif
    }
    return false;
}

bool net_poll_mod(net_poll_t* poll, net_sock_t* sock, const net_event_t* event)
{
    if (likely(poll && sock && event)) {
#if defined(EPOLL_NET_IMPL)
        struct epoll_event ev = {
            .events   = EPOLLIN | ((event->flags & NET_POLL_SEND) ? EPOLLOUT : 0),
            .data.ptr = event->data,
        };
        return !epoll_ctl(poll->fd, EPOLL_CTL_MOD, sock->fd, &ev);
#elif defined(KQUEUE_NET_IMPL)
        // There's no way to completely mimic EPOLL_CTL_MOD on kqueue without extra syscalls
        return net_poll_add(poll, sock, event);
#else
        return net_poll_select_mod(poll, sock, event);
#endif
    }
    return false;
}

bool net_poll_remove(net_poll_t* poll, net_sock_t* sock)
{
    if (likely(poll && sock)) {
#if defined(EPOLL_NET_IMPL)
        struct epoll_event ev = {0};
        return !epoll_ctl(poll->fd, EPOLL_CTL_DEL, sock->fd, &ev);
#elif defined(KQUEUE_NET_IMPL)
        struct kevent ev[2] = {0};
        EV_SET(&ev[0], sock->fd, EVFILT_READ, EV_DELETE, 0, 0, NULL);
        EV_SET(&ev[1], sock->fd, EVFILT_WRITE, EV_DELETE, 0, 0, NULL);
        return !kevent(poll->fd, ev, STATIC_ARRAY_SIZE(ev), NULL, 0, NULL);
#else
        return net_poll_select_remove(poll, sock);
#endif
    }
    return false;
}

size_t net_poll_wait(net_poll_t* poll, net_event_t* events, size_t size, uint32_t wait_ms)
{
    size_t ret = 0;
    if (likely(poll && size)) {
#if defined(EPOLL_NET_IMPL)
        struct epoll_event ev[64];
        // Fetch events into temporary buffer
        int num_ev = epoll_wait(poll->fd, ev, EVAL_MIN(size, STATIC_ARRAY_SIZE(ev)), wait_ms);
        for (int i = 0; i < num_ev; ++i) {
            uint32_t flags = 0;
            if (ev[i].events & EPOLLOUT) {
                flags |= NET_POLL_SEND;
            }
            if ((ev[i].events & ~EPOLLOUT) || !flags) {
                flags |= NET_POLL_RECV;
            }
            if (ret < size) {
                events[ret].data  = ev[i].data.ptr;
                events[ret].flags = flags;
                ret++;
            }
        }
#elif defined(KQUEUE_NET_IMPL)
        struct kevent    ev[64];
        struct timespec  ts     = {0};
        struct timespec* ts_ptr = NULL;
        if (wait_ms != NET_POLL_INF) {
            // Short delay uses fast path without division
            if (wait_ms < 1000) {
                ts.tv_nsec = (wait_ms * 1000000);
            } else {
                ts.tv_sec  = (wait_ms / 1000);
                ts.tv_nsec = (wait_ms % 1000) * 1000000;
            }
            ts_ptr = &ts;
        }
        int num_ev = kevent(poll->fd, NULL, 0, ev, EVAL_MIN(size, STATIC_ARRAY_SIZE(ev)), ts_ptr);
        // Write out NET_POLL_RECV events
        for (int i = 0; i < num_ev; ++i) {
            if (ev[i].filter == EVFILT_READ && ret < size) {
                void* data        = (void*)ev[i].udata;
                events[ret].data  = data;
                events[ret].flags = NET_POLL_RECV;
                ret++;
            }
        }
        // Coalesce NET_POLL_SEND flags onto associated event entry
        size_t read_events = ret;
        for (int i = 0; i < num_ev; ++i) {
            if (ev[i].filter == EVFILT_WRITE) {
                void* data     = (void*)ev[i].udata;
                bool  coalesce = false;
                for (size_t j = 0; j < read_events; ++j) {
                    if (events[j].data == data) {
                        events[j].flags |= NET_POLL_SEND;
                        coalesce         = true;
                        break;
                    }
                }
                if (!coalesce && ret < size) {
                    events[ret].data  = data;
                    events[ret].flags = NET_POLL_SEND;
                    ret++;
                }
            }
        }
#else
        ret = net_poll_select_wait(poll, events, size, wait_ms);
#endif
    }
    return ret;
}

void net_poll_close(net_poll_t* poll)
{
    if (likely(poll)) {
#if defined(EPOLL_NET_IMPL) || defined(KQUEUE_NET_IMPL)
        net_close_handle(poll->fd);
#else
        // Unlink from related sockets
        vector_foreach_back (poll->events, i) {
            net_monitor_t* monitor = vector_at(poll->events, i);
            net_sock_t*    sock    = monitor->sock;
            vector_foreach_back (sock->watchers, j) {
                if (vector_at(sock->watchers, j) == monitor) {
                    vector_erase(sock->watchers, j);
                    break;
                }
            }
            free(monitor);
        }
        vector_free(poll->events);
        net_sock_close(poll->wake_sock[0]);
        net_sock_close(poll->wake_sock[1]);
#endif
        free(poll);
    }
}
