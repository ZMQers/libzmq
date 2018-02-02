/*
    Copyright (c) 2007-2016 Contributors as noted in the AUTHORS file

    This file is part of libzmq, the ZeroMQ core engine in C++.

    libzmq is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License (LGPL) as published
    by the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    As a special exception, the Contributors give you permission to link
    this library with independent modules to produce an executable,
    regardless of the license terms of these independent modules, and to
    copy and distribute the resulting executable under terms of your choice,
    provided that you also meet, for each linked independent module, the
    terms and conditions of the license of that module. An independent
    module is a module which is not derived from or based on this library.
    If you modify this library, you must extend this exception to your
    version of the library.

    libzmq is distributed in the hope that it will be useful, but WITHOUT
    ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
    FITNESS FOR A PARTICULAR PURPOSE. See the GNU Lesser General Public
    License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "precompiled.hpp"
#include "macros.hpp"
#include "ip.hpp"
#include "tcp.hpp"
#include "err.hpp"

#if !defined ZMQ_HAVE_WINDOWS
#include <fcntl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <linux/errqueue.h>
#endif

#if defined ZMQ_HAVE_OPENVMS
#include <ioctl.h>
#endif

//  defined in newer glibcs, but value is already a stable kernel API
#ifndef MSG_ZEROCOPY
#define MSG_ZEROCOPY 0x4000000
#endif
#ifndef SO_EE_ORIGIN_ZEROCOPY
#define SO_EE_ORIGIN_ZEROCOPY       5
#endif
#ifndef PACKET_TX_TIMESTAMP
#define PACKET_TX_TIMESTAMP     16
#endif

int zmq::tune_tcp_socket (fd_t s_)
{
    //  Disable Nagle's algorithm. We are doing data batching on 0MQ level,
    //  so using Nagle wouldn't improve throughput in anyway, but it would
    //  hurt latency.
    int nodelay = 1;
    int rc = setsockopt (s_, IPPROTO_TCP, TCP_NODELAY, (char*) &nodelay,
        sizeof (int));
    tcp_assert_tuning_error (s_, rc);
    if (rc != 0)
        return rc;

#ifdef ZMQ_HAVE_OPENVMS
    //  Disable delayed acknowledgements as they hurt latency significantly.
    int nodelack = 1;
    rc = setsockopt (s_, IPPROTO_TCP, TCP_NODELACK, (char*) &nodelack,
        sizeof (int));
    tcp_assert_tuning_error (s_, rc);
#endif
    return rc;
}

int zmq::set_tcp_send_buffer (fd_t sockfd_, int bufsize_)
{
    const int rc = setsockopt (sockfd_, SOL_SOCKET, SO_SNDBUF,
        (char*) &bufsize_, sizeof bufsize_);
    tcp_assert_tuning_error (sockfd_, rc);
    return rc;
}

int zmq::set_tcp_receive_buffer (fd_t sockfd_, int bufsize_)
{
    const int rc = setsockopt (sockfd_, SOL_SOCKET, SO_RCVBUF,
        (char *) &bufsize_, sizeof bufsize_);
    tcp_assert_tuning_error (sockfd_, rc);
    return rc;
}

int zmq::set_tcp_zero_copy (fd_t sockfd_)
{
    const int enable = 1;
    const int rc = setsockopt (sockfd_, SOL_SOCKET, SO_ZEROCOPY,
        &enable, sizeof enable);
    if (rc != 0 && errno == ENOPROTOOPT)
        return rc;
    tcp_assert_tuning_error (sockfd_, rc);
    return rc;
}

int zmq::tune_tcp_keepalives (fd_t s_, int keepalive_, int keepalive_cnt_,
        int keepalive_idle_, int keepalive_intvl_)
{
    // These options are used only under certain #ifdefs below.
    LIBZMQ_UNUSED (keepalive_);
    LIBZMQ_UNUSED (keepalive_cnt_);
    LIBZMQ_UNUSED (keepalive_idle_);
    LIBZMQ_UNUSED (keepalive_intvl_);

    // If none of the #ifdefs apply, then s_ is unused.
    LIBZMQ_UNUSED (s_);

    //  Tuning TCP keep-alives if platform allows it
    //  All values = -1 means skip and leave it for OS
#ifdef ZMQ_HAVE_WINDOWS
    if (keepalive_ != -1) {
        tcp_keepalive keepalive_opts;
        keepalive_opts.onoff = keepalive_;
        keepalive_opts.keepalivetime = keepalive_idle_ != -1 ?
                                            keepalive_idle_ * 1000 : 7200000;
        keepalive_opts.keepaliveinterval = keepalive_intvl_ != -1 ?
                                            keepalive_intvl_ * 1000 : 1000;
        DWORD num_bytes_returned;
        int rc = WSAIoctl (s_, SIO_KEEPALIVE_VALS, &keepalive_opts,
            sizeof (keepalive_opts), NULL, 0, &num_bytes_returned, NULL, NULL);
        tcp_assert_tuning_error (s_, rc);
        if (rc == SOCKET_ERROR)
            return rc;
    }
#else
#ifdef ZMQ_HAVE_SO_KEEPALIVE
    if (keepalive_ != -1) {
        int rc = setsockopt (s_, SOL_SOCKET, SO_KEEPALIVE,
                (char*) &keepalive_, sizeof (int));
        tcp_assert_tuning_error (s_, rc);
        if (rc != 0)
            return rc;

#ifdef ZMQ_HAVE_TCP_KEEPCNT
        if (keepalive_cnt_ != -1) {
            int rc = setsockopt (s_, IPPROTO_TCP, TCP_KEEPCNT,
                    &keepalive_cnt_, sizeof (int));
            tcp_assert_tuning_error (s_, rc);
            if (rc != 0)
                return rc;
        }
#endif // ZMQ_HAVE_TCP_KEEPCNT

#ifdef ZMQ_HAVE_TCP_KEEPIDLE
        if (keepalive_idle_ != -1) {
            int rc = setsockopt (s_, IPPROTO_TCP, TCP_KEEPIDLE,
                    &keepalive_idle_, sizeof (int));
            tcp_assert_tuning_error (s_, rc);
            if (rc != 0)
                return rc;
        }
#else // ZMQ_HAVE_TCP_KEEPIDLE
#ifdef ZMQ_HAVE_TCP_KEEPALIVE
        if (keepalive_idle_ != -1) {
            int rc = setsockopt (s_, IPPROTO_TCP, TCP_KEEPALIVE,
                    &keepalive_idle_, sizeof (int));
            tcp_assert_tuning_error (s_, rc);
            if (rc != 0)
                return rc;
        }
#endif // ZMQ_HAVE_TCP_KEEPALIVE
#endif // ZMQ_HAVE_TCP_KEEPIDLE

#ifdef ZMQ_HAVE_TCP_KEEPINTVL
        if (keepalive_intvl_ != -1) {
            int rc = setsockopt (s_, IPPROTO_TCP, TCP_KEEPINTVL,
                    &keepalive_intvl_, sizeof (int));
            tcp_assert_tuning_error (s_, rc);
            if (rc != 0)
                return rc;
        }
#endif // ZMQ_HAVE_TCP_KEEPINTVL
    }
#endif // ZMQ_HAVE_SO_KEEPALIVE
#endif // ZMQ_HAVE_WINDOWS
    
    return 0;
}

int zmq::tune_tcp_maxrt (fd_t sockfd_, int timeout_)
{
    if (timeout_ <= 0)
        return 0;

    LIBZMQ_UNUSED (sockfd_);

#if defined (ZMQ_HAVE_WINDOWS) && defined (TCP_MAXRT)
    // msdn says it's supported in >= Vista, >= Windows Server 2003
    timeout_ /= 1000;    // in seconds
    int rc = setsockopt (sockfd_, IPPROTO_TCP, TCP_MAXRT, (char*) &timeout_,
        sizeof (timeout_));
    tcp_assert_tuning_error (sockfd_, rc);
    return rc;
// FIXME: should be ZMQ_HAVE_TCP_USER_TIMEOUT
#elif defined (TCP_USER_TIMEOUT)
    int rc = setsockopt (sockfd_, IPPROTO_TCP, TCP_USER_TIMEOUT, &timeout_,
        sizeof (timeout_));
    tcp_assert_tuning_error (sockfd_, rc);
    return rc;
#endif
    return 0;
}

 int zmq::tcp_write (fd_t s_, const void *data_, size_t size_, bool *zero_copy)
{
#ifdef ZMQ_HAVE_WINDOWS

    int nbytes = send (s_, (char*) data_, (int) size_, 0);

    //  If not a single byte can be written to the socket in non-blocking mode
    //  we'll get an error (this may happen during the speculative write).
    const int last_error = WSAGetLastError ();
    if (nbytes == SOCKET_ERROR && last_error == WSAEWOULDBLOCK)
        return 0;

    //  Signalise peer failure.
    if (nbytes == SOCKET_ERROR && (
          last_error == WSAENETDOWN     ||
          last_error == WSAENETRESET    ||
          last_error == WSAEHOSTUNREACH ||
          last_error == WSAECONNABORTED ||
          last_error == WSAETIMEDOUT    ||
          last_error == WSAECONNRESET
        ))
        return -1;

    //  Circumvent a Windows bug:
    //  See https://support.microsoft.com/en-us/kb/201213
    //  See https://zeromq.jira.com/browse/LIBZMQ-195
    if (nbytes == SOCKET_ERROR && last_error == WSAENOBUFS)
        return 0;

    wsa_assert (nbytes != SOCKET_ERROR);
    return nbytes;

#else
    //  Zero copy send has its own cost, so it is not conveniente for small
    //  writes.
    //  TODO: fix heuristic: docs say 10 KB is the suggested value
    ssize_t nbytes = send (s_, data_, size_, size_ > 1024 && *zero_copy ? MSG_ZEROCOPY : 0);
    //  signal the caller that the send was zero-copy to avoid freeing the msg
    if (*zero_copy && size_ > 1024 && nbytes <= 0)
        *zero_copy = false;

    //  Fallback to normal send if zero copy fails
    if (nbytes == -1 && errno == ENOBUFS)
        nbytes = send (s_, data_, size_, 0);

    //  Several errors are OK. When speculative write is being done we may not
    //  be able to write a single byte from the socket. Also, SIGSTOP issued
    //  by a debugging tool can result in EINTR error.
    if (nbytes == -1 && (errno == EAGAIN || errno == EWOULDBLOCK ||
          errno == EINTR))
        return 0;

    //  Signalise peer failure.
    if (nbytes == -1) {
        errno_assert (errno != EACCES
                   && errno != EBADF
                   && errno != EDESTADDRREQ
                   && errno != EFAULT
                   && errno != EISCONN
                   && errno != EMSGSIZE
                   && errno != ENOMEM
                   && errno != ENOTSOCK
                   && errno != EOPNOTSUPP);
        return -1;
    }

    return static_cast <int> (nbytes);

#endif
}

int zmq::tcp_zero_copy_check_callbacks (fd_t s_, uint32_t *begin,
        uint32_t *end)
{
    struct msghdr msg = { };
    struct sock_extended_err *serr;
    struct cmsghdr *cm;
    int ret;
    char control_buffer[100] = { 0 };

    msg.msg_control = control_buffer;
    msg.msg_controllen = sizeof(100);

    ret = recvmsg(s_, &msg, MSG_ERRQUEUE);
    if (ret == -1 && errno == EAGAIN)
        return -1;
    if (ret == -1) {
        zmq_assert("recvmsg notification");
        return -1;
    }
    if (msg.msg_flags & MSG_CTRUNC) {
        zmq_assert("recvmsg notification: truncated");
        return -1;
    }

    cm = CMSG_FIRSTHDR(&msg);
    if (!cm) {
        zmq_assert("cmsg: no cmsg");
        return -1;
    }
    if (!((cm->cmsg_level == SOL_IP && cm->cmsg_type == IP_RECVERR)
            || (cm->cmsg_level == SOL_IPV6 && cm->cmsg_type == IPV6_RECVERR)
            || (cm->cmsg_level == SOL_PACKET
                    && cm->cmsg_type == PACKET_TX_TIMESTAMP))) {
        zmq_assert("serr: wrong type: %d.%d cm->cmsg_level, cm->cmsg_type");
        return -1;
    }

    serr = (sock_extended_err *)CMSG_DATA(cm);
    if (serr->ee_origin != SO_EE_ORIGIN_ZEROCOPY)
        zmq_assert("serr: wrong origin: %u  serr->ee_origin");
    if (serr->ee_errno != 0)
        zmq_assert("serr: wrong error code: %u serr->ee_errno");

    *end = serr->ee_data;
    *begin = serr->ee_info;

    return 0;
}

int zmq::tcp_read (fd_t s_, void *data_, size_t size_)
{
#ifdef ZMQ_HAVE_WINDOWS

    const int rc = recv (s_, (char*) data_, (int) size_, 0);

    //  If not a single byte can be read from the socket in non-blocking mode
    //  we'll get an error (this may happen during the speculative read).
    if (rc == SOCKET_ERROR) {
        const int last_error = WSAGetLastError ();
        if (last_error == WSAEWOULDBLOCK) {
            errno = EAGAIN;
        }
        else {
            wsa_assert (last_error == WSAENETDOWN ||
                last_error == WSAENETRESET        ||
                last_error == WSAECONNABORTED     ||
                last_error == WSAETIMEDOUT        ||
                last_error == WSAECONNRESET       ||
                last_error == WSAECONNREFUSED     ||
                last_error == WSAENOTCONN);
            errno = wsa_error_to_errno (last_error);
        }
    }

    return rc == SOCKET_ERROR ? -1 : rc;

#else

    const ssize_t rc = recv (s_, data_, size_, 0);

    //  Several errors are OK. When speculative read is being done we may not
    //  be able to read a single byte from the socket. Also, SIGSTOP issued
    //  by a debugging tool can result in EINTR error.
    if (rc == -1) {
        errno_assert (errno != EBADF
                   && errno != EFAULT
                   && errno != ENOMEM
                   && errno != ENOTSOCK);
        if (errno == EWOULDBLOCK || errno == EINTR)
            errno = EAGAIN;
    }

    return static_cast <int> (rc);

#endif
}

void zmq::tcp_assert_tuning_error (zmq::fd_t s_, int rc_)
{
    if (rc_ == 0)
        return;

    //  Check whether an error occurred
    int err = 0;
#ifdef ZMQ_HAVE_HPUX
    int len = sizeof err;
#else
    socklen_t len = sizeof err;
#endif
    
    int rc = getsockopt (s_, SOL_SOCKET, SO_ERROR, (char*) &err, &len);
    
    //  Assert if the error was caused by 0MQ bug.
    //  Networking problems are OK. No need to assert.
#ifdef ZMQ_HAVE_WINDOWS
    zmq_assert (rc == 0);
    if (err != 0) {
        wsa_assert (err == WSAECONNREFUSED
                 || err == WSAECONNRESET
                 || err == WSAECONNABORTED
                 || err == WSAEINTR
                 || err == WSAETIMEDOUT
                 || err == WSAEHOSTUNREACH
                 || err == WSAENETUNREACH
                 || err == WSAENETDOWN
                 || err == WSAENETRESET
                 || err == WSAEACCES
                 || err == WSAEINVAL
                 || err == WSAEADDRINUSE);
    }
#else
    //  Following code should handle both Berkeley-derived socket
    //  implementations and Solaris.
    if (rc == -1)
        err = errno;
    if (err != 0) {
        errno = err;
        errno_assert (
            errno == ECONNREFUSED ||
            errno == ECONNRESET ||
            errno == ECONNABORTED ||
            errno == EINTR ||
            errno == ETIMEDOUT ||
            errno == EHOSTUNREACH ||
            errno == ENETUNREACH ||
            errno == ENETDOWN ||
            errno == ENETRESET ||
            errno == EINVAL);
    }
#endif
}
