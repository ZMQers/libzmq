/*
    Copyright (c) 2007-2012 iMatix Corporation
    Copyright (c) 2011 250bpm s.r.o.
    Copyright (c) 2007-2011 Other contributors as noted in the AUTHORS file

    This file is part of 0MQ.

    0MQ is free software; you can redistribute it and/or modify it under
    the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    0MQ is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "../include/zmq.h"
#include <pthread.h>
#include <string.h>
#include "testutil.hpp"

// REQ socket events handled
static int req_socket_events;
// 2nd REQ socket events handled
static int req2_socket_events;
// REP socket events handled
static int rep_socket_events;

const char *addr;

// REQ socket monitor thread
static void *req_socket_monitor (void *ctx)
{
    zmq_event_t event;
    int rc;

    void *s = zmq_socket (ctx, ZMQ_PAIR);
    assert (s);

    rc = zmq_connect (s, "inproc://monitor.req");
    assert (rc == 0);
    while (true) {
        zmq_msg_t msg;
        zmq_msg_init (&msg);
        rc = zmq_msg_recv (&msg, s, 0);
        if (rc == -1 && zmq_errno() == ETERM)
            break;
        assert (rc != -1);

        memcpy (&event, zmq_msg_data (&msg), sizeof (event));
	assert (!strcmp (event.addr, addr));
        switch (event.event) {
            case ZMQ_EVENT_CONNECTED:
                assert (event.value > 0);
                req_socket_events |= ZMQ_EVENT_CONNECTED;
                req2_socket_events |= ZMQ_EVENT_CONNECTED;
                break;
            case ZMQ_EVENT_CONNECT_DELAYED:
                assert (event.value != 0);
                req_socket_events |= ZMQ_EVENT_CONNECT_DELAYED;
                break;
            case ZMQ_EVENT_CLOSE_FAILED:
                assert (event.value != 0);
                req_socket_events |= ZMQ_EVENT_CLOSE_FAILED;
                break;
            case ZMQ_EVENT_CLOSED:
                assert (event.value != 0);
                req_socket_events |= ZMQ_EVENT_CLOSED;
                break;
            case ZMQ_EVENT_DISCONNECTED:
                assert (event.value != 0);
                req_socket_events |= ZMQ_EVENT_DISCONNECTED;
                break;
        }
    }
    zmq_close (s);
    return NULL;
}

// 2nd REQ socket monitor thread
static void *req2_socket_monitor (void *ctx)
{
    zmq_event_t event;
    int rc;

    void *s = zmq_socket (ctx, ZMQ_PAIR);
    assert (s);

    rc = zmq_connect (s, "inproc://monitor.req2");
    assert (rc == 0);
    while (true) {
        zmq_msg_t msg;
        zmq_msg_init (&msg);
        rc = zmq_msg_recv (&msg, s, 0);
        if (rc == -1 && zmq_errno() == ETERM)
            break;
        assert (rc != -1);

        memcpy (&event, zmq_msg_data (&msg), sizeof (event));
	assert (!strcmp (event.addr, addr));
        switch (event.event) {
            case ZMQ_EVENT_CONNECTED:
                assert (event.value > 0);
                req2_socket_events |= ZMQ_EVENT_CONNECTED;
                break;
            case ZMQ_EVENT_CLOSED:
                assert (event.value != 0);
                req2_socket_events |= ZMQ_EVENT_CLOSED;
                break;
        }
    }
    zmq_close (s);
    return NULL;
}

// REP socket monitor thread
static void *rep_socket_monitor (void *ctx)
{
    zmq_event_t event;
    int rc;

    void *s = zmq_socket (ctx, ZMQ_PAIR);
    assert (s);

    rc = zmq_connect (s, "inproc://monitor.rep");
    assert (rc == 0);
    while (true) {
        zmq_msg_t msg;
        zmq_msg_init (&msg);
        rc = zmq_msg_recv (&msg, s, 0);
        if (rc == -1 && zmq_errno() == ETERM)
            break;
        assert (rc != -1);

        memcpy (&event, zmq_msg_data (&msg), sizeof (event));
	assert (!strcmp (event.addr, addr));
        switch (event.event) {
            case ZMQ_EVENT_LISTENING:
                assert (event.value > 0);
                rep_socket_events |= ZMQ_EVENT_LISTENING;
                break;
            case ZMQ_EVENT_ACCEPTED:
                assert (event.value > 0);
                rep_socket_events |= ZMQ_EVENT_ACCEPTED;
                break;
            case ZMQ_EVENT_CLOSE_FAILED:
                assert (event.value != 0);
                rep_socket_events |= ZMQ_EVENT_CLOSE_FAILED;
                break;
            case ZMQ_EVENT_CLOSED:
                assert (event.value != 0);
                rep_socket_events |= ZMQ_EVENT_CLOSED;
                break;
            case ZMQ_EVENT_DISCONNECTED:
                assert (event.value != 0);
                rep_socket_events |= ZMQ_EVENT_DISCONNECTED;
                break;
        }
        zmq_msg_close (&msg);
    }
    zmq_close (s);
    return NULL;
}

int main (void)
{
    int rc;
    void *req;
    void *req2;
    void *rep;
    pthread_t threads [3];

    addr = "tcp://127.0.0.1:5560";

    //  Create the infrastructure
    void *ctx = zmq_ctx_new ();
    assert (ctx);

    // REP socket
    rep = zmq_socket (ctx, ZMQ_REP);
    assert (rep);

    // Assert supported protocols
    rc =  zmq_socket_monitor (rep, addr, 0);
    assert (rc == -1);
    assert (zmq_errno() == EPROTONOSUPPORT);

    // Deregister monitor
    rc =  zmq_socket_monitor (rep, NULL, 0);
    assert (rc == 0);

    // REP socket monitor, all events
    rc = zmq_socket_monitor (rep, "inproc://monitor.rep", ZMQ_EVENT_ALL);
    assert (rc == 0);
    rc = pthread_create (&threads [0], NULL, rep_socket_monitor, ctx);
    assert (rc == 0);

    rc = zmq_bind (rep, addr);
    assert (rc == 0);

    // REQ socket
    req = zmq_socket (ctx, ZMQ_REQ);
    assert (req);

    // REQ socket monitor, all events
    rc = zmq_socket_monitor (req, "inproc://monitor.req", ZMQ_EVENT_ALL);
    assert (rc == 0);
    rc = pthread_create (&threads [1], NULL, req_socket_monitor, ctx);
    assert (rc == 0);

    rc = zmq_connect (req, addr);
    assert (rc == 0);

    bounce (rep, req);
    
    // 2nd REQ socket
    req2 = zmq_socket (ctx, ZMQ_REQ);
    assert (req2);

    // 2nd REQ socket monitor, connected event only
    rc = zmq_socket_monitor (req2, "inproc://monitor.req2", ZMQ_EVENT_CONNECTED);
    assert (rc == 0);
    rc = pthread_create (&threads [2], NULL, req2_socket_monitor, ctx);
    assert (rc == 0);

    rc = zmq_connect (req2, addr);
    assert (rc == 0);

    // Close the REP socket
    rc = zmq_close (rep);
    assert (rc == 0);

    // Allow some time for detecting error states
    struct timespec t = { 0, 250 * 1000000 };
    nanosleep (&t, NULL);

    //  Close the REQ socket
    rc = zmq_close (req);
    assert (rc == 0);

    //  Close the 2nd REQ socket
    rc = zmq_close (req2);
    assert (rc == 0);

    zmq_ctx_term (ctx);

    // Expected REP socket events
    assert (rep_socket_events & ZMQ_EVENT_LISTENING);
    assert (rep_socket_events & ZMQ_EVENT_ACCEPTED);
    assert (rep_socket_events & ZMQ_EVENT_CLOSED);

    // Expected REQ socket events
    assert (req_socket_events & ZMQ_EVENT_CONNECTED);
    assert (req_socket_events & ZMQ_EVENT_DISCONNECTED);
    assert (req_socket_events & ZMQ_EVENT_CLOSED);

    // Expected 2nd REQ socket events
    assert (req2_socket_events & ZMQ_EVENT_CONNECTED);
    assert (!(req2_socket_events & ZMQ_EVENT_CLOSED));

    pthread_exit (NULL);

    return 0 ;
}

