/*
    Copyright (c) 2007-2018 Contributors as noted in the AUTHORS file

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

#include "testutil.hpp"

int main (void)
{
    char endpoint[256];
    size_t size = 256;
    unsigned int z, c, n, ref;
    fprintf (stderr, "test_address_tipc running...\n");

    void *ctx = zmq_init (1);
    assert (ctx);

    // test Port Name addressing
    void *sb = zmq_socket (ctx, ZMQ_REP);
    assert (sb);
    int rc = zmq_bind (sb, "tipc://{5560,0,0}");
    assert (rc == 0);

    void *sc = zmq_socket (ctx, ZMQ_REQ);
    assert (sc);
    rc = zmq_connect (sc, "tipc://{5560,0}@0.0.0");
    assert (rc == 0);

    bounce (sb, sc);

    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb);
    assert (rc == 0);

    // Test binding to random Port Identity
    sb = zmq_socket (ctx, ZMQ_REP);
    assert (sb);
    rc = zmq_bind (sb, "tipc://<*>");
    assert (rc == 0);

    // Test resolving assigned address, should return a properly formatted string
    rc = zmq_getsockopt (sb, ZMQ_LAST_ENDPOINT, &endpoint[0], &size);
    assert (rc == 0);

    rc = sscanf (&endpoint[0], "tipc://<%u.%u.%u:%u>", &z, &c, &n, &ref);
    assert (rc == 4);

    sc = zmq_socket (ctx, ZMQ_REQ);
    assert (sc);
    rc = zmq_connect (sc, endpoint);
    assert (rc == 0);

    bounce (sb, sc);

    rc = zmq_close (sc);
    assert (rc == 0);

    rc = zmq_close (sb);
    assert (rc == 0);


    // Test binding to a fixed address, should fail
    sb = zmq_socket (ctx, ZMQ_REP);
    assert (sb);
    rc = zmq_bind (sb, "tipc://<1.2.3:123123>");
    assert (rc == -1);
    assert (errno == EINVAL);

    // Test connecting to random identity, should fail
    rc = zmq_connect (sb, "tipc://<*>");
    assert (rc == -1);
    assert (errno == EINVAL);

    // Clean up
    rc = zmq_close (sb);
    assert (rc == 0);
    rc = zmq_ctx_term (ctx);
    assert (rc == 0);

    return 0;
}
