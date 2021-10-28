import socket
import time

import pytest
from OpenSSL.SSL import (
    TLSv1_2_METHOD,
    SESS_CACHE_CLIENT,
    OP_NO_TICKET,
    Context,
    Connection,
    _lib,
)
from unit.applications.tls import TestApplicationTLS
from unit.option import option


class TestTLSSession(TestApplicationTLS):
    prerequisites = {'modules': {'openssl': 'any'}}

    @pytest.fixture(autouse=True)
    def setup_method_fixture(self, request):
        self.certificate()

        assert 'success' in self.conf(
            {
                "listeners": {
                    "*:7080": {
                        "pass": "routes",
                        "tls": {"certificate": "default", "session": {}},
                    }
                },
                "routes": [{"action": {"return": 200}}],
                "applications": {},
            }
        ), 'load application configuration'

    def add_session(self, cache_size=None, timeout=None):
        session = {}

        if cache_size is not None:
            session['cache_size'] = cache_size
        if timeout is not None:
            session['timeout'] = timeout

        return self.conf(session, 'listeners/*:7080/tls/session')

    def connect(self, ctx=None, session=None):
        sock = socket.create_connection(('127.0.0.1', 7080))

        if ctx is None:
            ctx = Context(TLSv1_2_METHOD)
            ctx.set_session_cache_mode(SESS_CACHE_CLIENT)
            ctx.set_options(OP_NO_TICKET)

        client = Connection(ctx, sock)
        client.set_connect_state()

        if session is not None:
            client.set_session(session)

        client.do_handshake()
        client.shutdown()

        return (
            client,
            client.get_session(),
            ctx,
            _lib.SSL_session_reused(client._ssl),
        )

    def test_tls_session(self):
        client, sess, ctx, reused = self.connect()
        assert not reused, 'new connection'

        client, _, _, reused = self.connect(ctx, sess)
        assert not reused, 'no cache'

        assert 'success' in self.add_session(cache_size=1)

        client, sess, ctx, reused = self.connect()
        assert not reused, 'new connection cache'

        client, _, _, reused = self.connect(ctx, sess)
        assert reused, 'cache'

        client, _, _, reused = self.connect(ctx, sess)
        assert reused, 'cache 2'

        # check that at least one session of two is not reused

        client, sess, ctx, reused = self.connect()
        client2, sess2, ctx2, reused2 = self.connect()
        assert True not in [reused, reused2], 'new connection cache small'

        client, _, _, reused = self.connect(ctx, sess)
        client2, _, _, reused2 = self.connect(ctx2, sess2)
        assert False in [reused, reused2], 'cache small'

        # both sessions are reused

        assert 'success' in self.add_session(cache_size=2)

        client, sess, ctx, reused = self.connect()
        client2, sess2, ctx2, reused2 = self.connect()
        assert True not in [reused, reused2], 'new connection cache big'

        client, _, _, reused = self.connect(ctx, sess)
        client2, _, _, reused2 = self.connect(ctx2, sess2)
        assert False not in [reused, reused2], 'cache big'

    def test_tls_session_timeout(self):
        assert 'success' in self.add_session(cache_size=1, timeout=1)

        client, sess, ctx, reused = self.connect()
        assert not reused, 'new connection'

        client, _, _, reused = self.connect(ctx, sess)
        assert reused, 'no timeout'

        time.sleep(3)

        client, _, _, reused = self.connect(ctx, sess)
        assert not reused, 'timeout'

    def test_tls_session_invalid(self):
        assert 'error' in self.add_session(cache_size=-1)
        assert 'error' in self.add_session(cache_size={})
        assert 'error' in self.add_session(timeout=-1)
        assert 'error' in self.add_session(timeout={})
