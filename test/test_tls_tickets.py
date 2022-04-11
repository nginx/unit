import socket

import pytest

pytest.importorskip('OpenSSL.SSL')
from OpenSSL.SSL import (
    TLSv1_2_METHOD,
    Context,
    Connection,
    Session,
    _lib,
)
from unit.applications.tls import TestApplicationTLS


class TestTLSTicket(TestApplicationTLS):
    prerequisites = {'modules': {'openssl': 'any'}}

    ticket = 'U1oDTh11mMxODuw12gS0EXX1E/PkZG13cJNQ6m5+6BGlfPTjNlIEw7PSVU3X1gTE'
    ticket2 = '5AV0DSYIYbZWZQB7fCnTHZmMxtotb/aXjam+n2XS79lTvX3Tq9xGqpC8XKNEF2lt'
    ticket80 = '6Pfil8lv/k8zf8MndPpfXaO5EAV6dhME6zs6CfUyq2yziynQwSywtKQMqHGnJ2HR\
49TZXi/Y4/8RSIO7QPsU51/HLR1gWIMhVM2m9yh93Bw='

    @pytest.fixture(autouse=True)
    def setup_method_fixture(self, request):
        self.certificate()

        listener_conf = {
            "pass": "routes",
            "tls": {
                "certificate": "default",
                "session": {"cache_size": 0, "tickets": True},
            },
        }

        assert 'success' in self.conf(
            {
                "listeners": {
                    "*:7080": listener_conf,
                    "*:7081": listener_conf,
                    "*:7082": listener_conf,
                },
                "routes": [{"action": {"return": 200}}],
                "applications": {},
            }
        ), 'load application configuration'

    def set_tickets(self, tickets=True, port=7080):
        assert 'success' in self.conf(
            {"cache_size": 0, "tickets": tickets},
            'listeners/*:' + str(port) + '/tls/session',
        )

    def connect(self, ctx=None, session=None, port=7080):
        sock = socket.create_connection(('127.0.0.1', port))

        if ctx is None:
            ctx = Context(TLSv1_2_METHOD)

        client = Connection(ctx, sock)
        client.set_connect_state()

        if session is not None:
            client.set_session(session)

        client.do_handshake()
        client.shutdown()

        return (
            client.get_session(),
            ctx,
            _lib.SSL_session_reused(client._ssl),
        )

    def has_ticket(self, sess):
        return _lib.SSL_SESSION_has_ticket(sess._session)

    @pytest.mark.skipif(
        not hasattr(_lib, 'SSL_SESSION_has_ticket'),
        reason='ticket check is not supported',
    )
    def test_tls_ticket(self):
        sess, ctx, reused = self.connect()
        assert self.has_ticket(sess), 'tickets True'
        assert not reused, 'tickets True not reused'

        sess, ctx, reused = self.connect(ctx, sess)
        assert self.has_ticket(sess), 'tickets True reconnect'
        assert reused, 'tickets True reused'

        self.set_tickets(tickets=False)

        sess, _, _ = self.connect()
        assert not self.has_ticket(sess), 'tickets False'

        assert 'success' in self.conf_delete(
            'listeners/*:7080/tls/session/tickets'
        ), 'tickets default configure'

        sess, _, _ = self.connect()
        assert not self.has_ticket(sess), 'tickets default (false)'

    @pytest.mark.skipif(
        not hasattr(_lib, 'SSL_SESSION_has_ticket'),
        reason='ticket check is not supported',
    )
    def test_tls_ticket_string(self):
        self.set_tickets(self.ticket)
        sess, ctx, _ = self.connect()
        assert self.has_ticket(sess), 'tickets string'

        sess2, _, reused = self.connect(ctx, sess)
        assert self.has_ticket(sess2), 'tickets string reconnect'
        assert reused, 'tickets string reused'

        sess2, _, reused = self.connect(ctx, sess, port=7081)
        assert self.has_ticket(sess2), 'connect True'
        assert not reused, 'connect True not reused'

        self.set_tickets(self.ticket2, port=7081)

        sess2, _, reused = self.connect(ctx, sess, port=7081)
        assert self.has_ticket(sess2), 'wrong ticket'
        assert not reused, 'wrong ticket not reused'

        self.set_tickets(self.ticket80)

        sess, ctx, _ = self.connect()
        assert self.has_ticket(sess), 'tickets string 80'

        sess2, _, reused = self.connect(ctx, sess)
        assert self.has_ticket(sess2), 'tickets string 80 reconnect'
        assert reused, 'tickets string 80 reused'

        sess2, _, reused = self.connect(ctx, sess, port=7081)
        assert self.has_ticket(sess2), 'wrong ticket 80'
        assert not reused, 'wrong ticket 80 not reused'

    @pytest.mark.skipif(
        not hasattr(_lib, 'SSL_SESSION_has_ticket'),
        reason='ticket check is not supported',
    )
    def test_tls_ticket_array(self):
        self.set_tickets([])

        sess, ctx, _ = self.connect()
        assert not self.has_ticket(sess), 'tickets array empty'

        self.set_tickets([self.ticket, self.ticket2])
        self.set_tickets(self.ticket, port=7081)
        self.set_tickets(self.ticket2, port=7082)

        sess, ctx, _ = self.connect()
        _, _, reused = self.connect(ctx, sess, port=7081)
        assert not reused, 'not last ticket'
        _, _, reused = self.connect(ctx, sess, port=7082)
        assert reused, 'last ticket'

        sess, ctx, _ = self.connect(port=7081)
        _, _, reused = self.connect(ctx, sess)
        assert reused, 'first ticket'

        sess, ctx, _ = self.connect(port=7082)
        _, _, reused = self.connect(ctx, sess)
        assert reused, 'second ticket'

        assert 'success' in self.conf_delete(
            'listeners/*:7080/tls/session/tickets/0'
        ), 'removed first ticket'
        assert 'success' in self.conf_post(
            '"' + self.ticket + '"', 'listeners/*:7080/tls/session/tickets'
        ), 'add new ticket to the end of array'

        sess, ctx, _ = self.connect()
        _, _, reused = self.connect(ctx, sess, port=7082)
        assert not reused, 'not last ticket 2'
        _, _, reused = self.connect(ctx, sess, port=7081)
        assert reused, 'last ticket 2'

    def test_tls_ticket_invalid(self):
        def check_tickets(tickets):
            assert 'error' in self.conf(
                {"tickets": tickets},
                'listeners/*:7080/tls/session',
            )

        check_tickets({})
        check_tickets('!?&^' * 16)
        check_tickets(self.ticket[:-2] + '!' + self.ticket[3:])
        check_tickets(self.ticket[:-1])
        check_tickets(self.ticket + 'b')
        check_tickets(self.ticket + 'blah')
        check_tickets([True, self.ticket, self.ticket2])
        check_tickets([self.ticket, 'blah', self.ticket2])
        check_tickets([self.ticket, self.ticket2, []])
