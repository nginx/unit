from packaging import version

from unit.applications.lang.node import ApplicationNode
from unit.applications.websockets import ApplicationWebsocket

prerequisites = {
    'modules': {'node': lambda v: version.parse(v) >= version.parse('14.16.0')}
}

client = ApplicationNode(es_modules=True)
ws = ApplicationWebsocket()


def assert_basic_application():
    resp = client.get()
    assert resp['headers']['Content-Type'] == 'text/plain', 'basic header'
    assert resp['body'] == 'Hello World\n', 'basic body'


def test_node_es_modules_loader_http():
    client.load('loader/es_modules_http', name="app.mjs")

    assert_basic_application()


def test_node_es_modules_loader_http_indirect():
    client.load('loader/es_modules_http_indirect', name="app.js")

    assert_basic_application()


def test_node_es_modules_loader_websockets():
    client.load('loader/es_modules_websocket', name="app.mjs")

    message = 'blah'

    _, sock, _ = ws.upgrade()

    ws.frame_write(sock, ws.OP_TEXT, message)
    frame = ws.frame_read(sock)

    assert message == frame['data'].decode('utf-8'), 'mirror'

    ws.frame_write(sock, ws.OP_TEXT, message)
    frame = ws.frame_read(sock)

    assert message == frame['data'].decode('utf-8'), 'mirror 2'

    sock.close()
