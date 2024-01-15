import os
import socket
from pathlib import Path

import pytest

from unit.applications.proto import ApplicationProto
from unit.utils import waitforfiles


client = ApplicationProto()


@pytest.fixture(autouse=True)
def setup_method_fixture(temp_dir):
    assets_dir = f'{temp_dir}/assets'

    Path(f'{assets_dir}/dir').mkdir(parents=True)
    Path(f'{assets_dir}/index.html').write_text('0123456789', encoding='utf-8')
    Path(f'{assets_dir}/README').write_text('readme', encoding='utf-8')
    Path(f'{assets_dir}/log.log').write_text('[debug]', encoding='utf-8')
    Path(f'{assets_dir}/dir/file').write_text('blah', encoding='utf-8')

    assert 'success' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "routes"}},
            "routes": [{"action": {"share": f'{assets_dir}$uri'}}],
            "settings": {
                "http": {
                    "static": {"mime_types": {"text/plain": [".log", "README"]}}
                }
            },
        }
    )


def test_static_index(temp_dir):
    def set_index(index):
        assert 'success' in client.conf(
            {"share": f'{temp_dir}/assets$uri', "index": index},
            'routes/0/action',
        ), 'configure index'

    set_index('README')
    assert client.get()['body'] == 'readme', 'index'

    client.conf_delete('routes/0/action/index')
    assert client.get()['body'] == '0123456789', 'delete index'

    set_index('')
    assert client.get()['status'] == 404, 'index empty'


def test_static_index_default():
    assert client.get(url='/index.html')['body'] == '0123456789', 'index'
    assert client.get(url='/')['body'] == '0123456789', 'index 2'
    assert client.get(url='//')['body'] == '0123456789', 'index 3'
    assert client.get(url='/.')['body'] == '0123456789', 'index 4'
    assert client.get(url='/./')['body'] == '0123456789', 'index 5'
    assert client.get(url='/?blah')['body'] == '0123456789', 'index vars'
    assert client.get(url='/#blah')['body'] == '0123456789', 'index anchor'
    assert client.get(url='/dir/')['status'] == 404, 'index not found'

    resp = client.get(url='/index.html/')
    assert resp['status'] == 404, 'index not found 2 status'
    assert (
        resp['headers']['Content-Type'] == 'text/html'
    ), 'index not found 2 Content-Type'


def test_static_index_invalid(skip_alert, temp_dir):
    skip_alert(r'failed to apply new conf')

    def check_index(index):
        assert 'error' in client.conf(
            {"share": f'{temp_dir}/assets$uri', "index": index},
            'routes/0/action',
        )

    check_index({})
    check_index(['index.html', '$blah'])


def test_static_large_file(temp_dir):
    file_size = 32 * 1024 * 1024
    with open(f'{temp_dir}/assets/large', 'wb') as f:
        f.seek(file_size - 1)
        f.write(b'\0')

    assert (
        len(client.get(url='/large', read_buffer_size=1024 * 1024)['body'])
        == file_size
    ), 'large file'


def test_static_etag(temp_dir):
    etag = client.get(url='/')['headers']['ETag']
    etag_2 = client.get(url='/README')['headers']['ETag']

    assert etag != etag_2, 'different ETag'
    assert etag == client.get(url='/')['headers']['ETag'], 'same ETag'

    with open(f'{temp_dir}/assets/index.html', 'w', encoding='utf-8') as f:
        f.write('blah')

    assert etag != client.get(url='/')['headers']['ETag'], 'new ETag'


def test_static_redirect():
    resp = client.get(url='/dir')
    assert resp['status'] == 301, 'redirect status'
    assert resp['headers']['Location'] == '/dir/', 'redirect Location'
    assert 'Content-Type' not in resp['headers'], 'redirect Content-Type'


def test_static_space_in_name(temp_dir):
    assets_dir = f'{temp_dir}/assets'

    Path(f'{assets_dir}/dir/file').rename(f'{assets_dir}/dir/fi le')

    assert waitforfiles(f'{assets_dir}/dir/fi le')
    assert client.get(url='/dir/fi le')['body'] == 'blah', 'file name'

    Path(f'{assets_dir}/dir').rename(f'{assets_dir}/di r')
    assert waitforfiles(f'{assets_dir}/di r/fi le')
    assert client.get(url='/di r/fi le')['body'] == 'blah', 'dir name'

    Path(f'{assets_dir}/di r').rename(f'{assets_dir}/ di r ')
    assert waitforfiles(f'{assets_dir}/ di r /fi le')
    assert (
        client.get(url='/ di r /fi le')['body'] == 'blah'
    ), 'dir name enclosing'

    assert (
        client.get(url='/%20di%20r%20/fi le')['body'] == 'blah'
    ), 'dir encoded'
    assert client.get(url='/ di r %2Ffi le')['body'] == 'blah', 'slash encoded'
    assert client.get(url='/ di r /fi%20le')['body'] == 'blah', 'file encoded'
    assert (
        client.get(url='/%20di%20r%20%2Ffi%20le')['body'] == 'blah'
    ), 'encoded'
    assert (
        client.get(url='/%20%64%69%20%72%20%2F%66%69%20%6C%65')['body']
        == 'blah'
    ), 'encoded 2'

    Path(f'{assets_dir}/ di r /fi le').rename(f'{assets_dir}/ di r / fi le ')
    assert waitforfiles(f'{assets_dir}/ di r / fi le ')
    assert (
        client.get(url='/%20di%20r%20/%20fi%20le%20')['body'] == 'blah'
    ), 'file name enclosing'

    try:
        Path(f'{temp_dir}/ф а').touch()
        utf8 = True

    except KeyboardInterrupt:
        raise

    except:
        utf8 = False

    if utf8:
        Path(f'{assets_dir}/ di r / fi le ').rename(
            f'{assets_dir}/ di r /фа йл'
        )
        assert waitforfiles(f'{assets_dir}/ di r /фа йл')
        assert client.get(url='/ di r /фа йл')['body'] == 'blah'

        Path(f'{assets_dir}/ di r ').rename(f'{assets_dir}/ди ректория')
        assert waitforfiles(f'{assets_dir}/ди ректория/фа йл')
        assert (
            client.get(url='/ди ректория/фа йл')['body'] == 'blah'
        ), 'dir name 2'


def test_static_unix_socket(temp_dir):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.bind(f'{temp_dir}/assets/unix_socket')

    assert client.get(url='/unix_socket')['status'] == 404, 'socket'

    sock.close()


def test_static_unix_fifo(temp_dir):
    os.mkfifo(f'{temp_dir}/assets/fifo')

    assert client.get(url='/fifo')['status'] == 404, 'fifo'


def test_static_method():
    resp = client.head()
    assert resp['status'] == 200, 'HEAD status'
    assert resp['body'] == '', 'HEAD empty body'

    assert client.delete()['status'] == 405, 'DELETE'
    assert client.post()['status'] == 405, 'POST'
    assert client.put()['status'] == 405, 'PUT'


def test_static_path():
    assert client.get(url='/dir/../dir/file')['status'] == 200, 'relative'

    assert client.get(url='./')['status'] == 400, 'path invalid'
    assert client.get(url='../')['status'] == 400, 'path invalid 2'
    assert client.get(url='/..')['status'] == 400, 'path invalid 3'
    assert client.get(url='../assets/')['status'] == 400, 'path invalid 4'
    assert client.get(url='/../assets/')['status'] == 400, 'path invalid 5'


def test_static_two_clients():
    sock = client.get(no_recv=True)
    sock2 = client.get(no_recv=True)

    assert sock.recv(1) == b'H', 'client 1'
    assert sock2.recv(1) == b'H', 'client 2'
    assert sock.recv(1) == b'T', 'client 1 again'
    assert sock2.recv(1) == b'T', 'client 2 again'

    sock.close()
    sock2.close()


def test_static_mime_types():
    assert 'success' in client.conf(
        {
            "text/x-code/x-blah/x-blah": "readme",
            "text/plain": [".html", ".log", "file"],
        },
        'settings/http/static/mime_types',
    ), 'configure mime_types'

    assert (
        client.get(url='/README')['headers']['Content-Type']
        == 'text/x-code/x-blah/x-blah'
    ), 'mime_types string case insensitive'
    assert (
        client.get(url='/index.html')['headers']['Content-Type'] == 'text/plain'
    ), 'mime_types html'
    assert (
        client.get(url='/')['headers']['Content-Type'] == 'text/plain'
    ), 'mime_types index default'
    assert (
        client.get(url='/dir/file')['headers']['Content-Type'] == 'text/plain'
    ), 'mime_types file in dir'


def test_static_mime_types_partial_match():
    assert 'success' in client.conf(
        {
            "text/x-blah": ["ile", "fil", "f", "e", ".file"],
        },
        'settings/http/static/mime_types',
    ), 'configure mime_types'
    assert 'Content-Type' not in client.get(url='/dir/file'), 'partial match'


def test_static_mime_types_reconfigure():
    assert 'success' in client.conf(
        {
            "text/x-code": "readme",
            "text/plain": [".html", ".log", "file"],
        },
        'settings/http/static/mime_types',
    ), 'configure mime_types'

    assert client.conf_get('settings/http/static/mime_types') == {
        'text/x-code': 'readme',
        'text/plain': ['.html', '.log', 'file'],
    }, 'mime_types get'
    assert (
        client.conf_get('settings/http/static/mime_types/text%2Fx-code')
        == 'readme'
    ), 'mime_types get string'
    assert client.conf_get('settings/http/static/mime_types/text%2Fplain') == [
        '.html',
        '.log',
        'file',
    ], 'mime_types get array'
    assert (
        client.conf_get('settings/http/static/mime_types/text%2Fplain/1')
        == '.log'
    ), 'mime_types get array element'

    assert 'success' in client.conf_delete(
        'settings/http/static/mime_types/text%2Fplain/2'
    ), 'mime_types remove array element'
    assert (
        'Content-Type' not in client.get(url='/dir/file')['headers']
    ), 'mime_types removed'

    assert 'success' in client.conf_post(
        '"file"', 'settings/http/static/mime_types/text%2Fplain'
    ), 'mime_types add array element'
    assert (
        client.get(url='/dir/file')['headers']['Content-Type'] == 'text/plain'
    ), 'mime_types reverted'

    assert 'success' in client.conf(
        '"file"', 'settings/http/static/mime_types/text%2Fplain'
    ), 'configure mime_types update'
    assert (
        client.get(url='/dir/file')['headers']['Content-Type'] == 'text/plain'
    ), 'mime_types updated'
    assert (
        'Content-Type' not in client.get(url='/log.log')['headers']
    ), 'mime_types updated 2'

    assert 'success' in client.conf(
        '".log"', 'settings/http/static/mime_types/text%2Fblahblahblah'
    ), 'configure mime_types create'
    assert (
        client.get(url='/log.log')['headers']['Content-Type']
        == 'text/blahblahblah'
    ), 'mime_types create'


def test_static_mime_types_correct():
    assert 'error' in client.conf(
        {"text/x-code": "readme", "text/plain": "readme"},
        'settings/http/static/mime_types',
    ), 'mime_types same extensions'
    assert 'error' in client.conf(
        {"text/x-code": [".h", ".c"], "text/plain": ".c"},
        'settings/http/static/mime_types',
    ), 'mime_types same extensions array'
    assert 'error' in client.conf(
        {
            "text/x-code": [".h", ".c", "readme"],
            "text/plain": "README",
        },
        'settings/http/static/mime_types',
    ), 'mime_types same extensions case insensitive'


@pytest.mark.skip('not yet')
def test_static_mime_types_invalid(temp_dir):
    assert 'error' in client.http(
        b"""PUT /config/settings/http/static/mime_types/%0%00% HTTP/1.1\r
Host: localhost\r
Connection: close\r
Content-Length: 6\r
\r
\"blah\"""",
        raw_resp=True,
        raw=True,
        sock_type='unix',
        addr=f'{temp_dir}/control.unit.sock',
    ), 'mime_types invalid'
