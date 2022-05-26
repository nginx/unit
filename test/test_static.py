import os
import shutil
import socket

import pytest
from conftest import unit_run
from conftest import unit_stop
from unit.applications.proto import TestApplicationProto
from unit.option import option
from unit.utils import waitforfiles


class TestStatic(TestApplicationProto):
    prerequisites = {}

    def setup_method(self):
        os.makedirs(option.temp_dir + '/assets/dir')
        with open(option.temp_dir + '/assets/index.html', 'w') as index, open(
            option.temp_dir + '/assets/README', 'w'
        ) as readme, open(
            option.temp_dir + '/assets/log.log', 'w'
        ) as log, open(
            option.temp_dir + '/assets/dir/file', 'w'
        ) as file:
            index.write('0123456789')
            readme.write('readme')
            log.write('[debug]')
            file.write('blah')

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [
                    {"action": {"share": option.temp_dir + "/assets$uri"}}
                ],
                "settings": {
                    "http": {
                        "static": {
                            "mime_types": {"text/plain": [".log", "README"]}
                        }
                    }
                },
            }
        )

    def test_static_migration(self, skip_fds_check, temp_dir):
        skip_fds_check(True, True, True)

        def set_conf_version(path, version):
            with open(path, 'w+') as f:
                f.write(str(version))

        with open(temp_dir + '/state/version', 'r') as f:
            assert int(f.read().rstrip()) > 12500, 'current version'

        assert 'success' in self.conf(
            {"share": temp_dir + "/assets"}, 'routes/0/action'
        ), 'configure migration 12500'

        shutil.copytree(temp_dir + '/state', temp_dir + '/state_copy_12500')
        set_conf_version(temp_dir + '/state_copy_12500/version', 12500)

        assert 'success' in self.conf(
            {"share": temp_dir + "/assets$uri"}, 'routes/0/action'
        ), 'configure migration 12600'
        shutil.copytree(temp_dir + '/state', temp_dir + '/state_copy_12600')
        set_conf_version(temp_dir + '/state_copy_12600/version', 12600)

        assert 'success' in self.conf(
            {"share": temp_dir + "/assets"}, 'routes/0/action'
        ), 'configure migration no version'
        shutil.copytree(
            temp_dir + '/state', temp_dir + '/state_copy_no_version'
        )
        os.remove(temp_dir + '/state_copy_no_version/version')

        unit_stop()
        unit_run(temp_dir + '/state_copy_12500')
        assert self.get(url='/')['body'] == '0123456789', 'before 1.26.0'

        unit_stop()
        unit_run(temp_dir + '/state_copy_12600')
        assert self.get(url='/')['body'] == '0123456789', 'after 1.26.0'

        unit_stop()
        unit_run(temp_dir + '/state_copy_no_version')
        assert self.get(url='/')['body'] == '0123456789', 'before 1.26.0 2'

    def test_static_index(self):
        def set_index(index):
            assert 'success' in self.conf(
                {"share": option.temp_dir + "/assets$uri", "index": index},
                'routes/0/action',
            ), 'configure index'

        set_index('README')
        assert self.get()['body'] == 'readme', 'index'

        self.conf_delete('routes/0/action/index')
        assert self.get()['body'] == '0123456789', 'delete index'

        set_index('')
        assert self.get()['status'] == 404, 'index empty'

    def test_static_index_default(self):
        assert self.get(url='/index.html')['body'] == '0123456789', 'index'
        assert self.get(url='/')['body'] == '0123456789', 'index 2'
        assert self.get(url='//')['body'] == '0123456789', 'index 3'
        assert self.get(url='/.')['body'] == '0123456789', 'index 4'
        assert self.get(url='/./')['body'] == '0123456789', 'index 5'
        assert self.get(url='/?blah')['body'] == '0123456789', 'index vars'
        assert self.get(url='/#blah')['body'] == '0123456789', 'index anchor'
        assert self.get(url='/dir/')['status'] == 404, 'index not found'

        resp = self.get(url='/index.html/')
        assert resp['status'] == 404, 'index not found 2 status'
        assert (
            resp['headers']['Content-Type'] == 'text/html'
        ), 'index not found 2 Content-Type'

    def test_static_index_invalid(self, skip_alert):
        skip_alert(r'failed to apply new conf')

        def check_index(index):
            assert 'error' in self.conf(
                {"share": option.temp_dir + "/assets$uri", "index": index},
                'routes/0/action',
            )

        check_index({})
        check_index(['index.html', '$blah'])

    def test_static_large_file(self, temp_dir):
        file_size = 32 * 1024 * 1024
        with open(temp_dir + '/assets/large', 'wb') as f:
            f.seek(file_size - 1)
            f.write(b'\0')

        assert (
            len(self.get(url='/large', read_buffer_size=1024 * 1024)['body'])
            == file_size
        ), 'large file'

    def test_static_etag(self, temp_dir):
        etag = self.get(url='/')['headers']['ETag']
        etag_2 = self.get(url='/README')['headers']['ETag']

        assert etag != etag_2, 'different ETag'
        assert etag == self.get(url='/')['headers']['ETag'], 'same ETag'

        with open(temp_dir + '/assets/index.html', 'w') as f:
            f.write('blah')

        assert etag != self.get(url='/')['headers']['ETag'], 'new ETag'

    def test_static_redirect(self):
        resp = self.get(url='/dir')
        assert resp['status'] == 301, 'redirect status'
        assert resp['headers']['Location'] == '/dir/', 'redirect Location'
        assert 'Content-Type' not in resp['headers'], 'redirect Content-Type'

    def test_static_space_in_name(self, temp_dir):
        os.rename(
            temp_dir + '/assets/dir/file',
            temp_dir + '/assets/dir/fi le',
        )
        assert waitforfiles(temp_dir + '/assets/dir/fi le')
        assert self.get(url='/dir/fi le')['body'] == 'blah', 'file name'

        os.rename(temp_dir + '/assets/dir', temp_dir + '/assets/di r')
        assert waitforfiles(temp_dir + '/assets/di r/fi le')
        assert self.get(url='/di r/fi le')['body'] == 'blah', 'dir name'

        os.rename(temp_dir + '/assets/di r', temp_dir + '/assets/ di r ')
        assert waitforfiles(temp_dir + '/assets/ di r /fi le')
        assert (
            self.get(url='/ di r /fi le')['body'] == 'blah'
        ), 'dir name enclosing'

        assert (
            self.get(url='/%20di%20r%20/fi le')['body'] == 'blah'
        ), 'dir encoded'
        assert (
            self.get(url='/ di r %2Ffi le')['body'] == 'blah'
        ), 'slash encoded'
        assert self.get(url='/ di r /fi%20le')['body'] == 'blah', 'file encoded'
        assert (
            self.get(url='/%20di%20r%20%2Ffi%20le')['body'] == 'blah'
        ), 'encoded'
        assert (
            self.get(url='/%20%64%69%20%72%20%2F%66%69%20%6C%65')['body']
            == 'blah'
        ), 'encoded 2'

        os.rename(
            temp_dir + '/assets/ di r /fi le',
            temp_dir + '/assets/ di r / fi le ',
        )
        assert waitforfiles(temp_dir + '/assets/ di r / fi le ')
        assert (
            self.get(url='/%20di%20r%20/%20fi%20le%20')['body'] == 'blah'
        ), 'file name enclosing'

        try:
            open(temp_dir + '/ф а', 'a').close()
            utf8 = True

        except KeyboardInterrupt:
            raise

        except:
            utf8 = False

        if utf8:
            os.rename(
                temp_dir + '/assets/ di r / fi le ',
                temp_dir + '/assets/ di r /фа йл',
            )
            assert waitforfiles(temp_dir + '/assets/ di r /фа йл')
            assert (
                self.get(url='/ di r /фа йл')['body'] == 'blah'
            ), 'file name 2'

            os.rename(
                temp_dir + '/assets/ di r ',
                temp_dir + '/assets/ди ректория',
            )
            assert waitforfiles(temp_dir + '/assets/ди ректория/фа йл')
            assert (
                self.get(url='/ди ректория/фа йл')['body'] == 'blah'
            ), 'dir name 2'

    def test_static_unix_socket(self, temp_dir):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(temp_dir + '/assets/unix_socket')

        assert self.get(url='/unix_socket')['status'] == 404, 'socket'

        sock.close()

    def test_static_unix_fifo(self, temp_dir):
        os.mkfifo(temp_dir + '/assets/fifo')

        assert self.get(url='/fifo')['status'] == 404, 'fifo'

    def test_static_method(self):
        resp = self.head()
        assert resp['status'] == 200, 'HEAD status'
        assert resp['body'] == '', 'HEAD empty body'

        assert self.delete()['status'] == 405, 'DELETE'
        assert self.post()['status'] == 405, 'POST'
        assert self.put()['status'] == 405, 'PUT'

    def test_static_path(self):
        assert self.get(url='/dir/../dir/file')['status'] == 200, 'relative'

        assert self.get(url='./')['status'] == 400, 'path invalid'
        assert self.get(url='../')['status'] == 400, 'path invalid 2'
        assert self.get(url='/..')['status'] == 400, 'path invalid 3'
        assert self.get(url='../assets/')['status'] == 400, 'path invalid 4'
        assert self.get(url='/../assets/')['status'] == 400, 'path invalid 5'

    def test_static_two_clients(self):
        _, sock = self.get(url='/', start=True, no_recv=True)
        _, sock2 = self.get(url='/', start=True, no_recv=True)

        assert sock.recv(1) == b'H', 'client 1'
        assert sock2.recv(1) == b'H', 'client 2'
        assert sock.recv(1) == b'T', 'client 1 again'
        assert sock2.recv(1) == b'T', 'client 2 again'

        sock.close()
        sock2.close()

    def test_static_mime_types(self):
        assert 'success' in self.conf(
            {
                "text/x-code/x-blah/x-blah": "readme",
                "text/plain": [".html", ".log", "file"],
            },
            'settings/http/static/mime_types',
        ), 'configure mime_types'

        assert (
            self.get(url='/README')['headers']['Content-Type']
            == 'text/x-code/x-blah/x-blah'
        ), 'mime_types string case insensitive'
        assert (
            self.get(url='/index.html')['headers']['Content-Type']
            == 'text/plain'
        ), 'mime_types html'
        assert (
            self.get(url='/')['headers']['Content-Type'] == 'text/plain'
        ), 'mime_types index default'
        assert (
            self.get(url='/dir/file')['headers']['Content-Type'] == 'text/plain'
        ), 'mime_types file in dir'

    def test_static_mime_types_partial_match(self):
        assert 'success' in self.conf(
            {
                "text/x-blah": ["ile", "fil", "f", "e", ".file"],
            },
            'settings/http/static/mime_types',
        ), 'configure mime_types'
        assert 'Content-Type' not in self.get(url='/dir/file'), 'partial match'

    def test_static_mime_types_reconfigure(self):
        assert 'success' in self.conf(
            {
                "text/x-code": "readme",
                "text/plain": [".html", ".log", "file"],
            },
            'settings/http/static/mime_types',
        ), 'configure mime_types'

        assert self.conf_get('settings/http/static/mime_types') == {
            'text/x-code': 'readme',
            'text/plain': ['.html', '.log', 'file'],
        }, 'mime_types get'
        assert (
            self.conf_get('settings/http/static/mime_types/text%2Fx-code')
            == 'readme'
        ), 'mime_types get string'
        assert self.conf_get(
            'settings/http/static/mime_types/text%2Fplain'
        ) == ['.html', '.log', 'file'], 'mime_types get array'
        assert (
            self.conf_get('settings/http/static/mime_types/text%2Fplain/1')
            == '.log'
        ), 'mime_types get array element'

        assert 'success' in self.conf_delete(
            'settings/http/static/mime_types/text%2Fplain/2'
        ), 'mime_types remove array element'
        assert (
            'Content-Type' not in self.get(url='/dir/file')['headers']
        ), 'mime_types removed'

        assert 'success' in self.conf_post(
            '"file"', 'settings/http/static/mime_types/text%2Fplain'
        ), 'mime_types add array element'
        assert (
            self.get(url='/dir/file')['headers']['Content-Type'] == 'text/plain'
        ), 'mime_types reverted'

        assert 'success' in self.conf(
            '"file"', 'settings/http/static/mime_types/text%2Fplain'
        ), 'configure mime_types update'
        assert (
            self.get(url='/dir/file')['headers']['Content-Type'] == 'text/plain'
        ), 'mime_types updated'
        assert (
            'Content-Type' not in self.get(url='/log.log')['headers']
        ), 'mime_types updated 2'

        assert 'success' in self.conf(
            '".log"', 'settings/http/static/mime_types/text%2Fblahblahblah'
        ), 'configure mime_types create'
        assert (
            self.get(url='/log.log')['headers']['Content-Type']
            == 'text/blahblahblah'
        ), 'mime_types create'

    def test_static_mime_types_correct(self):
        assert 'error' in self.conf(
            {"text/x-code": "readme", "text/plain": "readme"},
            'settings/http/static/mime_types',
        ), 'mime_types same extensions'
        assert 'error' in self.conf(
            {"text/x-code": [".h", ".c"], "text/plain": ".c"},
            'settings/http/static/mime_types',
        ), 'mime_types same extensions array'
        assert 'error' in self.conf(
            {
                "text/x-code": [".h", ".c", "readme"],
                "text/plain": "README",
            },
            'settings/http/static/mime_types',
        ), 'mime_types same extensions case insensitive'

    @pytest.mark.skip('not yet')
    def test_static_mime_types_invalid(self, temp_dir):
        assert 'error' in self.http(
            b"""PUT /config/settings/http/static/mime_types/%0%00% HTTP/1.1\r
Host: localhost\r
Connection: close\r
Content-Length: 6\r
\r
\"blah\"""",
            raw_resp=True,
            raw=True,
            sock_type='unix',
            addr=temp_dir + '/control.unit.sock',
        ), 'mime_types invalid'
