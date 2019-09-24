import os
import socket
import unittest
from unit.applications.proto import TestApplicationProto


class TestStatic(TestApplicationProto):
    prerequisites = {}

    def setUp(self):
        super().setUp()

        os.makedirs(self.testdir + '/assets/dir')
        with open(self.testdir + '/assets/index.html', 'w') as index,  \
             open(self.testdir + '/assets/README',     'w') as readme, \
             open(self.testdir + '/assets/log.log',    'w') as log,    \
             open(self.testdir + '/assets/dir/file',   'w') as file:
            index.write('0123456789')
            readme.write('readme')
            log.write('[debug]')
            file.write('blah')

        self._load_conf(
            {
                "listeners": {"*:7080": {"pass": "routes"}},
                "routes": [{"action": {"share": self.testdir + "/assets"}}],
                "settings": {
                    "http": {
                        "static": {
                            "mime_types": {"text/plain": [".log", "README"]}
                        }
                    }
                },
            }
        )

    def test_static_index(self):
        self.assertEqual(
            self.get(url='/index.html')['body'], '0123456789', 'index'
        )
        self.assertEqual(self.get(url='/')['body'], '0123456789', 'index 2')
        self.assertEqual(
            self.get(url='/dir/')['status'], 404, 'index not found'
        )

        resp = self.get(url='/index.html/')
        self.assertEqual(resp['status'], 404, 'index not found 2 status')
        self.assertEqual(
            resp['headers']['Content-Type'],
            'text/html',
            'index not found 2 Content-Type',
        )

    def test_static_large_file(self):
        file_size = 32 * 1024 * 1024
        with open(self.testdir + '/assets/large', 'wb') as f:
            f.seek(file_size - 1)
            f.write(b'\0')

        self.assertEqual(
            len(
                self.get(url='/large', read_buffer_size=1024 * 1024)['body']
            ),
            file_size,
            'large file',
        )

    def test_static_etag(self):
        etag = self.get(url='/')['headers']['ETag']
        etag_2 = self.get(url='/README')['headers']['ETag']

        self.assertNotEqual(etag, etag_2, 'different ETag')
        self.assertEqual(
            etag, self.get(url='/')['headers']['ETag'], 'same ETag'
        )

        with open(self.testdir + '/assets/index.html', 'w') as f:
            f.write('blah')

        self.assertNotEqual(
            etag, self.get(url='/')['headers']['ETag'], 'new ETag'
        )

    def test_static_redirect(self):
        resp = self.get(url='/dir')
        self.assertEqual(resp['status'], 301, 'redirect status')
        self.assertEqual(
            resp['headers']['Location'], '/dir/', 'redirect Location'
        )
        self.assertNotIn(
            'Content-Type', resp['headers'], 'redirect Content-Type'
        )

    def test_static_space_in_name(self):
        os.rename(
            self.testdir + '/assets/dir/file',
            self.testdir + '/assets/dir/fi le',
        )
        self.waitforfiles(self.testdir + '/assets/dir/fi le')
        self.assertEqual(
            self.get(url='/dir/fi le')['body'], 'blah', 'file name'
        )

        os.rename(self.testdir + '/assets/dir', self.testdir + '/assets/di r')
        self.waitforfiles(self.testdir + '/assets/di r/fi le')
        self.assertEqual(
            self.get(url='/di r/fi le')['body'], 'blah', 'dir name'
        )

        os.rename(
            self.testdir + '/assets/di r', self.testdir + '/assets/ di r '
        )
        self.waitforfiles(self.testdir + '/assets/ di r /fi le')
        self.assertEqual(
            self.get(url='/ di r /fi le')['body'], 'blah', 'dir name enclosing'
        )

        self.assertEqual(
            self.get(url='/%20di%20r%20/fi le')['body'], 'blah', 'dir encoded'
        )
        self.assertEqual(
            self.get(url='/ di r %2Ffi le')['body'], 'blah', 'slash encoded'
        )
        self.assertEqual(
            self.get(url='/ di r /fi%20le')['body'], 'blah', 'file encoded'
        )
        self.assertEqual(
            self.get(url='/%20di%20r%20%2Ffi%20le')['body'], 'blah', 'encoded'
        )
        self.assertEqual(
            self.get(url='/%20%64%69%20%72%20%2F%66%69%20%6C%65')['body'],
            'blah',
            'encoded 2',
        )

        os.rename(
            self.testdir + '/assets/ di r /fi le',
            self.testdir + '/assets/ di r / fi le ',
        )
        self.waitforfiles(self.testdir + '/assets/ di r / fi le ')
        self.assertEqual(
            self.get(url='/%20di%20r%20/%20fi%20le%20')['body'],
            'blah',
            'file name enclosing',
        )

        try:
            print('файл')
            utf8 = True

        except:
            utf8 = False

        if utf8:
            os.rename(
                self.testdir + '/assets/ di r / fi le ',
                self.testdir + '/assets/ di r /фа йл',
            )
            self.waitforfiles(self.testdir + '/assets/ di r /фа йл')
            self.assertEqual(
                self.get(url='/ di r /фа йл')['body'], 'blah', 'file name 2'
            )

            os.rename(
                self.testdir + '/assets/ di r ',
                self.testdir + '/assets/ди ректория',
            )
            self.waitforfiles(self.testdir + '/assets/ди ректория/фа йл')
            self.assertEqual(
                self.get(url='/ди ректория/фа йл')['body'], 'blah', 'dir name 2'
            )

    def test_static_unix_socket(self):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(self.testdir + '/assets/unix_socket')

        self.assertEqual(self.get(url='/unix_socket')['status'], 404, 'socket')

        sock.close()

    def test_static_unix_fifo(self):
        os.mkfifo(self.testdir + '/assets/fifo')

        self.assertEqual(self.get(url='/fifo')['status'], 404, 'fifo')

    def test_static_symlink(self):
        os.symlink(self.testdir + '/assets/dir', self.testdir + '/assets/link')

        self.assertEqual(self.get(url='/dir')['status'], 301, 'dir')
        self.assertEqual(self.get(url='/dir/file')['status'], 200, 'file')
        self.assertEqual(self.get(url='/link')['status'], 301, 'symlink dir')
        self.assertEqual(
            self.get(url='/link/file')['status'], 200, 'symlink file'
        )

    def test_static_head(self):
        resp = self.head(url='/')
        self.assertEqual(resp['status'], 200, 'status')
        self.assertEqual(resp['body'], '', 'empty body')

    def test_static_two_clients(self):
        _, sock = self.get(url='/', start=True, no_recv=True)
        _, sock2 = self.get(url='/', start=True, no_recv=True)

        self.assertEqual(sock.recv(1), b'H', 'client 1')
        self.assertEqual(sock2.recv(1), b'H', 'client 2')
        self.assertEqual(sock.recv(1), b'T', 'client 1 again')
        self.assertEqual(sock2.recv(1), b'T', 'client 2 again')

        sock.close()
        sock2.close()

    def test_static_mime_types(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "text/x-code/x-blah/x-blah": "readme",
                    "text/plain": [".html", ".log", "file"],
                },
                'settings/http/static/mime_types',
            ),
            'configure mime_types',
        )

        self.assertEqual(
            self.get(url='/README')['headers']['Content-Type'],
            'text/x-code/x-blah/x-blah',
            'mime_types string case insensitive',
        )
        self.assertEqual(
            self.get(url='/index.html')['headers']['Content-Type'],
            'text/plain',
            'mime_types html',
        )
        self.assertEqual(
            self.get(url='/')['headers']['Content-Type'],
            'text/plain',
            'mime_types index default',
        )
        self.assertEqual(
            self.get(url='/dir/file')['headers']['Content-Type'],
            'text/plain',
            'mime_types file in dir',
        )

    def test_static_mime_types_partial_match(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "text/x-blah": ["ile", "fil", "f", "e", ".file"],
                },
                'settings/http/static/mime_types',
            ),
            'configure mime_types',
        )
        self.assertNotIn(
            'Content-Type', self.get(url='/dir/file'), 'partial match'
        )

    def test_static_mime_types_reconfigure(self):
        self.assertIn(
            'success',
            self.conf(
                {
                    "text/x-code": "readme",
                    "text/plain": [".html", ".log", "file"],
                },
                'settings/http/static/mime_types',
            ),
            'configure mime_types',
        )

        self.assertEqual(
            self.conf_get('settings/http/static/mime_types'),
            {'text/x-code': 'readme', 'text/plain': ['.html', '.log', 'file']},
            'mime_types get',
        )
        self.assertEqual(
            self.conf_get('settings/http/static/mime_types/text%2Fx-code'),
            'readme',
            'mime_types get string',
        )
        self.assertEqual(
            self.conf_get('settings/http/static/mime_types/text%2Fplain'),
            ['.html', '.log', 'file'],
            'mime_types get array',
        )
        self.assertEqual(
            self.conf_get('settings/http/static/mime_types/text%2Fplain/1'),
            '.log',
            'mime_types get array element',
        )

        self.assertIn(
            'success',
            self.conf_delete('settings/http/static/mime_types/text%2Fplain/2'),
            'mime_types remove array element',
        )
        self.assertNotIn(
            'Content-Type',
            self.get(url='/dir/file')['headers'],
            'mime_types removed',
        )

        self.assertIn(
            'success',
            self.conf_post(
                '"file"', 'settings/http/static/mime_types/text%2Fplain'
            ),
            'mime_types add array element',
        )
        self.assertEqual(
            self.get(url='/dir/file')['headers']['Content-Type'],
            'text/plain',
            'mime_types reverted',
        )

        self.assertIn(
            'success',
            self.conf(
                '"file"', 'settings/http/static/mime_types/text%2Fplain'
            ),
            'configure mime_types update',
        )
        self.assertEqual(
            self.get(url='/dir/file')['headers']['Content-Type'],
            'text/plain',
            'mime_types updated',
        )
        self.assertNotIn(
            'Content-Type',
            self.get(url='/log.log')['headers'],
            'mime_types updated 2',
        )

        self.assertIn(
            'success',
            self.conf(
                '".log"', 'settings/http/static/mime_types/text%2Fblahblahblah'
            ),
            'configure mime_types create',
        )
        self.assertEqual(
            self.get(url='/log.log')['headers']['Content-Type'],
            'text/blahblahblah',
            'mime_types create',
        )

    def test_static_mime_types_correct(self):
        self.assertIn(
            'error',
            self.conf(
                {"text/x-code": "readme", "text/plain": "readme"},
                'settings/http/static/mime_types',
            ),
            'mime_types same extensions',
        )
        self.assertIn(
            'error',
            self.conf(
                {"text/x-code": [".h", ".c"], "text/plain": ".c"},
                'settings/http/static/mime_types',
            ),
            'mime_types same extensions array',
        )
        self.assertIn(
            'error',
            self.conf(
                {
                    "text/x-code": [".h", ".c", "readme"],
                    "text/plain": "README",
                },
                'settings/http/static/mime_types',
            ),
            'mime_types same extensions case insensitive',
        )

    @unittest.skip('not yet')
    def test_static_mime_types_invalid(self):
        self.assertIn(
            'error',
            self.http(
                b"""PUT /config/settings/http/static/mime_types/%0%00% HTTP/1.1\r
Host: localhost\r
Connection: close\r
Content-Length: 6\r
\r
\"blah\"""",
                raw_resp=True,
                raw=True,
                sock_type='unix',
                addr=self.testdir + '/control.unit.sock',
            ),
            'mime_types invalid',
        )

if __name__ == '__main__':
    TestStatic.main()
