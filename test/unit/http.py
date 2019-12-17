import re
import time
import json
import socket
import select
from unit.main import TestUnit


class TestHTTP(TestUnit):
    def http(self, start_str, **kwargs):
        sock_type = (
            'ipv4' if 'sock_type' not in kwargs else kwargs['sock_type']
        )
        port = 7080 if 'port' not in kwargs else kwargs['port']
        url = '/' if 'url' not in kwargs else kwargs['url']
        http = 'HTTP/1.0' if 'http_10' in kwargs else 'HTTP/1.1'
        read_buffer_size = (
            4096
            if 'read_buffer_size' not in kwargs
            else kwargs['read_buffer_size']
        )

        headers = (
            {'Host': 'localhost', 'Connection': 'close'}
            if 'headers' not in kwargs
            else kwargs['headers']
        )

        body = b'' if 'body' not in kwargs else kwargs['body']
        crlf = '\r\n'

        if 'addr' not in kwargs:
            addr = '::1' if sock_type == 'ipv6' else '127.0.0.1'
        else:
            addr = kwargs['addr']

        sock_types = {
            'ipv4': socket.AF_INET,
            'ipv6': socket.AF_INET6,
            'unix': socket.AF_UNIX,
        }

        if 'sock' not in kwargs:
            sock = socket.socket(sock_types[sock_type], socket.SOCK_STREAM)

            if (
                sock_type == sock_types['ipv4']
                or sock_type == sock_types['ipv6']
            ):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            if 'wrapper' in kwargs:
                sock = kwargs['wrapper'](sock)

            connect_args = addr if sock_type == 'unix' else (addr, port)
            try:
                sock.connect(connect_args)
            except ConnectionRefusedError:
                sock.close()
                return None

        else:
            sock = kwargs['sock']

        if 'raw' not in kwargs:
            req = ' '.join([start_str, url, http]) + crlf

            if body != b'':
                if isinstance(body, str):
                    body = body.encode()

                if 'Content-Length' not in headers:
                    headers['Content-Length'] = len(body)

            for header, value in headers.items():
                if isinstance(value, list):
                    for v in value:
                        req += header + ': ' + str(v) + crlf

                else:
                    req += header + ': ' + str(value) + crlf

            req = (req + crlf).encode() + body

        else:
            req = start_str

        sock.sendall(req)

        encoding = 'utf-8' if 'encoding' not in kwargs else kwargs['encoding']

        if TestUnit.detailed:
            print('>>>')
            try:
                print(req.decode(encoding, 'ignore'))
            except UnicodeEncodeError:
                print(req)

        resp = ''

        if 'no_recv' not in kwargs:
            read_timeout = (
                30 if 'read_timeout' not in kwargs else kwargs['read_timeout']
            )
            resp = self.recvall(
                sock, read_timeout=read_timeout, buff_size=read_buffer_size
            ).decode(encoding)

        if TestUnit.detailed:
            print('<<<')
            try:
                print(resp)
            except UnicodeEncodeError:
                print(resp.encode())

        if 'raw_resp' not in kwargs:
            resp = self._resp_to_dict(resp)

            headers = resp.get('headers')
            if headers and headers.get('Transfer-Encoding') == 'chunked':
                resp['body'] = self._parse_chunked_body(resp['body']).decode(
                    encoding
                )

            if 'json' in kwargs:
                resp = self._parse_json(resp)

        if 'start' not in kwargs:
            sock.close()
            return resp

        return (resp, sock)

    def delete(self, **kwargs):
        return self.http('DELETE', **kwargs)

    def get(self, **kwargs):
        return self.http('GET', **kwargs)

    def head(self, **kwargs):
        return self.http('HEAD', **kwargs)

    def post(self, **kwargs):
        return self.http('POST', **kwargs)

    def put(self, **kwargs):
        return self.http('PUT', **kwargs)

    def recvall(self, sock, read_timeout=30, buff_size=4096):
        data = b''
        while select.select([sock], [], [], read_timeout)[0]:
            try:
                part = sock.recv(buff_size)
            except:
                break

            data += part

            if not len(part):
                break

        return data

    def _resp_to_dict(self, resp):
        m = re.search(r'(.*?\x0d\x0a?)\x0d\x0a?(.*)', resp, re.M | re.S)

        if not m:
            return {}

        headers_text, body = m.group(1), m.group(2)

        p = re.compile('(.*?)\x0d\x0a?', re.M | re.S)
        headers_lines = p.findall(headers_text)

        status = re.search(
            r'^HTTP\/\d\.\d\s(\d+)|$', headers_lines.pop(0)
        ).group(1)

        headers = {}
        for line in headers_lines:
            m = re.search(r'(.*)\:\s(.*)', line)

            if m.group(1) not in headers:
                headers[m.group(1)] = m.group(2)

            elif isinstance(headers[m.group(1)], list):
                headers[m.group(1)].append(m.group(2))

            else:
                headers[m.group(1)] = [headers[m.group(1)], m.group(2)]

        return {'status': int(status), 'headers': headers, 'body': body}

    def _parse_chunked_body(self, raw_body):
        if isinstance(raw_body, str):
            raw_body = bytes(raw_body.encode())

        crlf = b'\r\n'
        chunks = raw_body.split(crlf)

        if len(chunks) < 3:
            self.fail('Invalid chunked body')

        if chunks.pop() != b'':
            self.fail('No CRLF at the end of the body')

        try:
            last_size = int(chunks[-2], 16)
        except:
            self.fail('Invalid zero size chunk')

        if last_size != 0 or chunks[-1] != b'':
            self.fail('Incomplete body')

        body = b''
        while len(chunks) >= 2:
            try:
                size = int(chunks.pop(0), 16)
            except:
                self.fail('Invalid chunk size %s' % str(size))

            if size == 0:
                self.assertEqual(len(chunks), 1, 'last zero size')
                break

            temp_body = crlf.join(chunks)

            body += temp_body[:size]

            temp_body = temp_body[size + len(crlf) :]

            chunks = temp_body.split(crlf)

        return body

    def _parse_json(self, resp):
        headers = resp['headers']

        self.assertIn('Content-Type', headers, 'Content-Type header set')
        self.assertEqual(
            headers['Content-Type'],
            'application/json',
            'Content-Type header is application/json',
        )

        resp['body'] = json.loads(resp['body'])

        return resp

    def getjson(self, **kwargs):
        return self.get(json=True, **kwargs)

    def waitforsocket(self, port):
        ret = False

        for i in range(50):
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.connect(('127.0.0.1', port))
                ret = True
                break
            except:
                sock.close()
                time.sleep(0.1)

        sock.close()

        self.assertTrue(ret, 'socket connected')
