import binascii
import io
import json
import os
import re
import select
import socket

import pytest

from unit.option import option


class HTTP1:
    def http(self, start_str, **kwargs):
        sock_type = kwargs.get('sock_type', 'ipv4')
        port = kwargs.get('port', 8080)
        url = kwargs.get('url', '/')
        http = 'HTTP/1.0' if 'http_10' in kwargs else 'HTTP/1.1'

        headers = kwargs.get(
            'headers', {'Host': 'localhost', 'Connection': 'close'}
        )

        body = kwargs.get('body', b'')
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

            if sock_type in (sock_types['ipv4'], sock_types['ipv6']):
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            if 'wrapper' in kwargs:
                server_hostname = headers.get('Host', None)
                sock = kwargs['wrapper'](sock, server_hostname=server_hostname)

            connect_args = addr if sock_type == 'unix' else (addr, port)
            try:
                sock.connect(connect_args)
            except (ConnectionRefusedError, FileNotFoundError):
                sock.close()
                pytest.fail("Client can't connect to the server.")

        else:
            sock = kwargs['sock']

        if 'raw' not in kwargs:
            req = f'{start_str} {url} {http}{crlf}'

            if body != b'':
                if isinstance(body, str):
                    body = body.encode()
                elif isinstance(body, dict):
                    body, content_type = self.form_encode(body)

                    headers['Content-Type'] = content_type

                if 'Content-Length' not in headers and 'Transfer-Encoding' not in headers:
                    headers['Content-Length'] = len(body)

            for header, value in headers.items():
                if isinstance(value, list):
                    for v in value:
                        req += f'{header}: {v}{crlf}'

                else:
                    req += f'{header}: {value}{crlf}'

            req = (req + crlf).encode() + body

        else:
            req = start_str

        sock.sendall(req)

        encoding = kwargs.get('encoding', 'utf-8')

        self.log_out(req, encoding)

        resp = ''

        if 'no_recv' not in kwargs:
            recvall_kwargs = {}

            if 'read_timeout' in kwargs:
                recvall_kwargs['read_timeout'] = kwargs['read_timeout']

            if 'read_buffer_size' in kwargs:
                recvall_kwargs['buff_size'] = kwargs['read_buffer_size']

            resp = self.recvall(sock, **recvall_kwargs).decode(
                encoding, errors='ignore'
            )

        else:
            return sock

        self.log_in(resp)

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

    def log_out(self, log, encoding):
        if option.detailed:
            print('>>>')
            log = self.log_truncate(log)
            try:
                print(log.decode(encoding, 'ignore'))
            except UnicodeEncodeError:
                print(log)

    def log_in(self, log):
        if option.detailed:
            print('<<<')
            log = self.log_truncate(log)
            try:
                print(log)
            except UnicodeEncodeError:
                print(log.encode())

    def log_truncate(self, log, limit=1024):
        len_log = len(log)
        if len_log > limit:
            log = log[:limit]
            appendix = f'(...logged {limit} of {len_log} bytes)'

            if isinstance(log, bytes):
                appendix = appendix.encode()

            log = f'{log}{appendix}'

        return log

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

    def recvall(self, sock, **kwargs):
        timeout_default = 60

        timeout = kwargs.get('read_timeout', timeout_default)
        buff_size = kwargs.get('buff_size', 4096)

        data = b''
        while True:
            rlist = select.select([sock], [], [], timeout)[0]
            if not rlist:
                # For all current cases if the "read_timeout" was changed
                # than test do not expect to get a response from server.
                if timeout == timeout_default:
                    pytest.fail("Can't read response from server.")
                break

            try:
                part = sock.recv(buff_size)

            except KeyboardInterrupt:
                raise

            except:
                break

            data += part

            if not part:
                break

        return data

    def _resp_to_dict(self, resp):
        m = re.search(r'(.*?\x0d\x0a?)\x0d\x0a?(.*)', resp, re.M | re.S)

        if not m:
            return {}

        headers_text, body = m.group(1), m.group(2)
        headers_lines = re.findall('(.*?)\x0d\x0a?', headers_text, re.M | re.S)

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
            pytest.fail('Invalid chunked body')

        if chunks.pop() != b'':
            pytest.fail('No CRLF at the end of the body')

        try:
            last_size = int(chunks[-2], 16)

        except ValueError:
            pytest.fail('Invalid zero size chunk')

        if last_size != 0 or chunks[-1] != b'':
            pytest.fail('Incomplete body')

        body = b''
        while len(chunks) >= 2:
            try:
                size = int(chunks.pop(0), 16)

            except ValueError:
                pytest.fail('Invalid chunk size')

            if size == 0:
                assert len(chunks) == 1, 'last zero size'
                break

            temp_body = crlf.join(chunks)

            body += temp_body[:size]

            temp_body = temp_body[size + len(crlf) :]

            chunks = temp_body.split(crlf)

        return body

    def _parse_json(self, resp):
        headers = resp['headers']

        assert 'Content-Type' in headers
        assert headers['Content-Type'] == 'application/json'

        resp['body'] = json.loads(resp['body'])

        return resp

    def getjson(self, **kwargs):
        return self.get(json=True, **kwargs)

    def form_encode(self, fields):
        is_multipart = False

        for _, value in fields.items():
            if isinstance(value, dict):
                is_multipart = True
                break

        if is_multipart:
            body, content_type = self.multipart_encode(fields)

        else:
            body, content_type = self.form_url_encode(fields)

        return body, content_type

    def form_url_encode(self, fields):
        data = "&".join(
            f'{name}={value}' for name, value in fields.items()
        ).encode()
        return data, 'application/x-www-form-urlencoded'

    def multipart_encode(self, fields):
        boundary = binascii.hexlify(os.urandom(16)).decode('ascii')

        body = ''

        for field, value in fields.items():
            filename = ''
            datatype = ''

            if isinstance(value, dict):
                datatype = 'text/plain'
                filename = value['filename']

                if value.get('type'):
                    datatype = value['type']

                if not isinstance(value['data'], io.IOBase):
                    pytest.fail('multipart encoding of file requires a stream.')

                data = value['data'].read()

            elif isinstance(value, str):
                data = value

            else:
                pytest.fail('multipart requires a string or stream data')

            body += (
                f'--{boundary}\r\nContent-Disposition: form-data;'
                f'name="{field}"'
            )

            if filename != '':
                body += f'; filename="{filename}"'

            body += '\r\n'

            if datatype != '':
                body += f'Content-Type: {datatype}\r\n'

            body += f'\r\n{data}\r\n'

        body += f'--{boundary}--\r\n'

        return body.encode(), f'multipart/form-data; boundary={boundary}'
