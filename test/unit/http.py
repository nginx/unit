import re
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

            if body is not b'':
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

        if TestUnit.detailed:
            print('>>>', req, sep='\n')

        resp = ''

        if 'no_recv' not in kwargs:
            enc = 'utf-8' if 'encoding' not in kwargs else kwargs['encoding']
            read_timeout = (
                5 if 'read_timeout' not in kwargs else kwargs['read_timeout']
            )
            resp = self.recvall(sock, read_timeout=read_timeout).decode(enc)

        if TestUnit.detailed:
            print('<<<', resp.encode('utf-8'), sep='\n')

        if 'raw_resp' not in kwargs:
            resp = self._resp_to_dict(resp)

        if 'start' not in kwargs:
            sock.close()
            return resp

        return (resp, sock)

    def delete(self, **kwargs):
        return self.http('DELETE', **kwargs)

    def get(self, **kwargs):
        return self.http('GET', **kwargs)

    def post(self, **kwargs):
        return self.http('POST', **kwargs)

    def put(self, **kwargs):
        return self.http('PUT', **kwargs)

    def recvall(self, sock, read_timeout=5, buff_size=4096):
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
        m = re.search('(.*?\x0d\x0a?)\x0d\x0a?(.*)', resp, re.M | re.S)

        if not m:
            return {}

        headers_text, body = m.group(1), m.group(2)

        p = re.compile('(.*?)\x0d\x0a?', re.M | re.S)
        headers_lines = p.findall(headers_text)

        status = re.search(
            '^HTTP\/\d\.\d\s(\d+)|$', headers_lines.pop(0)
        ).group(1)

        headers = {}
        for line in headers_lines:
            m = re.search('(.*)\:\s(.*)', line)

            if m.group(1) not in headers:
                headers[m.group(1)] = m.group(2)

            elif isinstance(headers[m.group(1)], list):
                headers[m.group(1)].append(m.group(2))

            else:
                headers[m.group(1)] = [headers[m.group(1)], m.group(2)]

        return {'status': int(status), 'headers': headers, 'body': body}
