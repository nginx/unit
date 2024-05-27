import base64
import hashlib
import itertools
import random
import select
import struct

import pytest

from unit.applications.proto import ApplicationProto

GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class ApplicationWebsocket(ApplicationProto):

    OP_CONT = 0x00
    OP_TEXT = 0x01
    OP_BINARY = 0x02
    OP_CLOSE = 0x08
    OP_PING = 0x09
    OP_PONG = 0x0A
    CLOSE_CODES = [1000, 1001, 1002, 1003, 1007, 1008, 1009, 1010, 1011]

    def key(self):
        raw_key = bytes(random.getrandbits(8) for _ in range(16))
        return base64.b64encode(raw_key).decode()

    def accept(self, key):
        sha1 = hashlib.sha1((key + GUID).encode()).digest()
        return base64.b64encode(sha1).decode()

    def upgrade(self, headers=None):
        key = None

        if headers is None:
            key = self.key()
            headers = {
                'Host': 'localhost',
                'Upgrade': 'websocket',
                'Connection': 'Upgrade',
                'Sec-WebSocket-Key': key,
                'Sec-WebSocket-Protocol': 'chat, phone, video',
                'Sec-WebSocket-Version': 13,
            }

        sock = self.get(
            headers=headers,
            no_recv=True,
        )

        resp = ''
        while True:
            rlist = select.select([sock], [], [], 60)[0]
            if not rlist:
                pytest.fail("Can't read response from server.")

            resp += sock.recv(4096).decode()

            if resp.startswith('HTTP/') and '\r\n\r\n' in resp:
                resp = self._resp_to_dict(resp)
                break

        return (resp, sock, key)

    def apply_mask(self, data, mask):
        return bytes(b ^ m for b, m in zip(data, itertools.cycle(mask)))

    def serialize_close(self, code=1000, reason=''):
        return struct.pack('!H', code) + reason.encode('utf-8')

    def frame_read(self, sock, read_timeout=60):
        def recv_bytes(sock, bytes_len):
            data = b''
            while True:
                rlist = select.select([sock], [], [], read_timeout)[0]
                if not rlist:
                    # For all current cases if the "read_timeout" was changed
                    # than test do not expect to get a response from server.
                    if read_timeout == 60:
                        pytest.fail("Can't read response from server.")
                    break

                data += sock.recv(bytes_len - len(data))

                if len(data) == bytes_len:
                    break

            return data

        frame = {}

        (head1,) = struct.unpack('!B', recv_bytes(sock, 1))
        (head2,) = struct.unpack('!B', recv_bytes(sock, 1))

        frame['fin'] = bool(head1 & 0b10000000)
        frame['rsv1'] = bool(head1 & 0b01000000)
        frame['rsv2'] = bool(head1 & 0b00100000)
        frame['rsv3'] = bool(head1 & 0b00010000)
        frame['opcode'] = head1 & 0b00001111
        frame['mask'] = head2 & 0b10000000

        length = head2 & 0b01111111
        if length == 126:
            data = recv_bytes(sock, 2)
            (length,) = struct.unpack('!H', data)
        elif length == 127:
            data = recv_bytes(sock, 8)
            (length,) = struct.unpack('!Q', data)

        if frame['mask']:
            mask_bits = recv_bytes(sock, 4)

        data = b''

        if length != 0:
            data = recv_bytes(sock, length)

        if frame['mask']:
            data = self.apply_mask(data, mask_bits)

        if frame['opcode'] == self.OP_CLOSE:
            if length >= 2:
                (code,) = struct.unpack('!H', data[:2])
                reason = data[2:].decode('utf-8')
                if not (code in self.CLOSE_CODES or 3000 <= code < 5000):
                    pytest.fail('Invalid status code')
                frame['code'] = code
                frame['reason'] = reason
            elif length == 0:
                frame['code'] = 1005
                frame['reason'] = ''
            else:
                pytest.fail('Close frame too short')

        frame['data'] = data

        if frame['mask']:
            pytest.fail('Received frame with mask')

        return frame

    def frame_to_send(
        self,
        opcode,
        data,
        fin=True,
        length=None,
        rsv1=False,
        rsv2=False,
        rsv3=False,
        mask=True,
    ):
        frame = b''

        if isinstance(data, str):
            data = data.encode('utf-8')

        head1 = (
            (0b10000000 if fin else 0)
            | (0b01000000 if rsv1 else 0)
            | (0b00100000 if rsv2 else 0)
            | (0b00010000 if rsv3 else 0)
            | opcode
        )

        head2 = 0b10000000 if mask else 0

        data_length = len(data) if length is None else length
        if data_length < 126:
            frame += struct.pack('!BB', head1, head2 | data_length)
        elif data_length < 65536:
            frame += struct.pack('!BBH', head1, head2 | 126, data_length)
        else:
            frame += struct.pack('!BBQ', head1, head2 | 127, data_length)

        if mask:
            mask_bits = struct.pack('!I', random.getrandbits(32))
            frame += mask_bits

        if mask:
            frame += self.apply_mask(data, mask_bits)
        else:
            frame += data

        return frame

    def frame_write(self, sock, *args, **kwargs):
        chopsize = kwargs.pop('chopsize') if 'chopsize' in kwargs else None

        frame = self.frame_to_send(*args, **kwargs)

        if chopsize is None:
            try:
                sock.sendall(frame)
            except BrokenPipeError:
                pass

        else:
            pos = 0
            frame_len = len(frame)
            while pos < frame_len:
                end = min(pos + chopsize, frame_len)
                try:
                    sock.sendall(frame[pos:end])
                except BrokenPipeError:
                    end = frame_len
                pos = end

    def message(self, sock, mes_type, message, fragmention_size=None, **kwargs):
        message_len = len(message)

        if fragmention_size is None:
            fragmention_size = message_len

        if message_len <= fragmention_size:
            self.frame_write(sock, mes_type, message, **kwargs)
            return

        pos = 0
        op_code = mes_type
        while pos < message_len:
            end = min(pos + fragmention_size, message_len)
            fin = end == message_len
            self.frame_write(sock, op_code, message[pos:end], fin=fin, **kwargs)
            op_code = self.OP_CONT
            pos = end

    def message_read(self, sock, read_timeout=60):
        frame = self.frame_read(sock, read_timeout=read_timeout)

        while not frame['fin']:
            temp = self.frame_read(sock, read_timeout=read_timeout)
            frame['data'] += temp['data']
            frame['fin'] = temp['fin']

        return frame
