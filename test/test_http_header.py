import unittest
import unit

class TestUnitHTTPHeader(unit.TestUnitApplicationPython):

    def setUpClass():
        unit.TestUnit().check_modules('python')

    def test_http_header_value_leading_sp(self):
        self.load('custom_header')

        resp = self.get(headers={
            'Custom-Header': ' ,'
        })

        self.assertEqual(resp['status'], 200, 'value leading sp status')
        self.assertEqual(resp['headers']['Custom-Header'], ',',
            'value leading sp custom header')

    def test_http_header_value_leading_htab(self):
        self.load('custom_header')

        resp = self.get(headers={
            'Custom-Header': '\t,'
        })

        self.assertEqual(resp['status'], 200, 'value leading htab status')
        self.assertEqual(resp['headers']['Custom-Header'], ',',
            'value leading htab custom header')

    def test_http_header_value_trailing_sp(self):
        self.load('custom_header')

        resp = self.get(headers={
            'Custom-Header': ', '
        })

        self.assertEqual(resp['status'], 200, 'value trailing sp status')
        self.assertEqual(resp['headers']['Custom-Header'], ',',
            'value trailing sp custom header')

    def test_http_header_value_trailing_htab(self):
        self.load('custom_header')

        resp = self.get(headers={
            'Custom-Header': ',\t'
        })

        self.assertEqual(resp['status'], 200, 'value trailing htab status')
        self.assertEqual(resp['headers']['Custom-Header'], ',',
            'value trailing htab custom header')

    def test_http_header_value_both_sp(self):
        self.load('custom_header')

        resp = self.get(headers={
            'Custom-Header': ' , '
        })

        self.assertEqual(resp['status'], 200, 'value both sp status')
        self.assertEqual(resp['headers']['Custom-Header'], ',',
            'value both sp custom header')

    def test_http_header_value_both_htab(self):
        self.load('custom_header')

        resp = self.get(headers={
            'Custom-Header': '\t,\t'
        })

        self.assertEqual(resp['status'], 200, 'value both htab status')
        self.assertEqual(resp['headers']['Custom-Header'], ',',
            'value both htab custom header')

    def test_http_header_value_chars(self):
        self.load('custom_header')

        resp = self.get(headers={
            'Custom-Header': '(),/:;<=>?@[\]{}\t !#$%&\'*+-.^_`|~'
        })

        self.assertEqual(resp['status'], 200, 'value chars status')
        self.assertEqual(resp['headers']['Custom-Header'],
            '(),/:;<=>?@[\]{}\t !#$%&\'*+-.^_`|~', 'value chars custom header')

    def test_http_header_value_chars_edge(self):
        self.load('custom_header')

        resp = self.http(b"""GET / HTTP/1.1
Host: localhost
Custom-Header: \x20\xFF
Connection: close

""", raw=True, encoding='latin1')

        self.assertEqual(resp['status'], 200, 'value chars edge status')
        self.assertEqual(resp['headers']['Custom-Header'], '\xFF',
            'value chars edge')

    def test_http_header_value_chars_below(self):
        self.load('custom_header')

        resp = self.http(b"""GET / HTTP/1.1
Host: localhost
Custom-Header: \x1F
Connection: close

""", raw=True)

        self.assertEqual(resp['status'], 400, 'value chars below')

    def test_http_header_field_leading_sp(self):
        self.load('empty')

        resp = self.get(headers={
            ' Custom-Header': 'blah'
        })

        self.assertEqual(resp['status'], 400, 'field leading sp')

    def test_http_header_field_leading_htab(self):
        self.load('empty')

        resp = self.get(headers={
            '\tCustom-Header': 'blah'
        })

        self.assertEqual(resp['status'], 400, 'field leading htab')

    def test_http_header_field_trailing_sp(self):
        self.load('empty')

        resp = self.get(headers={
            'Custom-Header ': 'blah'
        })

        self.assertEqual(resp['status'], 400, 'field trailing sp')

    def test_http_header_field_trailing_htab(self):
        self.load('empty')

        resp = self.get(headers={
            'Custom-Header\t': 'blah'
        })

        self.assertEqual(resp['status'], 400, 'field trailing htab')

    def test_http_header_content_length_big(self):
        self.load('empty')

        self.assertEqual(self.post(headers={
            'Content-Length': str(2 ** 64),
            'Connection': 'close',
            'Host': 'localhost'
        }, body='X' * 1000)['status'], 400, 'Content-Length big')

    def test_http_header_content_length_negative(self):
        self.load('empty')

        self.assertEqual(self.post(headers={
            'Content-Length': '-100',
            'Connection': 'close',
            'Host': 'localhost'
        }, body='X' * 1000)['status'], 400, 'Content-Length negative')

    def test_http_header_content_length_text(self):
        self.load('empty')

        self.assertEqual(self.post(headers={
            'Content-Length': 'blah',
            'Connection': 'close',
            'Host': 'localhost'
        }, body='X' * 1000)['status'], 400, 'Content-Length text')

    def test_http_header_content_length_multiple_values(self):
        self.load('empty')

        self.assertEqual(self.post(headers={
            'Content-Length': '41, 42',
            'Connection': 'close',
            'Host': 'localhost'
        }, body='X' * 1000)['status'], 400, 'Content-Length multiple value')

    def test_http_header_content_length_multiple_fields(self):
        self.load('empty')

        self.assertEqual(self.post(headers={
            'Content-Length': ['41', '42'],
            'Connection': 'close',
            'Host': 'localhost'
        }, body='X' * 1000)['status'], 400, 'Content-Length multiple fields')

if __name__ == '__main__':
    TestUnitHTTPHeader.main()
