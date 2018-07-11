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

        resp = self.get(headers={
            'Custom-Header': '\x20\xFF'
        })

        self.assertEqual(resp['status'], 200, 'value chars edge status')
        self.assertEqual(resp['headers']['Custom-Header'], '\xFF',
            'value chars edge')

    def test_http_header_value_chars_below(self):
        self.load('custom_header')

        resp = self.get(headers={
            'Custom-Header': '\x1F'
        })

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

if __name__ == '__main__':
    unittest.main()
