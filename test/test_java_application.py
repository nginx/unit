import io
import re
import time
from pathlib import Path

from unit.applications.lang.java import ApplicationJava
from unit.option import option
from unit.utils import public_dir

prerequisites = {'modules': {'java': 'all'}}

client = ApplicationJava()


def test_java_conf_error(temp_dir, skip_alert):
    skip_alert(
        r'realpath.*failed',
        r'failed to apply new conf',
        r'application setup failed',
    )
    assert 'error' in client.conf(
        {
            "listeners": {"*:8080": {"pass": "applications/app"}},
            "applications": {
                "app": {
                    "type": client.get_application_type(),
                    "processes": 1,
                    "working_directory": f"{option.test_dir}/java/empty",
                    "webapp": f"{temp_dir}/java",
                    "unit_jars": f"{temp_dir}/no_such_dir",
                }
            },
        }
    ), 'conf error'


def test_java_war(temp_dir):
    client.load('empty_war')

    assert 'success' in client.conf(
        f'"{temp_dir}/java/empty.war"',
        '/config/applications/empty_war/webapp',
    ), 'configure war'

    assert client.get()['status'] == 200, 'war'


def test_java_application_cookies():
    client.load('cookies')

    headers = client.get(
        headers={
            'Cookie': 'var1=val1; var2=val2',
            'Host': 'localhost',
            'Connection': 'close',
        }
    )['headers']

    assert headers['X-Cookie-1'] == 'val1', 'cookie 1'
    assert headers['X-Cookie-2'] == 'val2', 'cookie 2'


def test_java_application_filter():
    client.load('filter')

    headers = client.get()['headers']

    assert headers['X-Filter-Before'] == '1', 'filter before'
    assert headers['X-Filter-After'] == '1', 'filter after'

    assert (
        client.get(url='/test')['headers']['X-Filter-After'] == '0'
    ), 'filter after 2'


def test_java_application_get_variables():
    client.load('get_params')

    def check_header(header, expect):
        values = header.split(' ')[:-1]
        assert len(values) == len(expect)
        assert set(values) == set(expect)

    headers = client.get(url='/?var1=val1&var2=&var4=val4&var4=foo')['headers']

    assert headers['X-Var-1'] == 'val1', 'GET variables'
    assert headers['X-Var-2'] == 'true', 'GET variables 2'
    assert headers['X-Var-3'] == 'false', 'GET variables 3'

    check_header(headers['X-Param-Names'], ['var4', 'var2', 'var1'])
    check_header(headers['X-Param-Values'], ['val4', 'foo'])
    check_header(
        headers['X-Param-Map'], ['var2=', 'var1=val1', 'var4=val4,foo']
    )


def test_java_application_post_variables():
    client.load('post_params')

    headers = client.post(
        headers={
            'Content-Type': 'application/x-www-form-urlencoded',
            'Host': 'localhost',
            'Connection': 'close',
        },
        body='var1=val1&var2=',
    )['headers']

    assert headers['X-Var-1'] == 'val1', 'POST variables'
    assert headers['X-Var-2'] == 'true', 'POST variables 2'
    assert headers['X-Var-3'] == 'false', 'POST variables 3'


def test_java_application_session():
    client.load('session')

    headers = client.get(url='/?var1=val1')['headers']
    session_id = headers['X-Session-Id']

    assert headers['X-Var-1'] == 'null', 'variable empty'
    assert headers['X-Session-New'] == 'true', 'session create'

    headers = client.get(
        headers={
            'Host': 'localhost',
            'Cookie': f'JSESSIONID={session_id}',
            'Connection': 'close',
        },
        url='/?var1=val2',
    )['headers']

    assert headers['X-Var-1'] == 'val1', 'variable'
    assert headers['X-Session-New'] == 'false', 'session resume'
    assert session_id == headers['X-Session-Id'], 'session same id'


def test_java_application_session_active(date_to_sec_epoch, sec_epoch):
    client.load('session_inactive')

    resp = client.get(
        headers={
            'X-Interval': '4',
            'Host': 'localhost',
            'Connection': 'close',
        }
    )
    session_id = resp['headers']['X-Session-Id']

    assert resp['status'] == 200, 'session init'
    assert resp['headers']['X-Session-Interval'] == '4', 'session interval'
    assert (
        abs(
            date_to_sec_epoch(resp['headers']['X-Session-Last-Access-Time'])
            - sec_epoch
        )
        < 5
    ), 'session last access time'

    time.sleep(1)

    resp = client.get(
        headers={
            'Host': 'localhost',
            'Cookie': f'JSESSIONID={session_id}',
            'Connection': 'close',
        }
    )

    assert resp['headers']['X-Session-Id'] == session_id, 'session active'

    session_id = resp['headers']['X-Session-Id']

    time.sleep(1)

    resp = client.get(
        headers={
            'Host': 'localhost',
            'Cookie': f'JSESSIONID={session_id}',
            'Connection': 'close',
        }
    )

    assert resp['headers']['X-Session-Id'] == session_id, 'session active 2'

    time.sleep(2)

    resp = client.get(
        headers={
            'Host': 'localhost',
            'Cookie': f'JSESSIONID={session_id}',
            'Connection': 'close',
        }
    )

    assert resp['headers']['X-Session-Id'] == session_id, 'session active 3'


def test_java_application_session_inactive():
    client.load('session_inactive')

    resp = client.get(
        headers={
            'X-Interval': '1',
            'Host': 'localhost',
            'Connection': 'close',
        }
    )
    session_id = resp['headers']['X-Session-Id']

    time.sleep(3)

    resp = client.get(
        headers={
            'Host': 'localhost',
            'Cookie': f'JSESSIONID={session_id}',
            'Connection': 'close',
        }
    )

    assert resp['headers']['X-Session-Id'] != session_id, 'session inactive'


def test_java_application_session_invalidate():
    client.load('session_invalidate')

    resp = client.get()
    session_id = resp['headers']['X-Session-Id']

    resp = client.get(
        headers={
            'Host': 'localhost',
            'Cookie': f'JSESSIONID={session_id}',
            'Connection': 'close',
        }
    )

    assert resp['headers']['X-Session-Id'] != session_id, 'session invalidate'


def test_java_application_session_listeners():
    client.load('session_listeners')

    headers = client.get(url='/test?var1=val1')['headers']
    session_id = headers['X-Session-Id']

    assert headers['X-Session-Created'] == session_id, 'session create'
    assert headers['X-Attr-Added'] == 'var1=val1', 'attribute add'

    headers = client.get(
        headers={
            'Host': 'localhost',
            'Cookie': f'JSESSIONID={session_id}',
            'Connection': 'close',
        },
        url='/?var1=val2',
    )['headers']

    assert session_id == headers['X-Session-Id'], 'session same id'
    assert headers['X-Attr-Replaced'] == 'var1=val1', 'attribute replace'

    headers = client.get(
        headers={
            'Host': 'localhost',
            'Cookie': f'JSESSIONID={session_id}',
            'Connection': 'close',
        },
        url='/',
    )['headers']

    assert session_id == headers['X-Session-Id'], 'session same id'
    assert headers['X-Attr-Removed'] == 'var1=val2', 'attribute remove'


def test_java_application_jsp():
    client.load('jsp')

    headers = client.get(url='/index.jsp')['headers']

    assert headers['X-Unit-JSP'] == 'ok', 'JSP Ok header'


def test_java_application_url_pattern():
    client.load('url_pattern')

    headers = client.get(url='/foo/bar/index.html')['headers']

    assert headers['X-Id'] == 'servlet1', '#1 Servlet1 request'
    assert headers['X-Request-URI'] == '/foo/bar/index.html', '#1 request URI'
    assert headers['X-Servlet-Path'] == '/foo/bar', '#1 servlet path'
    assert headers['X-Path-Info'] == '/index.html', '#1 path info'

    headers = client.get(url='/foo/bar/index.bop')['headers']

    assert headers['X-Id'] == 'servlet1', '#2 Servlet1 request'
    assert headers['X-Request-URI'] == '/foo/bar/index.bop', '#2 request URI'
    assert headers['X-Servlet-Path'] == '/foo/bar', '#2 servlet path'
    assert headers['X-Path-Info'] == '/index.bop', '#2 path info'

    headers = client.get(url='/baz')['headers']

    assert headers['X-Id'] == 'servlet2', '#3 Servlet2 request'
    assert headers['X-Request-URI'] == '/baz', '#3 request URI'
    assert headers['X-Servlet-Path'] == '/baz', '#3 servlet path'
    assert headers['X-Path-Info'] == 'null', '#3 path info'

    headers = client.get(url='/baz/index.html')['headers']

    assert headers['X-Id'] == 'servlet2', '#4 Servlet2 request'
    assert headers['X-Request-URI'] == '/baz/index.html', '#4 request URI'
    assert headers['X-Servlet-Path'] == '/baz', '#4 servlet path'
    assert headers['X-Path-Info'] == '/index.html', '#4 path info'

    headers = client.get(url='/catalog')['headers']

    assert headers['X-Id'] == 'servlet3', '#5 Servlet3 request'
    assert headers['X-Request-URI'] == '/catalog', '#5 request URI'
    assert headers['X-Servlet-Path'] == '/catalog', '#5 servlet path'
    assert headers['X-Path-Info'] == 'null', '#5 path info'

    headers = client.get(url='/catalog/index.html')['headers']

    assert headers['X-Id'] == 'default', '#6 default request'
    assert headers['X-Request-URI'] == '/catalog/index.html', '#6 request URI'
    assert headers['X-Servlet-Path'] == '/catalog/index.html', '#6 servlet path'
    assert headers['X-Path-Info'] == 'null', '#6 path info'

    headers = client.get(url='/catalog/racecar.bop')['headers']

    assert headers['X-Id'] == 'servlet4', '#7 servlet4 request'
    assert headers['X-Request-URI'] == '/catalog/racecar.bop', '#7 request URI'
    assert (
        headers['X-Servlet-Path'] == '/catalog/racecar.bop'
    ), '#7 servlet path'
    assert headers['X-Path-Info'] == 'null', '#7 path info'

    headers = client.get(url='/index.bop')['headers']

    assert headers['X-Id'] == 'servlet4', '#8 servlet4 request'
    assert headers['X-Request-URI'] == '/index.bop', '#8 request URI'
    assert headers['X-Servlet-Path'] == '/index.bop', '#8 servlet path'
    assert headers['X-Path-Info'] == 'null', '#8 path info'

    headers = client.get(url='/foo/baz')['headers']

    assert headers['X-Id'] == 'servlet0', '#9 servlet0 request'
    assert headers['X-Request-URI'] == '/foo/baz', '#9 request URI'
    assert headers['X-Servlet-Path'] == '/foo', '#9 servlet path'
    assert headers['X-Path-Info'] == '/baz', '#9 path info'

    headers = client.get()['headers']

    assert headers['X-Id'] == 'default', '#10 default request'
    assert headers['X-Request-URI'] == '/', '#10 request URI'
    assert headers['X-Servlet-Path'] == '/', '#10 servlet path'
    assert headers['X-Path-Info'] == 'null', '#10 path info'

    headers = client.get(url='/index.bop/')['headers']

    assert headers['X-Id'] == 'default', '#11 default request'
    assert headers['X-Request-URI'] == '/index.bop/', '#11 request URI'
    assert headers['X-Servlet-Path'] == '/index.bop/', '#11 servlet path'
    assert headers['X-Path-Info'] == 'null', '#11 path info'


def test_java_application_header():
    client.load('header')

    headers = client.get()['headers']

    assert headers['X-Set-Utf8-Value'] == '????', 'set Utf8 header value'
    assert headers['X-Set-Utf8-Name-???'] == 'x', 'set Utf8 header name'
    assert headers['X-Add-Utf8-Value'] == '????', 'add Utf8 header value'
    assert headers['X-Add-Utf8-Name-???'] == 'y', 'add Utf8 header name'
    assert headers['X-Add-Test'] == 'v1', 'add null header'
    assert 'X-Set-Test1' not in headers, 'set null header'
    assert headers['X-Set-Test2'] == '', 'set empty header'


def test_java_application_content_type():
    client.load('content_type')

    headers = client.get(url='/1')['headers']

    assert (
        headers['Content-Type'] == 'text/plain;charset=utf-8'
    ), '#1 Content-Type header'
    assert (
        headers['X-Content-Type'] == 'text/plain;charset=utf-8'
    ), '#1 response Content-Type'
    assert headers['X-Character-Encoding'] == 'utf-8', '#1 response charset'

    headers = client.get(url='/2')['headers']

    assert (
        headers['Content-Type'] == 'text/plain;charset=iso-8859-1'
    ), '#2 Content-Type header'
    assert (
        headers['X-Content-Type'] == 'text/plain;charset=iso-8859-1'
    ), '#2 response Content-Type'
    assert (
        headers['X-Character-Encoding'] == 'iso-8859-1'
    ), '#2 response charset'

    headers = client.get(url='/3')['headers']

    assert (
        headers['Content-Type'] == 'text/plain;charset=windows-1251'
    ), '#3 Content-Type header'
    assert (
        headers['X-Content-Type'] == 'text/plain;charset=windows-1251'
    ), '#3 response Content-Type'
    assert (
        headers['X-Character-Encoding'] == 'windows-1251'
    ), '#3 response charset'

    headers = client.get(url='/4')['headers']

    assert (
        headers['Content-Type'] == 'text/plain;charset=windows-1251'
    ), '#4 Content-Type header'
    assert (
        headers['X-Content-Type'] == 'text/plain;charset=windows-1251'
    ), '#4 response Content-Type'
    assert (
        headers['X-Character-Encoding'] == 'windows-1251'
    ), '#4 response charset'

    headers = client.get(url='/5')['headers']

    assert (
        headers['Content-Type'] == 'text/plain;charset=iso-8859-1'
    ), '#5 Content-Type header'
    assert (
        headers['X-Content-Type'] == 'text/plain;charset=iso-8859-1'
    ), '#5 response Content-Type'
    assert (
        headers['X-Character-Encoding'] == 'iso-8859-1'
    ), '#5 response charset'

    headers = client.get(url='/6')['headers']

    assert 'Content-Type' not in headers, '#6 no Content-Type header'
    assert 'X-Content-Type' not in headers, '#6 no response Content-Type'
    assert headers['X-Character-Encoding'] == 'utf-8', '#6 response charset'

    headers = client.get(url='/7')['headers']

    assert (
        headers['Content-Type'] == 'text/plain;charset=utf-8'
    ), '#7 Content-Type header'
    assert (
        headers['X-Content-Type'] == 'text/plain;charset=utf-8'
    ), '#7 response Content-Type'
    assert headers['X-Character-Encoding'] == 'utf-8', '#7 response charset'

    headers = client.get(url='/8')['headers']

    assert (
        headers['Content-Type'] == 'text/html;charset=utf-8'
    ), '#8 Content-Type header'
    assert (
        headers['X-Content-Type'] == 'text/html;charset=utf-8'
    ), '#8 response Content-Type'
    assert headers['X-Character-Encoding'] == 'utf-8', '#8 response charset'


def test_java_application_welcome_files():
    client.load('welcome_files')

    headers = client.get()['headers']

    resp = client.get(url='/dir1')

    assert resp['status'] == 302, 'dir redirect expected'

    resp = client.get(url='/dir1/')

    assert 'This is index.txt.' in resp['body'], 'dir1 index body'
    assert resp['headers']['X-TXT-Filter'] == '1', 'TXT Filter header'

    headers = client.get(url='/dir2/')['headers']

    assert headers['X-Unit-JSP'] == 'ok', 'JSP Ok header'
    assert headers['X-JSP-Filter'] == '1', 'JSP Filter header'

    headers = client.get(url='/dir3/')['headers']

    assert headers['X-App-Servlet'] == '1', 'URL pattern overrides welcome file'

    headers = client.get(url='/dir4/')['headers']

    assert 'X-App-Servlet' not in headers, 'Static welcome file served first'

    headers = client.get(url='/dir5/')['headers']

    assert (
        headers['X-App-Servlet'] == '1'
    ), 'Servlet for welcome file served when no static file found'


def test_java_application_request_listeners():
    client.load('request_listeners')

    headers = client.get(url='/test1')['headers']

    assert (
        headers['X-Request-Initialized'] == '/test1'
    ), 'request initialized event'
    assert headers['X-Request-Destroyed'] == '', 'request destroyed event'
    assert headers['X-Attr-Added'] == '', 'attribute added event'
    assert headers['X-Attr-Removed'] == '', 'attribute removed event'
    assert headers['X-Attr-Replaced'] == '', 'attribute replaced event'

    headers = client.get(url='/test2?var1=1')['headers']

    assert (
        headers['X-Request-Initialized'] == '/test2'
    ), 'request initialized event'
    assert headers['X-Request-Destroyed'] == '/test1', 'request destroyed event'
    assert headers['X-Attr-Added'] == 'var=1;', 'attribute added event'
    assert headers['X-Attr-Removed'] == 'var=1;', 'attribute removed event'
    assert headers['X-Attr-Replaced'] == '', 'attribute replaced event'

    headers = client.get(url='/test3?var1=1&var2=2')['headers']

    assert (
        headers['X-Request-Initialized'] == '/test3'
    ), 'request initialized event'
    assert headers['X-Request-Destroyed'] == '/test2', 'request destroyed event'
    assert headers['X-Attr-Added'] == 'var=1;', 'attribute added event'
    assert headers['X-Attr-Removed'] == 'var=2;', 'attribute removed event'
    assert headers['X-Attr-Replaced'] == 'var=1;', 'attribute replaced event'

    headers = client.get(url='/test4?var1=1&var2=2&var3=3')['headers']

    assert (
        headers['X-Request-Initialized'] == '/test4'
    ), 'request initialized event'
    assert headers['X-Request-Destroyed'] == '/test3', 'request destroyed event'
    assert headers['X-Attr-Added'] == 'var=1;', 'attribute added event'
    assert headers['X-Attr-Removed'] == '', 'attribute removed event'
    assert (
        headers['X-Attr-Replaced'] == 'var=1;var=2;'
    ), 'attribute replaced event'


def test_java_application_request_uri_forward():
    client.load('forward')

    resp = client.get(
        url='/fwd?uri=%2Fdata%2Ftest%3Furi%3Dnew_uri%26a%3D2%26b%3D3&a=1&c=4'
    )
    headers = resp['headers']

    assert headers['X-REQUEST-Id'] == 'fwd', 'initial request servlet mapping'
    assert (
        headers['X-Forward-To'] == '/data/test?uri=new_uri&a=2&b=3'
    ), 'forwarding triggered'
    assert (
        headers['X-REQUEST-Param-uri'] == '/data/test?uri=new_uri&a=2&b=3'
    ), 'original uri parameter'
    assert headers['X-REQUEST-Param-a'] == '1', 'original a parameter'
    assert headers['X-REQUEST-Param-c'] == '4', 'original c parameter'

    assert headers['X-FORWARD-Id'] == 'data', 'forward request servlet mapping'
    assert (
        headers['X-FORWARD-Request-URI'] == '/data/test'
    ), 'forward request uri'
    assert (
        headers['X-FORWARD-Servlet-Path'] == '/data'
    ), 'forward request servlet path'
    assert (
        headers['X-FORWARD-Path-Info'] == '/test'
    ), 'forward request path info'
    assert (
        headers['X-FORWARD-Query-String'] == 'uri=new_uri&a=2&b=3'
    ), 'forward request query string'
    assert (
        headers['X-FORWARD-Param-uri']
        == 'new_uri,/data/test?uri=new_uri&a=2&b=3'
    ), 'forward uri parameter'
    assert headers['X-FORWARD-Param-a'] == '2,1', 'forward a parameter'
    assert headers['X-FORWARD-Param-b'] == '3', 'forward b parameter'
    assert headers['X-FORWARD-Param-c'] == '4', 'forward c parameter'

    assert (
        headers['X-javax.servlet.forward.request_uri'] == '/fwd'
    ), 'original request uri'
    assert (
        headers['X-javax.servlet.forward.context_path'] == ''
    ), 'original request context path'
    assert (
        headers['X-javax.servlet.forward.servlet_path'] == '/fwd'
    ), 'original request servlet path'
    assert (
        headers['X-javax.servlet.forward.path_info'] == 'null'
    ), 'original request path info'
    assert (
        headers['X-javax.servlet.forward.query_string']
        == 'uri=%2Fdata%2Ftest%3Furi%3Dnew_uri%26a%3D2%26b%3D3&a=1&c=4'
    ), 'original request query'

    assert (
        'Before forwarding' not in resp['body']
    ), 'discarded data added before forward() call'
    assert (
        'X-After-Forwarding' not in headers
    ), 'cannot add headers after forward() call'
    assert (
        'After forwarding' not in resp['body']
    ), 'cannot add data after forward() call'


def test_java_application_named_dispatcher_forward():
    client.load('forward')

    resp = client.get(url='/fwd?disp=name&uri=data')
    headers = resp['headers']

    assert headers['X-REQUEST-Id'] == 'fwd', 'initial request servlet mapping'
    assert headers['X-Forward-To'] == 'data', 'forwarding triggered'

    assert headers['X-FORWARD-Id'] == 'data', 'forward request servlet mapping'
    assert headers['X-FORWARD-Request-URI'] == '/fwd', 'forward request uri'
    assert (
        headers['X-FORWARD-Servlet-Path'] == '/fwd'
    ), 'forward request servlet path'
    assert headers['X-FORWARD-Path-Info'] == 'null', 'forward request path info'
    assert (
        headers['X-FORWARD-Query-String'] == 'disp=name&uri=data'
    ), 'forward request query string'

    assert (
        headers['X-javax.servlet.forward.request_uri'] == 'null'
    ), 'original request uri'
    assert (
        headers['X-javax.servlet.forward.context_path'] == 'null'
    ), 'original request context path'
    assert (
        headers['X-javax.servlet.forward.servlet_path'] == 'null'
    ), 'original request servlet path'
    assert (
        headers['X-javax.servlet.forward.path_info'] == 'null'
    ), 'original request path info'
    assert (
        headers['X-javax.servlet.forward.query_string'] == 'null'
    ), 'original request query'

    assert (
        'Before forwarding' not in resp['body']
    ), 'discarded data added before forward() call'
    assert (
        'X-After-Forwarding' not in headers
    ), 'cannot add headers after forward() call'
    assert (
        'After forwarding' not in resp['body']
    ), 'cannot add data after forward() call'


def test_java_application_request_uri_include():
    client.load('include')

    resp = client.get(url='/inc?uri=/data/test')
    headers = resp['headers']
    body = resp['body']

    assert headers['X-REQUEST-Id'] == 'inc', 'initial request servlet mapping'
    assert headers['X-Include'] == '/data/test', 'including triggered'

    assert (
        'X-INCLUDE-Id' not in headers
    ), 'unable to add headers in include request'

    assert (
        'javax.servlet.include.request_uri:  /data/test' in body
    ), 'include request uri'
    # assert (
    #    'javax.servlet.include.context_path: ' in body
    # ) == True, 'include request context path'
    assert (
        'javax.servlet.include.servlet_path: /data' in body
    ), 'include request servlet path'
    assert (
        'javax.servlet.include.path_info:    /test' in body
    ), 'include request path info'
    assert (
        'javax.servlet.include.query_string: null' in body
    ), 'include request query'

    assert 'Before include' in body, 'preserve data added before include() call'
    assert (
        headers['X-After-Include'] == 'you-should-see-this'
    ), 'add headers after include() call'
    assert 'After include' in body, 'add data after include() call'


def test_java_application_named_dispatcher_include():
    client.load('include')

    resp = client.get(url='/inc?disp=name&uri=data')
    headers = resp['headers']
    body = resp['body']

    assert headers['X-REQUEST-Id'] == 'inc', 'initial request servlet mapping'
    assert headers['X-Include'] == 'data', 'including triggered'

    assert (
        'X-INCLUDE-Id' not in headers
    ), 'unable to add headers in include request'

    assert (
        'javax.servlet.include.request_uri:  null' in body
    ), 'include request uri'
    # assert (
    #    'javax.servlet.include.context_path: null' in body
    # ) == True, 'include request context path'
    assert (
        'javax.servlet.include.servlet_path: null' in body
    ), 'include request servlet path'
    assert (
        'javax.servlet.include.path_info:    null' in body
    ), 'include request path info'
    assert (
        'javax.servlet.include.query_string: null' in body
    ), 'include request query'

    assert 'Before include' in body, 'preserve data added before include() call'
    assert (
        headers['X-After-Include'] == 'you-should-see-this'
    ), 'add headers after include() call'
    assert 'After include' in body, 'add data after include() call'


def test_java_application_path_translation():
    client.load('path_translation')

    headers = client.get(url='/pt/test?path=/')['headers']

    assert headers['X-Servlet-Path'] == '/pt', 'matched servlet path'
    assert headers['X-Path-Info'] == '/test', 'the rest of the path'
    assert (
        headers['X-Path-Translated']
        == f"{headers['X-Real-Path']}{headers['X-Path-Info']}"
    ), 'translated path is the app root + path info'
    assert headers['X-Resource-Paths'].endswith(
        '/WEB-INF/, /index.html]'
    ), 'app root directory content'
    assert (
        headers['X-Resource-As-Stream'] == 'null'
    ), 'no resource stream for root path'

    headers = client.get(url='/test?path=/none')['headers']

    assert headers['X-Servlet-Path'] == '/test', 'matched whole path'
    assert (
        headers['X-Path-Info'] == 'null'
    ), 'the rest of the path is null, whole path matched'
    assert (
        headers['X-Path-Translated'] == 'null'
    ), 'translated path is null because path info is null'
    assert headers['X-Real-Path'].endswith('/none'), 'read path is not null'
    assert headers['X-Resource-Paths'] == 'null', 'no resource found'
    assert headers['X-Resource-As-Stream'] == 'null', 'no resource stream'


def test_java_application_query_string():
    client.load('query_string')

    assert (
        client.get(url='/?a=b')['headers']['X-Query-String'] == 'a=b'
    ), 'query string'


def test_java_application_query_empty():
    client.load('query_string')

    assert (
        client.get(url='/?')['headers']['X-Query-String'] == ''
    ), 'query string empty'


def test_java_application_query_absent():
    client.load('query_string')

    assert (
        client.get()['headers']['X-Query-String'] == 'null'
    ), 'query string absent'


def test_java_application_empty():
    client.load('empty')

    assert client.get()['status'] == 200, 'empty'


def test_java_application_keepalive_body():
    client.load('mirror')

    assert client.post()['status'] == 200, 'init'

    body = '0123456789' * 500
    (resp, sock) = client.post(
        headers={
            'Connection': 'keep-alive',
            'Content-Type': 'text/html',
            'Host': 'localhost',
        },
        start=True,
        body=body,
        read_timeout=1,
    )

    assert resp['body'] == body, 'keep-alive 1'

    body = '0123456789'
    resp = client.post(
        headers={
            'Connection': 'close',
            'Content-Type': 'text/html',
            'Host': 'localhost',
        },
        sock=sock,
        body=body,
    )

    assert resp['body'] == body, 'keep-alive 2'


def test_java_application_http_10():
    client.load('empty')

    assert client.get(http_10=True)['status'] == 200, 'HTTP 1.0'


def test_java_application_no_method():
    client.load('empty')

    assert client.post()['status'] == 405, 'no method'


def test_java_application_get_header():
    client.load('get_header')

    assert (
        client.get(
            headers={
                'X-Header': 'blah',
                'Content-Type': 'text/html',
                'Host': 'localhost',
                'Connection': 'close',
            }
        )['headers']['X-Reply']
        == 'blah'
    ), 'get header'


def test_java_application_get_header_empty():
    client.load('get_header')

    assert 'X-Reply' not in client.get()['headers'], 'get header empty'


def test_java_application_get_headers():
    client.load('get_headers')

    headers = client.get(
        headers={
            'X-Header': ['blah', 'blah'],
            'Content-Type': 'text/html',
            'Host': 'localhost',
            'Connection': 'close',
        }
    )['headers']

    assert headers['X-Reply-0'] == 'blah', 'get headers'
    assert headers['X-Reply-1'] == 'blah', 'get headers 2'


def test_java_application_many_headers():
    client.load('get_headers')

    value = '0123456789' * 10

    headers = client.get(
        headers={
            'X-Header': [value] * 100,
            'Content-Type': 'text/html',
            'Host': 'localhost',
            'Connection': 'close',
        }
    )['headers']

    for i in range(0, 99):
        assert headers[f'X-Reply-{i}'] == value, 'many headers'


def test_java_application_get_headers_empty():
    client.load('get_headers')

    assert 'X-Reply-0' not in client.get()['headers'], 'get headers empty'


def test_java_application_get_header_names():
    client.load('get_header_names')

    headers = client.get()['headers']

    assert re.search(
        r'(?:Host|Connection)', headers['X-Reply-0']
    ), 'get header names'
    assert re.search(
        r'(?:Host|Connection)', headers['X-Reply-1']
    ), 'get header names 2'
    assert (
        headers['X-Reply-0'] != headers['X-Reply-1']
    ), 'get header names not equal'


def test_java_application_header_int():
    client.load('header_int')

    headers = client.get(
        headers={
            'X-Header': '2',
            'Content-Type': 'text/html',
            'Host': 'localhost',
            'Connection': 'close',
        }
    )['headers']

    assert headers['X-Set-Int'] == '1', 'set int header'
    assert headers['X-Get-Int'] == '2', 'get int header'


def test_java_application_header_date():
    client.load('header_date')

    date = 'Fri, 15 Mar 2019 14:45:34 GMT'

    headers = client.get(
        headers={
            'X-Header': date,
            'Content-Type': 'text/html',
            'Host': 'localhost',
            'Connection': 'close',
        }
    )['headers']

    assert (
        headers['X-Set-Date'] == 'Thu, 01 Jan 1970 00:00:01 GMT'
    ), 'set date header'
    assert headers['X-Get-Date'] == date, 'get date header'


def test_java_application_multipart(search_in_file, temp_dir):
    client.load('multipart')

    reldst = '/uploads'
    fulldst = f'{temp_dir}{reldst}'
    Path(fulldst).mkdir(parents=True)
    public_dir(fulldst)

    fields = {
        'file': {
            'filename': 'sample.txt',
            'type': 'text/plain',
            'data': io.StringIO('Data from sample file'),
        },
        'destination': fulldst,
        'upload': 'Upload',
    }

    encoded, content_type = client.multipart_encode(fields)

    preamble = 'Preamble. Should be ignored.'
    epilogue = 'Epilogue. Should be ignored.'
    body = f'{preamble}\r\n{encoded.decode()}\r\n{epilogue}'

    resp = client.post(
        headers={
            'Content-Type': content_type,
            'Host': 'localhost',
            'Connection': 'close',
        },
        body=body,
    )

    assert resp['status'] == 200, 'multipart status'
    assert re.search(r'sample\.txt created', resp['body']), 'multipart body'
    assert (
        search_in_file(r'^Data from sample file$', name=f'{reldst}/sample.txt')
        is not None
    ), 'file created'


def test_java_application_threads():
    client.load('threads')

    assert 'success' in client.conf(
        '4', 'applications/threads/threads'
    ), 'configure 4 threads'

    socks = []

    for _ in range(4):
        sock = client.get(
            headers={
                'Host': 'localhost',
                'X-Delay': '2',
                'Connection': 'close',
            },
            no_recv=True,
        )

        socks.append(sock)

        time.sleep(0.25)  # required to avoid greedy request reading

    threads = set()

    for sock in socks:
        resp = client.recvall(sock).decode('utf-8')

        client.log_in(resp)

        resp = client._resp_to_dict(resp)

        assert resp['status'] == 200, 'status'

        threads.add(resp['headers']['X-Thread'])

        sock.close()

    assert len(socks) == len(threads), 'threads differs'
