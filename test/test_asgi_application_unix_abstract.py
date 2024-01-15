from packaging import version

from unit.applications.lang.python import ApplicationPython

prerequisites = {
    'modules': {'python': lambda v: version.parse(v) >= version.parse('3.5')},
    'features': {'unix_abstract': True},
}

client = ApplicationPython(load_module='asgi')


def test_asgi_application_unix_abstract():
    client.load('empty')

    addr = '\0sock'
    assert 'success' in client.conf(
        {f"unix:@{addr[1:]}": {"pass": "applications/empty"}},
        'listeners',
    )

    assert client.get(sock_type='unix', addr=addr)['status'] == 200
