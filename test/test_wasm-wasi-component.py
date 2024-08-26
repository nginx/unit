import pytest
from unit.applications.lang.wasm_component import ApplicationWasmComponent

prerequisites = {
    'modules': {'wasm-wasi-component': 'any'},
    'features': {'cargo_component': True},
}

client = ApplicationWasmComponent()


def test_wasm_component():
    client.load('hello_world')

    req = client.get()

    assert client.get()['status'] == 200
    assert req['body'] == 'Hello'
