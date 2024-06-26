from unit.applications.lang.wasm_component import ApplicationWasmComponent

def check_cargo_component():
    return ApplicationWasmComponent.prepare_env('hello_world') is not None
