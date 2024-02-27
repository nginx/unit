use std::env;
use std::path::PathBuf;

fn main() {
    // Tell cargo to invalidate the built crate whenever the wrapper changes
    println!("cargo:rerun-if-changed=wrapper.h");

    let bindings = bindgen::Builder::default()
        .clang_args(["-I", "../"])
        .clang_args(["-I", "../../build/include"])
        .header("./wrapper.h")
        // only generate bindings for `nxt_*` header files
        .allowlist_file(".*nxt_.*.h")
        // generates an "improper_ctypes" warning and we don't need it anyway
        .blocklist_function("nxt_vsprintf")
        // Tell cargo to invalidate the built crate whenever any of the
        // included header files changed.
        .parse_callbacks(Box::new(bindgen::CargoCallbacks))
        // disable some features which aren't necessary
        .layout_tests(false)
        .derive_debug(false)
        .generate()
        .expect("Unable to generate bindings");

    cc::Build::new()
        .object("../../build/src/nxt_unit.o")
        .compile("nxt-unit");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
