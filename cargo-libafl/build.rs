use std::{env, fs, path::Path, process::Command};

#[path = "src/common.rs"]
mod common;

fn main() {
    println!("cargo:rustc-env=TARGET={}", env::var("TARGET").unwrap());
    println!("cargo:rerun-if-changed=build.rs");

    let rt_path = Path::new("cargo-libafl-runtime");
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();
    let out_path = Path::new(&out_dir);

    assert!(Command::new("cargo")
        .current_dir(&rt_path)
        .env("CARGO_TARGET_DIR", out_path.join("rt"))
        .arg("build")
        .arg("--release")
        .status()
        .unwrap()
        .success());

    let archive = out_path
        .join("rt")
        .join("release")
        .join("libcargo_libafl_runtime.a");
    fs::copy(archive, common::archive_file_path())
        .expect("Couldn't copy libcargo_libafl_runtime.a");
}
