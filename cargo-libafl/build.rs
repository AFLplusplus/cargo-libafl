use std::{
    env, fs,
    io::{Read, Write},
    path::Path,
    process::Command,
};

#[path = "src/common.rs"]
mod common;

fn main() {
    println!("cargo:rustc-env=TARGET={}", env::var("TARGET").unwrap());
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=cargo-libafl-runtime/runtime.rs");
    println!("cargo:rerun-if-changed=cargo-libafl-runtime/Cargo.toml");

    if env::var("PUBLISH_ON_CRATES").is_ok() || env::var("DOCS_RS").is_ok() {
        return;
    }

    let manifest_dir = env::var_os("CARGO_MANIFEST_DIR").unwrap();
    let manifest_dir = manifest_dir.to_string_lossy().to_string();
    let manifest_path = Path::new(&manifest_dir);
    let rt_path = manifest_path.join("cargo-libafl-runtime");
    let out_dir = env::var_os("OUT_DIR").unwrap();
    let out_dir = out_dir.to_string_lossy().to_string();
    let out_path = Path::new(&out_dir);

    let mut file =
        fs::File::open(&rt_path.join("Cargo.toml")).expect("Couldn't open template.Cargo.toml");
    let mut template = String::new();
    file.read_to_string(&mut template)
        .expect("Couldn't read template.Cargo.toml");
    drop(file);

    template = template.replace(
        "version = \"13.3.7\"",
        &format!("version = \"{}\"", env!("CARGO_PKG_VERSION")),
    );

    let mut file =
        fs::File::create(&out_path.join("Cargo.toml")).expect("Couldn't open Cargo.toml");
    file.write_all(template.as_bytes())
        .expect("Couldn't write Cargo.toml");
    drop(file);

    fs::copy(rt_path.join("runtime.rs"), out_path.join("runtime.rs"))
        .expect("Couldn't copy runtime.rs");

    let mut cmd = Command::new("cargo");
    cmd.current_dir(&out_path)
        .env("CARGO_TARGET_DIR", out_path.join("rt"))
        .arg("build");
    #[cfg(feature = "sancov_8bit")]
    cmd.arg("--features").arg("sancov_8bit");
    #[cfg(feature = "tui")]
    cmd.arg("--features").arg("tui");
    assert!(cmd
        .arg(&format!("--manifest-path={}/Cargo.toml", out_dir))
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
