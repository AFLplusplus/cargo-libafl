use std::path::{Path, PathBuf};

use xdg::BaseDirectories;

fn xdg_dir() -> BaseDirectories {
    let prefix = Path::new("cargo-libafl")
        .join(rustc_version())
        .join(pkg_version());
    BaseDirectories::with_prefix(prefix).unwrap()
}

const SHORT_COMMIT_HASH_LEN: usize = 7;

pub fn rustc_version() -> String {
    let version_meta = rustc_version::version_meta().unwrap();
    let mut ret = String::from("rustc-");
    ret.push_str(&version_meta.semver.to_string());
    if let Some(commit_hash) = version_meta.commit_hash {
        ret.push('-');
        ret.push_str(&commit_hash[..SHORT_COMMIT_HASH_LEN]);
    }
    ret
}

fn pkg_version() -> String {
    let mut ret = String::from("cargo-libafl-");

    let version = env!("CARGO_PKG_VERSION");
    assert!(!version.is_empty());

    ret.push_str(version);
    ret
}

// Place directories inside the crate when building for docs.rs.
// (Modifying system paths are forbidden.)

#[cfg(docsrs)]
pub fn runtime_dir() -> PathBuf {
    let path = PathBuf::from("./cargo-libafl-dummy");
    std::fs::create_dir_all(&path).unwrap();
    path
}

#[cfg(not(docsrs))]
pub fn runtime_dir() -> PathBuf {
    xdg_dir().create_data_directory("cargo-libafl").unwrap()
}

#[allow(dead_code)]
pub fn archive_file_path() -> PathBuf {
    runtime_dir().join("libcargo_libafl_runtime.a")
}
