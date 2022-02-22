/// The default target to pass to cargo, to workaround issue #11.
pub fn default_target() -> &'static str {
    option_env!("TARGET").unwrap_or("x86_64-unknown-linux-gnu")
}
