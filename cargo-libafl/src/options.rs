mod add;
mod build;
mod coverage;
mod fmt;
mod init;
mod list;
mod run;

pub use self::{
    add::Add, build::Build, coverage::Coverage, fmt::Fmt, init::Init, list::List, run::Run,
};

use clap::{self, Parser};
use std::str::FromStr;
use std::{fmt as stdfmt, path::PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sanitizer {
    Address,
    Leak,
    Memory,
    Thread,
    None,
}

impl stdfmt::Display for Sanitizer {
    fn fmt(&self, f: &mut stdfmt::Formatter) -> stdfmt::Result {
        write!(
            f,
            "{}",
            match self {
                Sanitizer::Address => "address",
                Sanitizer::Leak => "leak",
                Sanitizer::Memory => "memory",
                Sanitizer::Thread => "thread",
                Sanitizer::None => "",
            }
        )
    }
}

impl FromStr for Sanitizer {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "address" => Ok(Sanitizer::Address),
            "leak" => Ok(Sanitizer::Leak),
            "memory" => Ok(Sanitizer::Memory),
            "thread" => Ok(Sanitizer::Thread),
            "none" => Ok(Sanitizer::None),
            _ => Err(format!("unknown sanitizer: {}", s)),
        }
    }
}

#[derive(Clone, Debug, Parser, PartialEq, Eq)]
#[allow(clippy::struct_excessive_bools)]
pub struct BuildOptions {
    #[clap(short = 'D', long = "dev", conflicts_with = "release")]
    /// Build artifacts in development mode, without optimizations
    pub dev: bool,

    #[clap(short = 'O', long = "release", conflicts_with = "dev")]
    /// Build artifacts in release mode, with optimizations
    pub release: bool,

    #[clap(short = 'a', long = "debug-assertions")]
    /// Build artifacts with debug assertions and overflow checks enabled (default if not -O)
    pub debug_assertions: bool,

    /// Build target with verbose output from `cargo build`
    #[clap(short = 'v', long = "verbose")]
    pub verbose: bool,

    #[clap(long = "no-default-features")]
    /// Build artifacts with default Cargo features disabled
    pub no_default_features: bool,

    #[clap(
        long = "all-features",
        conflicts_with = "no-default-features",
        conflicts_with = "features"
    )]
    /// Build artifacts with all Cargo features enabled
    pub all_features: bool,

    #[clap(long = "features")]
    /// Build artifacts with given Cargo feature enabled
    pub features: Option<String>,

    #[clap(
        short = 's',
        long = "sanitizer",
        possible_values(&["address", "leak", "memory", "thread", "none"]),
        default_value = "address",
    )]
    /// Use a specific sanitizer
    pub sanitizer: Sanitizer,

    #[clap(long = "build-std")]
    /// Pass `-Zbuild-std` to cargo to build the standard library with the same build settings as
    /// the fuzz target, such as debug assertions and sanitizers. This allows to identify a more
    /// diverse set of bugs. But beware, some sanitizers might cause false alarms with the standard
    /// library (e.g., thread sanitizer). Currently this conflicts with source-based coverage
    /// instrumentation.
    pub build_std: bool,

    #[clap(short, long = "careful")]
    /// enable "careful" mode: inspired by https://github.com/RalfJung/cargo-careful, this enables building the
    /// standard library (implies --build-std) with debug assertions and extra const UB and init checks.
    pub careful_mode: bool,

    #[clap(
        name = "triple",
        long = "target",
        default_value(crate::utils::default_target())
    )]
    /// Target triple of the fuzz target
    pub triple: String,

    #[clap(short = 'Z', value_name = "FLAG")]
    /// Unstable (nightly-only) flags to Cargo
    pub unstable_flags: Vec<String>,

    #[clap(long = "target-dir")]
    /// Target dir option to pass to cargo build.
    pub target_dir: Option<String>,

    #[clap(skip = false)]
    /// Instrument program code with source-based code coverage information.
    /// This build option will be automatically used when running `cargo fuzz coverage`.
    /// The option will not be shown to the user, which is ensured by the `skip` attribute.
    /// The attribute takes a default value `false`, ensuring that by default,
    /// the coverage option will be disabled).
    pub coverage: bool,

    /// Dead code is linked by default to prevent a potential error with some
    /// optimized targets. This flag allows you to opt out of it.
    #[clap(long)]
    pub strip_dead_code: bool,

    /// By default the 'cfg(fuzzing)' compilation configuration is set. This flag
    /// allows you to opt out of it.
    #[clap(long)]
    pub no_cfg_fuzzing: bool,

    #[clap(long)]
    /// Don't build with the `sanitizer-coverage-trace-compares` LLVM argument
    ///
    ///  Using this may improve fuzzer throughput at the cost of worse coverage accuracy.
    /// It also allows older CPUs lacking the `popcnt` instruction to use `cargo-fuzz`;
    /// the `*-trace-compares` instrumentation assumes that the instruction is
    /// available.
    pub no_trace_compares: bool,
}

impl stdfmt::Display for BuildOptions {
    fn fmt(&self, f: &mut stdfmt::Formatter) -> stdfmt::Result {
        if self.dev {
            write!(f, " -D")?;
        }

        if self.release {
            write!(f, " -O")?;
        }

        if self.debug_assertions {
            write!(f, " -a")?;
        }

        if self.verbose {
            write!(f, " -v")?;
        }

        if self.no_default_features {
            write!(f, " --no-default-features")?;
        }

        if self.all_features {
            write!(f, " --all-features")?;
        }

        if let Some(feature) = &self.features {
            write!(f, " --features={}", feature)?;
        }

        match self.sanitizer {
            Sanitizer::None => write!(f, " --sanitizer=none")?,
            Sanitizer::Address => {}
            _ => write!(f, " --sanitizer={}", self.sanitizer)?,
        }

        if self.triple != crate::utils::default_target() {
            write!(f, " --target={}", self.triple)?;
        }

        for flag in &self.unstable_flags {
            write!(f, " -Z{}", flag)?;
        }

        if let Some(target_dir) = &self.target_dir {
            write!(f, " --target-dir={}", target_dir)?;
        }

        if self.coverage {
            write!(f, " --coverage")?;
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Parser, PartialEq, Eq)]
pub struct FuzzDirWrapper {
    /// The path to the fuzz project directory.
    #[clap(long = "fuzz-dir")]
    pub fuzz_dir: Option<PathBuf>,
}

impl stdfmt::Display for FuzzDirWrapper {
    fn fmt(&self, f: &mut stdfmt::Formatter) -> stdfmt::Result {
        if let Some(ref elem) = self.fuzz_dir {
            write!(f, " --fuzz-dir={}", elem.display())?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn display_build_options() {
        let default_opts = BuildOptions {
            dev: false,
            release: false,
            debug_assertions: false,
            verbose: false,
            no_default_features: false,
            all_features: false,
            features: None,
            build_std: false,
            careful_mode: false,
            sanitizer: Sanitizer::Address,
            triple: String::from(crate::utils::default_target()),
            unstable_flags: Vec::new(),
            target_dir: None,
            coverage: false,
            strip_dead_code: false,
            no_cfg_fuzzing: false,
            no_trace_compares: false,
        };

        let opts = vec![
            default_opts.clone(),
            BuildOptions {
                dev: true,
                ..default_opts.clone()
            },
            BuildOptions {
                release: true,
                ..default_opts.clone()
            },
            BuildOptions {
                debug_assertions: true,
                ..default_opts.clone()
            },
            BuildOptions {
                verbose: true,
                ..default_opts.clone()
            },
            BuildOptions {
                no_default_features: true,
                ..default_opts.clone()
            },
            BuildOptions {
                all_features: true,
                ..default_opts.clone()
            },
            BuildOptions {
                features: Some(String::from("features")),
                ..default_opts.clone()
            },
            BuildOptions {
                sanitizer: Sanitizer::None,
                ..default_opts.clone()
            },
            BuildOptions {
                triple: String::from("custom_triple"),
                ..default_opts.clone()
            },
            BuildOptions {
                unstable_flags: vec![String::from("unstable"), String::from("flags")],
                ..default_opts.clone()
            },
            BuildOptions {
                target_dir: Some(String::from("/tmp/test")),
                ..default_opts.clone()
            },
            BuildOptions {
                coverage: false,
                ..default_opts
            },
        ];

        for case in opts {
            assert_eq!(
                case,
                BuildOptions::from_clap(
                    &BuildOptions::clap().get_matches_from(case.to_string().split(' '))
                )
            );
        }
    }
}
