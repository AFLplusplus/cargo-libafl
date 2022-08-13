use anyhow::Result;
use clap::{self, Parser};

#[macro_use]
mod templates;
mod common;
mod options;
mod project;
mod utils;

static FUZZ_TARGETS_DIR_OLD: &str = "fuzzers";
static FUZZ_TARGETS_DIR: &str = "fuzz_targets";

/// A trait for running our various commands.
trait RunCommand {
    /// Run this command!
    fn run_command(&mut self) -> Result<()>;
}

#[derive(Clone, Debug, Parser)]
#[clap(
    setting(clap::AppSettings::SubcommandRequiredElseHelp),
    setting(clap::AppSettings::GlobalVersion),
    version(option_env!("CARGO_PKG_VERSION").unwrap_or("0.0.0")),
    about(option_env!("CARGO_PKG_DESCRIPTION").unwrap_or("")),
    // Cargo passes in the subcommand name to the invoked executable. Use a
    // hidden, optional positional argument to deal with it.
    arg(clap::Arg::with_name("dummy")
        .possible_value("libafl")
        .required(false)
        .hidden(true)),
)]
enum Command {
    /// Initialize the fuzz directory
    Init(options::Init),

    /// Add a new fuzz target
    Add(options::Add),

    /// Build fuzz targets
    Build(options::Build),

    /// Print the `std::fmt::Debug` output for an input
    Fmt(options::Fmt),

    /// List all the existing fuzz targets
    List(options::List),

    /// Run a fuzz target
    Run(options::Run),

    /// Run program on the generated corpus and generate coverage information
    Coverage(options::Coverage),
}

impl RunCommand for Command {
    fn run_command(&mut self) -> Result<()> {
        match self {
            Command::Init(x) => x.run_command(),
            Command::Add(x) => x.run_command(),
            Command::Build(x) => x.run_command(),
            Command::List(x) => x.run_command(),
            Command::Fmt(x) => x.run_command(),
            Command::Run(x) => x.run_command(),
            Command::Coverage(x) => x.run_command(),
        }
    }
}

fn main() -> Result<()> {
    Command::from_args().run_command()
}
