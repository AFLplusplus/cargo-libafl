use crate::{
    options::{BuildOptions, FuzzDirWrapper},
    project::FuzzProject,
    RunCommand,
};
use anyhow::Result;
use structopt::StructOpt;

use std::path::PathBuf;

#[derive(Clone, Debug, StructOpt)]
pub struct Fmt {
    #[structopt(flatten)]
    pub build: BuildOptions,

    #[structopt(flatten)]
    pub fuzz_dir_wrapper: FuzzDirWrapper,

    /// Name of fuzz target
    pub target: String,

    /// Path to the input testcase to debug print
    pub input: PathBuf,
}

impl RunCommand for Fmt {
    fn run_command(&mut self) -> Result<()> {
        let project = FuzzProject::new(self.fuzz_dir_wrapper.fuzz_dir.clone())?;
        project.debug_fmt_input(self)
    }
}
