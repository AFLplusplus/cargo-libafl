use crate::{
    options::{BuildOptions, FuzzDirWrapper},
    project::FuzzProject,
    RunCommand,
};
use anyhow::Result;
use clap::{self, Parser};

#[derive(Clone, Debug, Parser)]
pub struct Run {
    #[clap(flatten)]
    pub build: BuildOptions,

    /// Name of the fuzz target
    pub target: String,

    /// Custom corpus directories or artifact files.
    pub corpus: Vec<String>,

    #[clap(flatten)]
    pub fuzz_dir_wrapper: FuzzDirWrapper,

    #[clap(last(true))]
    /// Additional libFuzzer arguments passed through to the binary
    pub args: Vec<String>,
}

impl RunCommand for Run {
    fn run_command(&mut self) -> Result<()> {
        let project = FuzzProject::new(self.fuzz_dir_wrapper.fuzz_dir.clone())?;
        project.exec_fuzz(self)
    }
}
