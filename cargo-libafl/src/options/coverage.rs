use crate::{
    options::{BuildOptions, FuzzDirWrapper},
    project::FuzzProject,
    RunCommand,
};
use anyhow::Result;
use clap::{self, Parser};

#[derive(Clone, Debug, Parser)]
pub struct Coverage {
    #[clap(flatten)]
    pub build: BuildOptions,

    #[clap(flatten)]
    pub fuzz_dir_wrapper: FuzzDirWrapper,

    /// Name of the fuzz target
    pub target: String,

    /// Custom corpus directories or artifact files
    pub corpus: Vec<String>,

    #[clap(last(true))]
    /// Additional libFuzzer arguments passed through to the binary
    pub args: Vec<String>,
}

impl RunCommand for Coverage {
    fn run_command(&mut self) -> Result<()> {
        let project = FuzzProject::new(self.fuzz_dir_wrapper.fuzz_dir.clone())?;
        self.build.coverage = true;
        project.exec_coverage(self)
    }
}
