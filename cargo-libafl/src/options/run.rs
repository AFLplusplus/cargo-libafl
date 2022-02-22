use crate::{
    options::{BuildOptions, FuzzDirWrapper},
    project::FuzzProject,
    RunCommand,
};
use anyhow::Result;
use structopt::StructOpt;

#[derive(Clone, Debug, StructOpt)]
pub struct Run {
    #[structopt(flatten)]
    pub build: BuildOptions,

    /// Name of the fuzz target
    pub target: String,

    /// Custom corpus directories or artifact files.
    pub corpus: Vec<String>,

    #[structopt(flatten)]
    pub fuzz_dir_wrapper: FuzzDirWrapper,

    #[structopt(last(true))]
    /// Additional libFuzzer arguments passed through to the binary
    pub args: Vec<String>,
}

impl RunCommand for Run {
    fn run_command(&mut self) -> Result<()> {
        let project = FuzzProject::new(self.fuzz_dir_wrapper.fuzz_dir.to_owned())?;
        project.exec_fuzz(self)
    }
}
