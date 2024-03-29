use crate::{
    options::{BuildOptions, FuzzDirWrapper},
    project::FuzzProject,
    RunCommand,
};
use anyhow::Result;
use clap::{self, Parser};

#[derive(Clone, Debug, Parser)]
pub struct Build {
    #[clap(flatten)]
    pub build: BuildOptions,

    #[clap(flatten)]
    pub fuzz_dir_wrapper: FuzzDirWrapper,

    /// Name of the fuzz target to build, or build all targets if not supplied
    pub target: Option<String>,
}

impl RunCommand for Build {
    fn run_command(&mut self) -> Result<()> {
        let project = FuzzProject::new(self.fuzz_dir_wrapper.fuzz_dir.clone())?;
        project.exec_build(&self.build, self.target.as_deref())
    }
}
