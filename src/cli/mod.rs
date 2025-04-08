pub mod decode;
pub mod encode;
pub mod version;
pub mod zero;

use clap::{Parser, Subcommand};
use std::{error::Error, ffi::OsString, fmt::Debug, boxed::Box};

#[derive(Parser, Debug, Clone)]
#[command(
    author,
    version,
    about,
    long_about = None,
    disable_help_subcommand = true,
    disable_version_flag = true,
    disable_colored_help = true,
    infer_subcommands = true,
)]
pub struct Root {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand, Debug, Clone)]
enum Cmd {
    /// Decode strkey
    Decode(decode::Cmd),
    /// Encode strkey
    Encode(encode::Cmd),
    /// Generate the zero strkey
    Zero(zero::Cmd),
    /// Print version information
    Version,
}

impl Root {
    /// Run the CLIs root command.
    ///
    /// ## Errors
    ///
    /// If the root command is configured with state that is invalid.
    pub fn run(&self) -> Result<(), Box<dyn Error>> {
        match &self.cmd {
            Cmd::Decode(c) => c.run()?,
            Cmd::Encode(c) => c.run()?,
            Cmd::Zero(c) => c.run(),
            Cmd::Version => version::Cmd::run(),
        }
        Ok(())
    }
}

/// Run the CLI with the given args.
///
/// ## Errors
///
/// If the input cannot be parsed.
pub fn run<I, T>(args: I) -> Result<(), Box<dyn Error>>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let root = Root::try_parse_from(args)?;
    root.run()
}
