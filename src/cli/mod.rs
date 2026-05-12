pub mod decode;
pub mod encode;
pub mod version;
pub mod zero;

use clap::{Parser, Subcommand};
use std::{ffi::OsString, fmt::Debug};

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
    /// Suppress stderr log and warning output
    #[arg(long, short = 'q', global = true)]
    quiet: bool,
}

#[derive(Subcommand, Debug, Clone)]
enum Cmd {
    /// Decode strkey
    ///
    /// Reads the strkey from stdin.
    Decode(decode::Cmd),
    /// Encode strkey
    ///
    /// Reads the JSON from stdin.
    Encode(encode::Cmd),
    /// Generate the zero strkey
    Zero(zero::Cmd),
    /// Print version information
    Version,
}

/// Runtime options sourced from global flags on [`Root`] and threaded to each
/// subcommand's `run`.
#[derive(Default)]
pub struct RunOpts {
    pub quiet: bool,
}

impl Root {
    /// Run the CLIs root command.
    ///
    /// ## Errors
    ///
    /// If the root command is configured with state that is invalid.
    pub fn run(&self) -> Result<(), Error> {
        let opts = RunOpts { quiet: self.quiet };
        match &self.cmd {
            Cmd::Decode(c) => c.run(&opts)?,
            Cmd::Encode(c) => c.run(&opts)?,
            Cmd::Zero(c) => c.run(),
            Cmd::Version => version::Cmd::run(),
        }
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error(transparent)]
    Clap(#[from] clap::Error),
    #[error(transparent)]
    Decode(#[from] decode::Error),
    #[error(transparent)]
    Encode(#[from] encode::Error),
}

/// Run the CLI with the given args.
///
/// ## Errors
///
/// If the input cannot be parsed.
pub fn run<I, T>(args: I) -> Result<(), Error>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString> + Clone,
{
    let root = Root::try_parse_from(args)?;
    root.run()
}

/// Emit a stderr warning that the output bound for stdout contains secret
/// material. Called from CLI paths that handle private-key strkeys.
pub(crate) fn warn_private_key() {
    eprintln!("⚠️  Warning: output contains a private key with secret material. Handle with care.");
}
