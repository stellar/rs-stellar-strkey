use clap::Error;
use std::env;
use stellar_strkey::cli;

fn main() {
    if let Err(e) = cli::run(env::args_os()) {
        match e {
            cli::Error::Clap(e) => e.exit(),
            cli::Error::Decode(_) | cli::Error::Encode(_) => {
                Error::raw(clap::error::ErrorKind::ValueValidation, e).exit()
            }
        }
    }
}
