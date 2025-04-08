use clap::Error;
use std::env;
use stellar_strkey::cli;

fn main() {
    if let Err(e) = cli::run(env::args_os()) {
        Error::raw(clap::error::ErrorKind::ValueValidation, e).exit()
    }
}
