//! Thin command-line entry point for evidence validation and diagnosis.

mod cli;

use std::{io, process::ExitCode};

fn main() -> ExitCode {
    match cli::run(std::env::args_os().skip(1), &mut io::stdout().lock()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::FAILURE
        }
    }
}
