//! Entry point for the `abb` binary. All logic lives in the library so that it
//! can be tested without spawning a process.

#![forbid(unsafe_code)]

use std::io::{stderr, stdout, Write};

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let mut out = stdout().lock();
    let mut err = stderr().lock();
    let code = abb_cli::run(&args, &mut out, &mut err);
    let _ = out.flush();
    let _ = err.flush();
    std::process::exit(code);
}
