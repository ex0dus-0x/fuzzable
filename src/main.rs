mod backends;
mod errors;

use clap::{Arg, ArgMatches, Command};
use goblin::Object;
use walkdir::WalkDir;

use std::fs;
use std::path::{Path, PathBuf};

use fuzzable::backends::{FuzzableBinja, FuzzableSource};
use fuzzable::errors::{FuzzError, FuzzResult};

fn main() {
    pretty_env_logger::init();
    let cli_args: ArgMatches = parse_args();
    match run(cli_args) {
        Ok(_) => {}
        Err(e) => {
            log::error!("{}", e);
        }
    }
}

fn parse_args() -> ArgMatches {
    Command::new(env!("CARGO_PKG_NAME"))
        .version(env!("CARGO_PKG_VERSION"))
        .author(env!("CARGO_PKG_AUTHORS"))
        .about(env!("CARGO_PKG_DESCRIPTION"))
        .arg_required_else_help(true)
        .arg(
            Arg::new("TARGET")
                .help("Path to a binary or workspace of C/C++ source code.")
                .takes_value(true)
                .required(true),
        )
        .arg(
            Arg::new("csv")
                .help("Output report to a CSV file. Use - for stdout.")
                .short('c')
                .long("csv")
                .takes_value(true)
                .required(false),
        )
        .get_matches()
}

fn run(args: ArgMatches) -> FuzzResult<()> {
    let target: &str = args.value_of("TARGET").unwrap();
    let csv: Option<&str> = args.value_of("csv");

    log::trace!("Checking if input is a valid target");
    let metadata = fs::metadata(target)?;
    if metadata.is_file() {
        let path = Path::new(target);
        let buffer = fs::read(path)?;

        // TODO: binary parser from Binja instead
        log::trace!("Initial parse with libgoblin to determine if executable");
        match Object::parse(&buffer)? {
            Object::Elf(_) | Object::PE(_) | Object::Mach(_) => {
                log::debug!("{:?} is a binary, continuing", path);
                let run = FuzzableBinja::excavate(path.to_path_buf());
            }
            _ => {
                log::trace!("Not a binary, checking if source");
                if let Some(ext) = path.extension() {
                    if ext == "c" || ext == "cpp" {
                        log::debug!("{:?} is a source path, continuing analysis", path);
                        let sources: Vec<PathBuf> = vec![path.to_path_buf()];
                        let run = FuzzableSource::excavate(sources)?;
                    }
                } else {
                    return Err(FuzzError::new(&String::from(
                        "target file is not a binary or C/C++ source code",
                    )));
                }
            }
        }

    // directories are only valid for source code
    } else if metadata.is_dir() {
        let mut source_targets: Vec<PathBuf> = vec![];

        log::trace!("Iterating over files in directory");
        for element in WalkDir::new(target).into_iter().filter_map(|e| e.ok()) {
            let path = element.path();
            if let Some(ext) = path.extension() {
                if ext == "c" || ext == "cpp" {
                    source_targets.push(path.to_path_buf());
                }
            }
        }

        log::debug!("Source paths: {:?}", source_targets);
        if source_targets.len() == 0 {
            return Err(FuzzError::new(&String::from(
                "directory specified, but no C/C++ source code found in it",
            )));
        }

        let run = FuzzableSource::excavate(source_targets)?;
    }
    Ok(())
}
