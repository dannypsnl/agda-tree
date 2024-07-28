use clap::Parser;
use std::io;
use std::path::PathBuf;

use agda_tree::cli::{Cli, Commands};
use agda_tree::command;

fn main() -> io::Result<()> {
    let cli = Cli::parse();

    // You can check the value provided by positional arguments, or option arguments
    if let Some(name) = cli.name.as_deref() {
        println!("Value for name: {name}");
    }

    if let Some(config_path) = cli.config.as_deref() {
        println!("Value for config: {}", config_path.display());
    }

    match &cli.command {
        Some(Commands::Build {
            directory,
            output_dir,
            skip_agda,
        }) => {
            let working_dir = match directory {
                Some(path) => path,
                None => &PathBuf::new().join("."),
            };
            let output_dir = match output_dir {
                Some(v) => v,
                None => &PathBuf::new().join("."),
            };
            command::build::execute(working_dir, output_dir, *skip_agda)
        }
        None => Ok(()),
    }
}
