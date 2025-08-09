use clap::{Parser, Subcommand};

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    Init,
    Add,
    Get { site: String },
    List,
    Delete { site: String },
    ChangePassword,
}

#[derive(Parser)]
#[command(name = "vault")]
#[command(version, about = "A CLI password manager", long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub cmd: Commands,
}
