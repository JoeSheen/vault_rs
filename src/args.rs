use clap::{Parser, Subcommand};

use crate::{models::Entry, vault};

const PROMPT: &str = "Master Password: ";

#[derive(Subcommand, Debug, Clone)]
pub enum Commands {
    // initialises the vault
    Init {
        #[arg(short = 'm', long = "master-password")]
        master_password: String,
    },
    // Adds new password entry
    Add {
        #[arg(short = 's', long = "site")]
        site: String,
        #[arg(short = 'u', long = "username")]
        username: String,
        #[arg(short = 'p', long = "password")]
        password: String,
    },
    // Retrieves a password for a site from the vault
    Get {
        #[arg(short = 's', long = "site")]
        site: String,
    },
    // Lists all stored site entries
    List,
    // Deletes a site entry
    Delete {
        #[arg(short = 's', long = "site")]
        site: String,
    },
    // Changes the master password
    ChangePassword {
        #[arg(short = 'o', long = "old-password")]
        old_password: String,
        #[arg(short = 'n', long = "new-password")]
        new_password: String,
    },
}

#[derive(Parser)]
#[command(name = "vault")]
#[command(version, about = "A CLI password manager", long_about = None)]
pub struct Args {
    #[command(subcommand)]
    pub cmd: Commands,
}

pub fn execute_command() -> Result<(), String> {
    let args: Args = Args::parse();

    match args.cmd {
        Commands::Init { master_password } => {
            vault::init_vault(&master_password)?;
            println!("Vault initialised");
        }
        Commands::Add {
            site,
            username,
            password,
        } => {
            let master: String = rpassword::prompt_password(PROMPT).unwrap();
            vault::add_entry(&master, Entry::new(site, username, password))?;
            println!("Entry added to vault");
        }
        Commands::Get { site } => {
            let master: String = rpassword::prompt_password(PROMPT).unwrap();
            if let Some(entry) = vault::get_entry(&master, &site)? {
                println!(
                    "site: {}, username: {}, password: {}",
                    entry.site, entry.username, entry.password
                );
            } else {
                println!("No entry found for site: {}", site);
            }
        }
        Commands::List => {}
        Commands::Delete { site } => {}
        Commands::ChangePassword {
            old_password,
            new_password,
        } => {}
    }

    Ok(())
}
