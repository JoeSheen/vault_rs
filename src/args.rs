use chrono::Local;
use clap::{Parser, Subcommand};
use comfy_table::{Cell, Table};

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
            match vault::get_entry(&master, &site) {
                Ok(entry) => {
                    let mut table: Table = Table::new();
                    table
                        .set_header(vec!["ID", "Site", "Username", "Password", "Created At"])
                        .add_row(vec![
                            Cell::new(entry.id),
                            Cell::new(entry.site),
                            Cell::new(entry.username),
                            Cell::new(entry.password),
                            Cell::new(
                                entry
                                    .created_at
                                    .with_timezone(&Local)
                                    .format("%Y-%m-%d %H:%M:%S"),
                            ),
                        ]);
                    println!("{}", table);
                }
                Err(e) => {
                    println!("No entry found for site: {}", site);
                    println!("error: {}", e);
                }
            }
        }
        Commands::List => {
            let master: String = rpassword::prompt_password(PROMPT).unwrap();
            let entries: Vec<Entry> = vault::list_entries(&master)?;
            if entries.is_empty() {
                println!("No entries found")
            } else {
                let mut table: Table = Table::new();
                table.set_header(vec!["ID", "Site", "Username", "Password", "Created At"]);
                for entry in entries {
                    table.add_row(vec![
                        Cell::new(entry.id),
                        Cell::new(entry.site),
                        Cell::new(entry.username),
                        Cell::new(entry.password),
                        Cell::new(
                            entry
                                .created_at
                                .with_timezone(&Local)
                                .format("%Y-%m-%d %H:%M:%S"),
                        ),
                    ]);
                }
                println!("{}", table);
            }
        }
        Commands::Delete { site } => {
            let master: String = rpassword::prompt_password(PROMPT).unwrap();
            vault::delete_entry(&master, &site)?;
            println!("Entry deleted: {}", site);
        }
        Commands::ChangePassword { new_password } => {
            let old_password: String = rpassword::prompt_password(PROMPT).unwrap();
            vault::change_master_password(&old_password, &new_password)?;
            println!("Master password changed")
        }
    }

    Ok(())
}
