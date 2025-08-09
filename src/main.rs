use clap::Parser;
use vault_rs::args::Args;

fn main() {
    let args = Args::parse();

    println!("{:?}", args.cmd);
}

/*
use vault_rs::models::Entry;

fn main() {
    let entry: Entry = Entry::new("example.com", "user", "encrypted");
    println!("{:?}", entry);
    println!("Hello, world!");
}
*/
