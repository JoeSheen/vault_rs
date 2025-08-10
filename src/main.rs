use vault_rs::args::execute_command;

fn main() {
    if let Err(e) = execute_command() {
        eprintln!("Error: {}", e);
        std::process::exit(1);
    }
}
