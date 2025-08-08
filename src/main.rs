use vault_rs::models::Entry;

fn main() {
    let entry: Entry = Entry::new("example.com", "user", "encrypted");
    println!("{:?}", entry);
    println!("Hello, world!");
}
