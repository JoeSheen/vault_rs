# vault_rs

A command-line interface (CLI) password manager written in Rust that securely stores, retrieves, and manages user credentials using an encrypted local sqlite database.

## Commands

| Command           | Description                                                          |
| :---------------- | :------------------------------------------------------------------- |
| `init`            | Initialise a new vault and sets a master password                    |
| `add`             | Add a new credential (id, username, password, etc.)                  |
| `get`             | Retrieve a stored credential entry                                   |
| `list`            | List all stored credentials entries                                  |
| `delete`          | Removes a credential entry from the vault                            |
| `change-password` | Change the master password - this drops all saved credential entries |

## Roadmap / TODO

- [/] Improve error types and handling.
- [] Refactor code to be more concise and idiomatic
- [] Improve project file structure
- [] Add more commands (maybe the following):
  - Add export to CSV
  - Add fuzzy search support

## Build & Run

Make sure you have **Rust** installed ([install via rustup](https://rustup.rs)).

```bash
# Clone the repository
git clone https://github.com/JoeSheen/vault_rs.git
cd vault_rs

# Build the project
cargo build --release

# Run it
./target/release/vault_rs
```
