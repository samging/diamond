# Obsidian

A secure, REPL based password manager built in Rust with military-grade encryption.

## Features

- **AES-256-GCM encryption** for password storage
- **Argon2** key derivation for master key and action password
- **Password strength validation** using zxcvbn
- **Built-in password generator** (16-character alphanumeric)
- **Unix file permissions** (0600) for secure storage
- **External file support** for multiple vaults
- **Interactive REPL interface** with rustyline

## Security

Obsidian uses industry-standard cryptography:

- **Encryption**: AES-256-GCM with random nonce per entry
- **Key Derivation**: Argon2 with random 16-byte salt
- **Memory Safety**: Zeroizing for sensitive data in memory
- **File Permissions**: Unix 0600 (owner read/write only)

All passwords are encrypted before storage. The master key never touches disk in plaintext.

## Installation

```bash
git clone https://github.com/mohammed-dev23/obsidian.git
cd obsidian
cargo run
```

The binary will be in `/obsidian`.

## Usage

Launch the REPL:

```bash
./obsidian or cargo run
```

### Commands

#### Add a password
```
add <username/email> <password> <id> <master-key> <action-key>
```

Example:
```
add user@example.com MyP@ssw0rd github MyMasterKey123456 MyActionPass123
```

#### Get a password
```
get <id> <master-key> <action-key>
```

Example:
```
get github MyMasterKey123456 MyActionPass123
```

#### List all entries
```
list <action-key>
```

#### Search for an entry
```
search <id> <action-key>
```

#### Change an entry
```
change <id> <username/email> <new-password> <master-key> <action-key>
```

#### Remove an entry
```
remove <id> <action-key>
```

#### Generate a password
```
gp
```

#### Help
```
help -l                    # List all commands
help --<command>           # Detailed help for a command
```

#### Exit
```
exit
```

#### Clear terminal
```
clear
```

### External Vaults

Use external files for separate password vaults:

```
external <path/file> <command> [arguments...]
```

Example:
```
external work.json add user@work.com P@ss123 slack MyKey123456 MyAction123
external work.json get slack MyKey123456 MyAction123
external work.json list MyAction123
```

## Password Requirements

- **Master Key**: Minimum 16 characters, must pass strength validation
- **Action Password**: Must pass strength validation
- **Regular Passwords**: Strength validated against username/email context

Passwords are rated as: Very Weak, Weak, Fair, Good, or Strong. Obsidian rejects Very Weak and Weak passwords.

## File Storage

Default location: `~/obsidian/`

- `obs.json` - Encrypted password database
- `obs_password.txt` - Hashed action password

External vaults are stored at the specified path relative to `~`.

Each entry stores:
- `id`: URL/app identifier
- `data`: Base64-encoded encrypted blob containing username/email and password

## Building from Source

### Dependencies

```toml
aes-gcm = "0.10"
argon2 = "0.5"
anyhow = "1.0"
base64 = "0.22"
colored = "2.1"
rand = "0.8"
rustyline = "14.0"
serde = { version = "1.0", features = ["derive"] }
serde_json = "1.0"
zeroize = "1.8"
zxcvbn = "3.1"
```

### Build

```bash
cargo build --release
```

### Run tests

```bash
cargo test
```

## Security Considerations

⚠️ **Important**:

- Never share your master key or action password
- The action password protects against unauthorized REPL commands
- The master key encrypts/decrypts your passwords
- Both are required and independently validated
- Loss of either password means permanent data loss (no recovery mechanism)
- Store vault backups securely

## Platform Support

- **Linux/Unix**: Full support with file permissions
- **macOS**: Full support with file permissions  
- **Windows**: Core functionality (no Unix permissions)

## Disclaimer

This software is provided as-is. Always maintain backups of your password vault. The authors are not responsible for data loss or security breaches.