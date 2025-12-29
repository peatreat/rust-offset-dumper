# Rust Offset Dumper

A build-time utility that automatically extracts the latest offsets and decryption functions for Rust game entities.

## Features

- 🔄 **Automatic Offset Extraction** - Dumps offsets on every build
- 🔐 **Decryption Functions** - Generates entity decryption functions
- 📦 **Easy Integration** - Use as a dependency in your project

## Supported Offsets

- `IL2CPP_HANDLE_TABLE_OFFSET` - IL2CPP runtime handle table
- `LIST_COMPONENT_BUFFER_OFFSET` - List component buffer offset
- `MAIN_CAMERA_C_OFFSET` - MainCamera class pointer
- `MAIN_CAMERA_C_CAMERA_OFFSET` - MainCamera camera offset
- `BASE_NETWORKABLE_C_OFFSET` - BaseNetworkable class pointer
- `BASE_NETWORKABLE_C_STATIC_FIELDS` - Static fields offset
- `BASE_NETWORKABLE_C_CLIENT_ENTS_OFFSET` - Client entities list offset
- `CLIENT_ENTS_ENT_REALM_OFFSET` - Entity realm offset
- `LOCAL_PLAYER_C_OFFSET` - LocalPlayer class pointer
- `LOCAL_PLAYER_C_STATIC_FIELDS` - Static fields offset
- `LOCAL_PLAYER_C_BASE_PLAYER_OFFSET` - BasePlayer offset
- `decrypt_client_entities()` - Decryption function for client entities
- `decrypt_entity_list()` - Decryption function for entity lists
- `decrypt_base_player()` - Decryption function for base player

## Setup

### Prerequisites

- Rust toolchain
- `GameAssembly.dll` from the Rust game files

### Installation

1. Add this crate as a dependency to your `Cargo.toml`:

```toml
[dependencies]
rust-offset-dumper = { git = "https://github.com/peatreat/rust-offset-dumper.git" }
```

2. Set the `RUST_GAME_ASSEMBLY_PATH` environment variable before building:

**Windows (PowerShell):**
```powershell
$env:RUST_GAME_ASSEMBLY_PATH = "C:\path\to\GameAssembly.dll"
cargo build
```

**Windows (Command Prompt):**
```cmd
set RUST_GAME_ASSEMBLY_PATH=C:\path\to\GameAssembly.dll
cargo build
```

**Linux/macOS:**
```bash
export RUST_GAME_ASSEMBLY_PATH="/path/to/GameAssembly.dll"
cargo build
```

## Usage

Once built, access the generated offsets in your code:

```rust
use rust_offset_dumper::*;

fn main() {
    println!("IL2CPP Handle Table: 0x{:x}", IL2CPP_HANDLE_TABLE_OFFSET);
    println!("BaseNetworkable Offset: 0x{:x}", BASE_NETWORKABLE_C_OFFSET);
    
    // Use decryption functions
    let decrypted = decrypt_client_entities(encrypted_value);
}
```

## How It Works

The `build.rs` script:

1. Reads `GameAssembly.dll` from the path specified in `RUST_GAME_ASSEMBLY_PATH`
2. Performs binary pattern scanning to locate offset addresses and decryption functions
3. Extracts instruction sequences from the game assembly's decryption routines
4. Generates `src/offsets.rs` with all discovered offsets and reconstructed decryption functions
5. Compiles the generated code into your binary at build time

Offsets are always current with your provided `GameAssembly.dll` version, so simply rebuild with an updated DLL file when the game updates.

## Requirements

- `RUST_GAME_ASSEMBLY_PATH` environment variable must be set during compilation
- The `GameAssembly.dll` file must be valid and from a compatible Rust game version
