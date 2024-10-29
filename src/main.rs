use std::{collections::HashMap, env};

pub mod crypto;
pub mod entry;
pub mod error;
pub mod gen;
pub mod storage;
pub mod ui;

use entry::EntryManager;
use error::PasswordManagerError;
use gen::PasswordGenerator;

const PASSWORD_MANAGER_PATH: &str = ".password_manager";

fn main() -> Result<(), PasswordManagerError> {
    let mut manager = EntryManager::new(PASSWORD_MANAGER_PATH);
    manager.init_or_load()?;

    run(manager)
}

fn run(mut manager: EntryManager) -> Result<(), PasswordManagerError> {
    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        return Ok(());
    }

    match args[0].as_str() {
        "add" => handle_add(&args, &mut manager),
        "get" => handle_get(&args, &manager),
        "list" | "getall" => handle_list(&args, &manager),
        "remove" | "delete" => handle_remove(&args, &mut manager),
        "edit" => handle_edit(&args, &mut manager),
        "help" => {
            print_usage();
            Ok(())
        }
        _ => {
            println!("Unknown command: {}", args[0]);
            print_usage();
            Ok(())
        }
    }
}

fn print_usage() {
    println!("Usage: password_manager [add|get|show] [name]");
    println!("\nAvailable Commands:");
    println!("  add [name] [--gen] - Add a new password entry");
    println!("    --gen: Generate a random password");
    println!("  get [name] - Get a password entry");
    println!("  show - Show all password entries");
    println!("  remove [name] - Remove a password entry");
    println!("  edit [name] - Edit a password entry (shortcut for remove and add)");
}

// helper function to check if an entry exists
fn does_entry_exist(manager: &EntryManager, name: &str) -> bool {
    let entry = manager.get_entry(name);
    entry.is_ok()
}

// TODO: Add support for short flags
fn extract_flags_and_values(args: &[String]) -> HashMap<String, String> {
    let mut options = HashMap::new();
    let provided_flags = args.iter().filter(|arg| arg.starts_with("--"));
    for flag in provided_flags {
        // remove the "--" prefix and split the flag and value
        let parts: Vec<&str> = flag.trim_start_matches("--").split('=').collect();
        if parts.len() == 2 {
            options.insert(parts[0].to_string(), parts[1].to_string());
        } else {
            options.insert(parts[0].to_string(), String::new());
        }
    }

    options
}

// Helper function to generate a password based on the provided options
fn generate_password(options: &HashMap<String, String>) -> String {
    let length = options
        .get("length")
        .and_then(|l| l.parse().ok())
        .unwrap_or(16);
    let exclude = options.get("exclude").unwrap_or(&String::new()).to_string();

    let gen = PasswordGenerator::with_default()
        .with_length(length)
        .exclude_chars(&exclude);

    gen.generate()
}

// Top-level function to handle adding a new password entry
fn handle_add(args: &[String], manager: &mut EntryManager) -> Result<(), PasswordManagerError> {
    let name = &args[1];
    if does_entry_exist(manager, name) {
        println!("Entry for {} already exists", name);
        if ui::prompt_confirm("Do you want to overwrite the existing entry?") {
            manager.remove_entry(name)?;
        } else {
            println!("Cancelled adding password for {}", name);
            return Ok(());
        }
    }

    let options = extract_flags_and_values(args);

    if options.contains_key("gen") {
        let password = generate_password(&options);

        manager.add_entry(name, &password)?;
        println!("Generated password for {}: {}", name, password);
    } else {
        let password = ui::prompt_password();
        manager.add_entry(name, &password)?;

        println!("Added password {} for {}", password, name);
    }

    Ok(())
}

fn handle_remove(args: &[String], manager: &mut EntryManager) -> Result<(), PasswordManagerError> {
    let name = &args[1];

    if let Ok(entry) = manager.get_entry(name) {
        let entry_path_name = manager
            .get_entry_path_name(&entry)
            .unwrap_or(name.to_string());

        if ui::prompt_confirm(&format!(
            "Do you want to remove the entry for {}?",
            entry_path_name
        )) {
            manager.remove_entry(name)?;
            println!("Removed password for {}", entry_path_name);
        } else {
            println!("Cancelled removing password for {}", entry_path_name);
        }
    }

    Ok(())
}

fn handle_get(args: &[String], manager: &EntryManager) -> Result<(), PasswordManagerError> {
    if args.len() != 2 {
        println!("Usage: password_manager get [name]");
        return Ok(());
    }

    let name = &args[1];
    match manager.get_entry(name) {
        Ok(entry) => {
            let entry_path_name = manager
                .get_entry_path_name(&entry)
                .unwrap_or(name.to_string());
            println!("Password for {}: {}", entry_path_name, entry.password);
            Ok(())
        }
        Err(e) => {
            println!("Error retrieving entry: {}", e);
            Ok(())
        }
    }
}

fn handle_list(args: &[String], manager: &EntryManager) -> Result<(), PasswordManagerError> {
    if args.len() != 1 {
        println!("Usage: password_manager show");
        return Ok(());
    }

    manager.list_entry_tree()
}

fn handle_edit(args: &[String], manager: &mut EntryManager) -> Result<(), PasswordManagerError> {
    let name = &args[1];

    match manager.get_entry(name) {
        Ok(entry) => entry,
        Err(_) => {
            println!("no entry found for name: {}", name);
            return Ok(());
        }
    };

    let new_password = ui::prompt_password();
    if ui::prompt_confirm("Do you want to overwrite the existing password?") {
        manager.add_entry(name, &new_password)?;
        println!("Updated password for {}", name);
    } else {
        println!("Cancelled updating password for {}", name);
    }

    Ok(())
}

