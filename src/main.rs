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

fn main() -> Result<(), PasswordManagerError> {
    let mut manager = EntryManager::new();
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
        "show" => handle_show(&args, &manager),
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
    println!("\nCommands:");
    println!("  add [name] [--gen] - Add a new password entry");
    println!("    --gen: Generate a random password");
    println!("  get [name] - Get a password entry");
    println!("  show - Show all password entries");
    println!("  remove [name] - Remove a password entry");
    println!("  edit [name] - Edit a password entry (shortcut for remove and add)");
}

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

fn handle_add(args: &[String], manager: &mut EntryManager) -> Result<(), PasswordManagerError> {
    let name = &args[1];
    let options = extract_flags_and_values(args);

    if options.contains_key("gen") {
        let mut gen = PasswordGenerator::with_default();
        if options.contains_key("length") {
            let length = options.get("length").unwrap().parse().unwrap();
            gen = gen.with_length(length);
        }

        let password = gen.generate();
        manager.add_entry(name, &password)?;

        println!("Generated password for {}: {}", name, password);
    } else {
        let password = ui::prompt_password();
        manager.add_entry(name, &password)?;

        println!("Added password for {}", name);
    }

    manager.save_entry(name)?;

    Ok(())
}

fn handle_remove(args: &[String], manager: &mut EntryManager) -> Result<(), PasswordManagerError> {
    let name = &args[1];
    manager.remove_entry(name)?;

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

fn handle_show(args: &[String], manager: &EntryManager) -> Result<(), PasswordManagerError> {
    if args.len() != 1 {
        println!("Usage: password_manager show");
        return Ok(());
    }

    manager.list_entry_tree()
}

fn handle_edit(args: &[String], manager: &mut EntryManager) -> Result<(), PasswordManagerError> {
    let name = &args[1];

    let entry = match manager.get_entry(name) {
        Ok(entry) => entry,
        Err(e) => {
            println!("Error retrieving entry: {}", e);
            return Ok(());
        }
    };

    let new_password = ui::prompt_on_same_line("Enter new password: ");
    manager.edit_entry_password(&entry.name, &new_password)?;

    Ok(())
}
