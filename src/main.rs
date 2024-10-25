use std::env;

pub mod crypto;
pub mod entry;
pub mod error;
pub mod storage;
pub mod ui;
pub mod gen;

use entry::EntryManager;
use error::PasswordManagerError;


fn main() -> Result<(), PasswordManagerError> {
    let mut manager = EntryManager::new();
    manager.init_or_load()?;

    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        print_usage();
        return Ok(());
    }

    match args[0].as_str() {
        "add" => handle_add(&args, &mut manager),
        "get" => handle_get(&args, &manager),
        "show" => handle_show(&args, &manager),
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
    println!("  add [name]    Add a new password entry");
    println!("  get [name]    Retrieve a password entry");
    println!("  show          Display all entries in a tree structure");
}

fn handle_add(args: &[String], manager: &mut EntryManager) -> Result<(), PasswordManagerError> {
    if args.len() != 2 {
        println!("Usage: password_manager add [name]");
        return Ok(());
    }

    let name = &args[1];
    let password = ui::prompt_password();
    
    manager.add_entry(name, &password)?;
    manager.save_entry(name)?;
    
    println!("Successfully added entry '{}'", name);
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
            println!("Password for {}: {}", name, entry.password);
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

    println!("Password entries:");
    manager.list_entry_tree()
}