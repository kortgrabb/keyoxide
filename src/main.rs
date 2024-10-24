use std::env;

use manager::Manager;

mod crypto;
mod manager;
mod ui;

fn main() {
    let mut manager = Manager::new();
    manager.init_or_load();

    let args: Vec<String> = env::args().skip(1).collect();
    if args.is_empty() {
        println!("Usage: password_manager [add|get|show] [name]");
        return;
    }

    let command = &args[0];
    match command.as_str() {
        "add" => {
            if args.len() != 2 {
                println!("Usage: password_manager add [name]");
                return;
            }
            let name = &args[1];
            let password = ui::prompt_password();
            manager.add_entry(name, &password);
            manager.save_entry(name).unwrap();
        }
        "get" => {
            if args.len() != 2 {
                println!("Usage: password_manager get [name]");
                return;
            }
            let name = &args[1];
            let entry = manager.get_entry(name).unwrap();
            println!("Password for {}: {}", name, entry.password);
        }
        "show" => {
            if args.len() != 1 {
                println!("Usage: password_manager show");
                return;
            }
            manager.list_entry_tree();
        }
        _ => {
            println!("Unknown command: {}", command);
            println!("Usage: password_manager [add|get|show] [name]");
        }
    }
}