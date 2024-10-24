use std::env;

use manager::Manager;

mod crypto;
mod manager;
mod utils;

fn main() {
    let mut manager = Manager::new();
    manager.init_or_load();

    let args: Vec<String> = env::args().skip(1).collect();
    match args.as_slice() {
        [command, name] if command == "add" => {
            let password = utils::prompt_password();
            manager.add_entry(name, &password);
            manager.save_entries();
        }
        [command, name] if command == "get" => {
            let entry = manager.get_entry(name).unwrap();

            println!("Password for {}: {}", name, entry.password);
        }
        [command] if command == "show" => {
            manager.list_entry_tree();
        }
        _ => {
            println!("Usage: password_manager [add|get] [name]");
        }
    }
}
