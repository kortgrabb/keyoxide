use std::io;

pub fn prompt_master_password() -> String {
    println!("Enter your master password:");
    let mut master_password = String::new();
    io::stdin().read_line(&mut master_password).unwrap();

    master_password.trim().to_string()
}

pub fn prompt_password() -> String {
    println!("Enter your password:");
    let mut password = String::new();
    io::stdin().read_line(&mut password).unwrap();

    password.trim().to_string()
}