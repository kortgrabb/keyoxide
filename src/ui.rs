use std::io::{self, Write};

pub fn prompt_master_password(double_check: bool) -> String {
    loop {
        let password = prompt_on_same_line("Enter master password: ");
        if !double_check {
            return password;
        }

        let confirm = prompt_on_same_line("Confirm master password: ");
        if password == confirm {
            return password;
        }

        println!("Passwords do not match, please try again");
    }
}

pub fn prompt_password() -> String {
    loop {
        let password = prompt_on_same_line("Enter password: ");
        let confirm = prompt_on_same_line("Confirm password: ");
        if password == confirm {
            return password;
        }
        println!("Passwords do not match, please try again");
    }
}

pub fn prompt_on_same_line(prompt: &str) -> String {
    print!("{}", prompt);
    io::stdout().flush().expect("Failed to flush stdout");
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .expect("Failed to read line");
    input.trim().to_string()
}

pub fn prompt_confirm(prompt: &str) -> bool {
    let response = prompt_on_same_line(&format!("{} (y/N): ", prompt));
    response.to_lowercase() == "y"
}
