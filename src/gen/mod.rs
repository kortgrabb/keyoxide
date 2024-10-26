use rand::Rng;

pub struct PasswordGenerator {
    length: usize,
    use_uppercase: bool,
    use_lowercase: bool,
    use_numbers: bool,
    use_special: bool,
}

impl PasswordGenerator {
    pub fn new(length: usize, use_uppercase: bool, use_lowercase: bool, use_numbers: bool, use_special: bool) -> Self {
        Self {
            length,
            use_uppercase,
            use_lowercase,
            use_numbers,
            use_special,
        }
    }

    pub fn default() -> Self {
        Self {
            length: 16,
            use_uppercase: true,
            use_lowercase: true,
            use_numbers: true,
            use_special: true,
        }
    }

    pub fn with_length(mut self, length: usize) -> Self {
        self.length = length;
        self
    }

    pub fn with_uppercase(mut self, use_uppercase: bool) -> Self {
        self.use_uppercase = use_uppercase;
        self
    }

    pub fn with_lowercase(mut self, use_lowercase: bool) -> Self {
        self.use_lowercase = use_lowercase;
        self
    }

    pub fn with_numbers(mut self, use_numbers: bool) -> Self {
        self.use_numbers = use_numbers;
        self
    }

    pub fn with_special(mut self, use_special: bool) -> Self {
        self.use_special = use_special;
        self
    }

    pub fn generate(&self) -> String {
        let mut password = String::new();
        let mut rng = rand::thread_rng();

        // string to hold all the chars we use
        let mut char_set = String::new();    

        if self.use_uppercase {
            char_set.push_str("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        }

        if self.use_lowercase {
            char_set.push_str("abcdefghijklmnopqrstuvwxyz");
        }

        if self.use_numbers {
            char_set.push_str("0123456789");
        }

        if self.use_special {
            char_set.push_str("!@#$%^&*()-_=+");
        }

        for _ in 0..self.length {
            // the length is inclusive, meaning the range is 0 to char_set.len() - 1
            let idx = rng.gen_range(0..char_set.len());
            password.push(char_set.chars().nth(idx).unwrap());
        }

        password
    }
}