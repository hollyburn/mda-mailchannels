use std::io::BufRead;

fn main() {
    const ENV_NAME: &str = ".build_env";
    if std::fs::exists(ENV_NAME).unwrap() {
        let f = std::fs::File::open(ENV_NAME).unwrap();
        let bf = std::io::BufReader::new(f);
        for line in bf.lines() {
            let line = line.unwrap();
            if line.starts_with("#") {
                continue;
            }
            print!("cargo::rustc-env=");
            println!("{}", line);
        }
    }
}
