use std::io::BufRead;

fn main() {
    println!("cargo::rerun-if-changed=.build_env");
    const ENV_NAME: &str = ".build_env";
    if let Ok(f) = std::fs::File::open(ENV_NAME) {
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
