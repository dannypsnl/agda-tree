// The program here extract agda code from `*.agda.tree`
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

pub fn extract_agda_code<P>(filename: P) -> io::Result<Vec<String>>
where
    P: AsRef<Path>,
{
    let lines_of_agda_tree = read_lines(filename)?;

    let mut recording = false;
    let mut buffer = String::new();
    let mut result = vec![];
    for line in lines_of_agda_tree {
        match line {
            Ok(line) => {
                if line == "\\agda{" {
                    recording = true;
                    buffer.push_str("```agda\n");
                } else if line == "}" && recording {
                    buffer.push_str("```");
                    result.push(buffer);
                    buffer = String::new();
                    recording = false;
                } else {
                    if recording {
                        buffer.push_str(line.as_str());
                        buffer.push('\n');
                    }
                }
            }
            Err(e) => {}
        }
    }
    Ok(result)
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
