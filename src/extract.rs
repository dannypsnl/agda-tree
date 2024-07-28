//! The program here extract agda code from `*.agda.tree`
use std::fs::File;
use std::io::{self, BufRead};
use std::path::Path;

use crate::tree::Tree;

/// The function do is
///
/// - if match `\agda{`, then open recorder
/// - if match `}`, then close the recorder
/// - if recorder is on, then push the content
///
/// so one must write `\agda{` and `}` without space and be single line, this might have problem but for now it's good enough.
pub fn extract_agda_code<P>(filename: P) -> io::Result<(Tree, Vec<String>)>
where
    P: AsRef<Path>,
{
    let lines_of_agda_tree = read_lines(filename)?;

    let mut recording = false;
    let mut buffer = String::new();
    let mut result = vec![];
    let mut tree = Tree::new();
    for line in lines_of_agda_tree {
        let line = line?;
        if line == "\\agda{" {
            recording = true;
            buffer.push_str("```agda\n");
        } else if line == "}" && recording {
            // remember, we must insert these `---` text, to ensure closed
            //     ```
            //     ```agda
            // will not be treated as same HTML node
            buffer.push_str("```\n---\n");
            result.push(buffer);
            buffer = String::new();
            recording = false;
            tree.push_agda();
        } else if recording {
            buffer.push_str(line.as_str());
            buffer.push('\n');
        } else {
            tree.push(line);
        }
    }
    Ok((tree, result))
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
