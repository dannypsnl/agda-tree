#![feature(path_file_prefix)]
use std::fs::File;
use std::fs::{self};
use std::io::Write;
use std::path::PathBuf;

use agda_tree::extract::extract_agda_code;

fn main() {
    // TODO: directory should be provided by users
    let files = fs::read_dir(".").unwrap();
    let files = files
        .filter_map(Result::ok)
        .filter_map(|f| {
            if let Ok(ft) = f.file_type() {
                if ft.is_file() && f.path().to_str()?.ends_with(".lagda.tree") {
                    return Some(f.path());
                }
            }
            None
        })
        .collect::<Vec<PathBuf>>();

    let files = files
        .into_iter()
        .map(|path| {
            let agda_blocks = extract_agda_code(&path)
                .expect(format!("failed to read file `{:?}`", path).as_str());

            let lagda_md = path.with_extension("md");

            let mut middle = File::create(lagda_md).unwrap();
            for block in agda_blocks {
                middle.write(block.as_bytes()).unwrap();
            }

            path
        })
        .collect::<Vec<PathBuf>>();

    generate_index(&files);

    // TODO:
    // final `output` is the a usual forester tree, we put final result in it
    files.into_iter().for_each(|path| {});

    // NOTE:
    // - html parser: https://github.com/y21/tl
}

fn generate_index(files: &Vec<PathBuf>) {
    // generate a index agda module, import our `.lagda.md`
    let imports = &files
        .into_iter()
        .map(|path| format!("import {}", path.file_prefix().unwrap().to_str().unwrap()))
        .collect::<Vec<String>>();
    let mut index = File::create("index.agda").unwrap();
    for imp in imports {
        index.write(imp.as_bytes()).unwrap();
    }
}
