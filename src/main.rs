#![feature(path_file_prefix)]
use html_parser::Dom;
use std::fs::{self};
use std::fs::{read_to_string, File};
use std::io::Write;
use std::path::{Path, PathBuf};

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

    files.into_iter().for_each(|path| {
        let basename = path.file_prefix().unwrap().to_str().unwrap();
        let agda_html = Path::new("html").join(basename).with_extension("html");

        let s = read_to_string(&agda_html)
            .expect(format!("failed to open generated html file `{:?}`", agda_html).as_str());
        let dom = Dom::parse(s.as_str()).unwrap();

        // This is the agda code blocks in generated html
        println!(
            "{:?}",
            dom.children[0].element().unwrap().children[1]
                .element()
                .unwrap()
                .children[0]
                .element()
                .unwrap()
                .children
        );

        // TODO:
        // final `output` is the a usual forester tree, we put final result in it
    });
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
