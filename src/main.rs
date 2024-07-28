#![feature(path_file_prefix)]
use html_parser::{Dom, Element, Node};
use std::fs::{self};
use std::fs::{read_to_string, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use agda_tree::extract::extract_agda_code;

fn main() {
    // TODO: directory should be provided by users
    let files = fs::read_dir(".")
        .unwrap()
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

    generate_lagda_md(&files);
    generate_index(&files);
    collect_html(&files);
}

fn generate_lagda_md(files: &Vec<PathBuf>) {
    files.into_iter().for_each(|path| {
        let agda_blocks =
            extract_agda_code(&path).expect(format!("failed to read file `{:?}`", path).as_str());

        let lagda_md = path.with_extension("md");

        let mut middle = File::create(lagda_md).unwrap();
        for block in agda_blocks {
            middle.write(block.as_bytes()).unwrap();
        }
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

fn collect_html(files: &Vec<PathBuf>) {
    files.into_iter().for_each(|path| {
        let basename = path.file_prefix().unwrap().to_str().unwrap();
        let agda_html = Path::new("html").join(basename).with_extension("html");

        let s = read_to_string(&agda_html)
            .expect(format!("failed to open generated html file `{:?}`", agda_html).as_str());
        let dom = Dom::parse(s.as_str()).unwrap();

        let nodes = &dom.children[0].element().unwrap().children[1]
            .element()
            .unwrap()
            .children[0]
            .element()
            .unwrap()
            .children;

        let forester_blocks = agda_html_blocks(nodes);

        // TODO: haven't recover the Literate tree part
        let mut output = File::create(Path::new(basename).with_extension("tree")).unwrap();
        output.write("\\import{base-macros}\n".as_bytes()).unwrap();
        for block in forester_blocks {
            output.write(block.as_bytes()).unwrap();
        }
    });
}

fn agda_html_blocks(nodes: &Vec<Node>) -> Vec<String> {
    let mut blocks = vec![];
    let mut buffer = String::new();
    let mut recording = false;
    for node in nodes {
        if is_block_start(node.element().unwrap()) {
            recording = true;
            buffer.push_str("\\<html:pre>[class]{Agda}{\n");
        } else if is_block_end(node.element().unwrap()) {
            buffer.push_str("}");
            blocks.push(buffer);
            recording = false;
            buffer = String::new();
        } else if recording {
            buffer.push_str(to_forester_syntax(node.element().unwrap()).as_str())
        }
    }
    blocks
}
fn is_block_start(elem: &Element) -> bool {
    !elem.children.is_empty() && elem.children[0].text().unwrap().contains("```agda")
}
fn is_block_end(elem: &Element) -> bool {
    !elem.children.is_empty() && elem.children[0].text().unwrap().contains("```")
}

fn to_forester_syntax(elem: &Element) -> String {
    let mut s = format!("\\<html:{}>", elem.name);

    if elem.id.is_some() {
        s.push_str(format!("[id]{{{}}}", elem.id.clone().unwrap().as_str()).as_str());
    }
    if !elem.classes.is_empty() {
        s.push_str(format!("[class]{{{}}}", elem.classes[0]).as_str());
    }
    for (k, v) in &elem.attributes {
        s.push_str(format!("[{}]{{{}}}", k, v.clone().unwrap().as_str()).as_str());
    }
    if elem.children.is_empty() {
        s.push_str("{}");
    } else {
        for c in &elem.children {
            s.push_str(format!("{{{}}}", c.text().unwrap()).as_str());
        }
    }

    s.push('\n');
    s
}
