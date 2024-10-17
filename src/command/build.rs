use html_parser::{Dom, Element, Node};
use std::collections::VecDeque;
use std::fs::{self, create_dir_all, read_to_string, File};
use std::io::{self, Write};
use std::iter::zip;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::extract::extract_agda_code;
use crate::tree::Tree;

pub fn execute(working_dir: &PathBuf, output_dir: &PathBuf, skip_agda: bool) -> io::Result<()> {
    let paths = fs::read_dir(working_dir)?
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

    // TODO:
    // 1. The new workflow will no need tmp *.lagda.md
    // 2. Instead, there will have *.lagda.tree -> *.html directly
    // 3. Then agda-tree should recognize these HTML block in *.html (forester syntax should leave
    //    unchanged by agda)
    // 4. Replace HTML with forester namespace syntax and put them back at right place
    let trees = generate_lagda_md(&paths)?;
    let index_path = generate_index(working_dir, &paths)?;
    if !skip_agda {
        run_agda_build(working_dir, index_path)?;
    }
    collect_html(working_dir, output_dir, &paths, trees)
}

fn generate_lagda_md(paths: &Vec<PathBuf>) -> io::Result<Vec<Tree>> {
    let mut r = vec![];
    for path in paths {
        let (tree, agda_blocks) = extract_agda_code(&path)?;
        let mut middle = File::create(path.with_extension("md"))?;
        for block in agda_blocks {
            middle.write(block.as_bytes())?;
        }
        r.push(tree);
    }
    Ok(r)
}

fn run_agda_build(working_dir: &PathBuf, index_path: PathBuf) -> io::Result<()> {
    let _ = Command::new("agda")
        .current_dir(working_dir)
        .args([
            "--html",
            index_path.into_os_string().into_string().unwrap().as_str(),
        ])
        .output()
        .expect("failed to build agda htmls");
    Ok(())
}

fn generate_index(working_dir: &PathBuf, paths: &Vec<PathBuf>) -> io::Result<PathBuf> {
    // generate a index agda module, import our `.lagda.md`
    let imports = paths
        .into_iter()
        .map(|path| format!("import {}", path.file_prefix().unwrap().to_str().unwrap()))
        .collect::<Vec<String>>();
    let index_path = working_dir.join("index.agda");
    let mut index = File::create(&index_path)?;
    for imp in imports {
        index.write(imp.as_bytes())?;
    }
    Ok(index_path)
}

fn collect_html(
    working_dir: &PathBuf,
    output_dir: &PathBuf,
    paths: &Vec<PathBuf>,
    trees: Vec<Tree>,
) -> io::Result<()> {
    for (path, tree) in zip(paths.into_iter(), trees.into_iter()) {
        let basename = path.file_prefix().unwrap().to_str().unwrap();
        let agda_html = working_dir
            .join("html")
            .join(basename)
            .with_extension("html");

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

        let forester_blocks = agda_html_blocks(working_dir, nodes);

        let new_tree = tree.merge(forester_blocks);

        create_dir_all(output_dir)?;
        let output = File::create(output_dir.join(basename).with_extension("tree"))?;
        new_tree.write(output);
    }

    Ok(())
}

fn agda_html_blocks(working_dir: &PathBuf, nodes: &Vec<Node>) -> VecDeque<String> {
    let mut blocks = VecDeque::new();
    let mut buffer = String::new();
    let mut recording = false;
    let mut line = line_of_symbol(nodes[0].element().unwrap());
    let mut last_col_end = end_col_of_symbol(nodes[0].element().unwrap());

    for node in nodes {
        let elem = node.element().unwrap();
        if is_block_start(elem) {
            recording = true;
            line = line_of_symbol(elem);
            last_col_end = col_of_symbol(elem);
            buffer.push_str("\\<html:pre>[class]{Agda}{\n");
        } else if is_block_end(elem) {
            buffer.push_str("}");
            blocks.push_back(buffer);
            recording = false;
            buffer = String::new();
        } else if recording {
            if line_of_symbol(elem) > line {
                for _ in 0..(line_of_symbol(elem) - line) {
                    buffer.push('\n');
                }
                last_col_end = 1;
            }
            if col_of_symbol(elem) > last_col_end {
                for _ in 0..col_of_symbol(elem) - last_col_end {
                    buffer.push(' ');
                }
            }
            last_col_end = end_col_of_symbol(elem);
            line = line_of_symbol(elem);
            buffer.push_str(symbol2forest(working_dir, elem).as_str());
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

fn line_of_symbol(elem: &Element) -> usize {
    elem.source_span.end_line
}
fn col_of_symbol(elem: &Element) -> usize {
    elem.source_span.start_column
}
fn end_col_of_symbol(elem: &Element) -> usize {
    elem.source_span.end_column
}

fn symbol2forest(working_dir: &PathBuf, elem: &Element) -> String {
    let mut s = format!("\\<html:{}>", elem.name);

    if elem.id.is_some() {
        s.push_str(format!("[id]{{{}}}", elem.id.clone().unwrap().as_str()).as_str());
    }
    if !elem.classes.is_empty() {
        s.push_str(format!("[class]{{{}}}", elem.classes[0]).as_str());
    }
    for (k, v) in &elem.attributes {
        let value = v.clone().unwrap();
        let value = if k == "href" {
            // value is a xxx.html#id
            // 1. split at `#`
            // 2. if there is a `xxx.lagda.tree` in workding dir, replace the path with `xxx.xml`
            // 3. put `#id` back if exists
            let split = value.split_terminator('#').collect::<Vec<&str>>();
            let a_link = split[0];
            let path = Path::new(a_link);
            if working_dir.join(path).with_extension("lagda.tree").exists() {
                let mut s = path.with_extension("xml").to_str().unwrap().to_owned();
                s.push('#');
                if split.len() == 2 {
                    let id_part = split[1];
                    s.push_str(id_part);
                }
                s
            } else {
                value
            }
        } else {
            value
        };
        s.push_str(format!("[{}]{{{}}}", k, value).as_str());
    }
    if elem.children.is_empty() {
        s.push_str("{}");
    } else {
        let childtext = elem.children[0].text().unwrap();
        // some escape code is useful for HTML, but not for forester
        let childtext = if childtext.contains("&#39;") {
            childtext.replace("&#39;", "'")
        } else {
            childtext.to_owned()
        };
        if childtext.contains('(')
            || childtext.contains(')')
            || childtext.contains('{')
            || childtext.contains('}')
        {
            s.push_str(format!("{{\\startverb{}\\stopverb}}", childtext).as_str());
        } else {
            s.push_str(format!("{{{}}}", childtext).as_str());
        }
    }

    s
}
