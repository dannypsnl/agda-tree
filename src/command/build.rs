use html_parser::{Dom, Element};
use std::fs::{self, create_dir_all, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

pub fn execute(working_dir: &PathBuf, output_dir: &PathBuf) -> io::Result<()> {
    let agda_generate_trees = fs::read_dir(working_dir.join("html"))?
        .filter_map(Result::ok)
        .filter_map(|f| {
            if let Ok(ft) = f.file_type() {
                if ft.is_file() && f.path().to_str()?.ends_with(".tree") {
                    return Some(f.path());
                }
            }
            None
        })
        .collect::<Vec<PathBuf>>();

    create_dir_all(output_dir)?;

    for tree_path in agda_generate_trees {
        let new_content = postprocess(working_dir, tree_path.clone())?;

        let created_path = output_dir
            .join(tree_path.file_stem().unwrap())
            .with_added_extension("tree");
        println!("Producing {:?}", created_path);
        let mut out_file = File::create(created_path)?;
        out_file.write_all(new_content.as_bytes())?;
    }

    Ok(())
}

fn postprocess(working_dir: &PathBuf, tree_path: PathBuf) -> io::Result<String> {
    println!("Processing file: {:?}", tree_path);

    let mut file = File::open(tree_path.clone())?;
    let mut content = String::new();
    file.read_to_string(&mut content)?;

    let mut new_content = String::new();
    let mut html = String::new();

    let mut recording = false;
    let mut line: usize = 0;
    let mut last_col_end: usize = 0;


    new_content.push_str("\\xmlns:html{http://www.w3.org/1999/xhtml}");

    for cur_line in content.lines() {
        if cur_line.contains("<pre class=\"Agda\">") {
            new_content.push_str("\\<html:pre>[class]{Agda}{");
            recording = true;
        } else if cur_line.contains("</pre>") {
            recording = false;
            let dom = Dom::parse(html.as_str()).unwrap();
            html.clear();

            for node in dom.children {
                let elem = node.element().unwrap();

                if line_of_symbol(elem) > line {
                    for _ in 0..(line_of_symbol(elem) - line) {
                        new_content.push('\n');
                    }
                    last_col_end = 1;
                }
                if col_of_symbol(elem) > last_col_end {
                    for _ in 0..col_of_symbol(elem) - last_col_end {
                        new_content.push(' ');
                    }
                }
                last_col_end = end_col_of_symbol(elem);
                line = line_of_symbol(elem);

                new_content.push_str(symbol2forest(working_dir, elem).as_str());
            }

            new_content.push_str("}\n");
        } else if recording {
            html.push_str(cur_line);
            html.push('\n');
        } else {
            new_content.push_str(cur_line);
            new_content.push('\n');
        }
    }

    Ok(new_content)
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
            if working_dir.join("html").join(path).with_extension("tree").exists() {
                let mut s = path.with_extension("").join("index.xml").to_str().unwrap().to_owned();
                s.push('#');
                s.push('#');
                if split.len() == 2 {
                    let id_part = split[1];
                    s.push_str(id_part);
                }
                s
            } else {
                let mut s = path.to_str().unwrap().to_owned();
                s.push('#');
                s.push('#');
                if split.len() == 2 {
                    let id_part = split[1];
                    s.push_str(id_part);
                    s
                }
                else{
                    value
                }
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
        let childtext = if childtext.contains("&lt;") {
            childtext.replace("&lt;", "<")
        } else {
            childtext.to_owned()
        };
        let childtext = if childtext.contains("&lt;") {
            childtext.replace("&gt;", ">")
        } else {
            childtext.to_owned()
        };
        let childtext = if childtext.contains("&quot;") {
            childtext.replace("&quot;", "\"")
        } else {
            childtext.to_owned()
        };
        // TODO: Hack to get \startverb-- to work "properly" in forester
        let childtext = if childtext.starts_with("--") {
            childtext.replacen("--", " --", 1)
        } else{
            childtext.to_owned()
        };
        if childtext.contains('(')
            || childtext.contains(')')
            || childtext.contains('{')
            || childtext.contains('}')
            || childtext.contains('[')
            || childtext.contains(']')
        {
            s.push_str(format!("{{\\startverb {}\\stopverb}}", childtext).as_str());
        } else {
            s.push_str(format!("{{{}}}", childtext).as_str());
        }
    }

    s
}
