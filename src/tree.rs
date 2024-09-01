use std::io::Write;
use std::{collections::VecDeque, fs::File};
use Line::{AgdaBlock, Content};

pub(crate) enum Line {
    AgdaBlock,
    Content(String),
}

pub(crate) struct Tree {
    lines: Vec<Line>,
}

impl Tree {
    pub(crate) fn new() -> Tree {
        Tree { lines: vec![] }
    }

    pub(crate) fn push(&mut self, content: String) {
        self.lines.push(Line::Content(content));
    }
    pub(crate) fn push_agda(&mut self) {
        self.lines.push(Line::AgdaBlock);
    }

    pub fn merge(&self, mut agda_blocks: VecDeque<String>) -> Tree {
        let mut new_tree = Tree::new();
        for l in &self.lines {
            match l {
                Content(s) => new_tree.push(s.clone()),
                AgdaBlock => {
                    let k = agda_blocks.pop_front().expect("agda blocks is not enough");
                    new_tree.push(k);
                }
            }
        }
        new_tree
    }

    pub fn write(&self, mut output: File) {
        output
            .write("\\xmlns:html{http://www.w3.org/1999/xhtml}\n".as_bytes())
            .unwrap();
        for l in &self.lines {
            match l {
                Content(s) => {
                    let _ = output.write(s.as_bytes()).unwrap();
                    let _ = output.write(&[b'\n']).unwrap();
                }
                AgdaBlock => {}
            }
        }
    }
}
