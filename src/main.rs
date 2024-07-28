use std::fs;

use agda_tree::extract::extract_agda_code;

fn main() {
    // TODO: directory should be provided by users
    let files = fs::read_dir(".").unwrap();
    let files = files.filter_map(Result::ok).filter_map(|f| {
        if let Ok(ft) = f.file_type() {
            if ft.is_file() && f.path().to_str()?.ends_with(".lagda.tree") {
                return Some(f);
            }
        }
        None
    });

    files.for_each(|f| {
        let agda_blocks = extract_agda_code(f.path())
            .expect(format!("failed to read file `{:?}`", f.path()).as_str());

        for bl in agda_blocks {
            println!("{}", bl.as_str());
        }

        let lagda_md = f.path().with_extension("lagda.md");

        // TODO:
        // - extract agda code, provides a module
        // - generate agda module for current `f`
    });

    // TODO:
    // - generate a index agda module, such that all `agdas` are in it
    // - final `output` is the a usual forester tree, we put final result in it
}
