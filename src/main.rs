use std::fs;

fn main() {
    // TODO: directory should be provided by users
    let files = fs::read_dir(".").unwrap();
    files
        .filter_map(Result::ok)
        .filter_map(|f| {
            if f.path().ends_with(".agda.tree") {
                Some(f.path())
            } else {
                None
            }
        })
        .for_each(|path| {
            // TODO: now we get some files to deal, we need to open them
            println!("{:?}", path);
        });
}
