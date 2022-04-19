use tree_sitter::{Parser, Language};

use crate::errors::{FuzzResult, FuzzError};

use std::fs;
use std::path::PathBuf;

extern "C" {
    fn tree_sitter_c() -> Language;
    fn tree_sitter_cpp() -> Language;
}

pub struct FuzzableSource {
}

impl FuzzableSource {
    pub fn new(paths: Vec<PathBuf>) -> FuzzResult<()> {
        log::trace!("Setting up tree-sitter parser");
        let language = unsafe { tree_sitter_c() };
        let mut parser = Parser::new();
        parser.set_language(language).unwrap();

        for path in paths {
            let source_code = fs::read_to_string(path)?;
            let tree = match parser.parse(source_code, None) {
                Some(res) => res,
                None => {
                    return Err(FuzzError(String::from("cannot parse source")));
                }
            };
            let root_node = tree.root_node();
        }
        Ok(())
    }
}
