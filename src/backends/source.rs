use tree_sitter::{Language, Node, Parser, Query, QueryCursor};

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use crate::backends::Candidate;
use crate::errors::{FuzzError, FuzzResult};

extern "C" {
    fn tree_sitter_c() -> Language;
    fn tree_sitter_cpp() -> Language;
}

pub struct FuzzableSource {
    candidates: BTreeMap<String, Candidate>,
    ranked: Vec<Candidate>,
}

impl FuzzableSource {
    pub fn excavate(paths: Vec<PathBuf>) -> FuzzResult<()> {
        log::trace!("Setting up tree-sitter parser");
        let language = unsafe { tree_sitter_c() };
        let mut parser = Parser::new();
        parser.set_language(language).unwrap();

        let query = Query::new(
            language,
            r#"
    		(
                (function_definition)
            )
    		"#,
        )
        .unwrap();

        let mut query_cursor = QueryCursor::new();

        for path in paths {
            log::trace!("Parsing the `{}` as an AST", path.display());
            let source_code = fs::read(&path)?;
            let text_callback = |n: Node| &source_code[n.byte_range()];
            let tree = match parser.parse(&source_code, None) {
                Some(res) => res,
                None => {
                    return Err(FuzzError(String::from("cannot parse source")));
                }
            };

            let root_node = tree.root_node();
            log::debug!("{}", root_node.to_sexp());

            let all_matches = query_cursor.matches(&query, root_node, source_code.as_slice());

            for m in all_matches {
                println!("{:?}", m);
                for capture in m.captures {
                    let node = capture.node;
                    println!("{}", node.to_sexp());
                }
            }
        }
        Ok(())
    }
}
