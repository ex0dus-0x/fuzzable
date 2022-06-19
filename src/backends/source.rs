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
                (function_definition
                    declarator: (_) @fn-name) @raise
                (#match? @fn-name "_")
            )
    		"#,
        )
        .unwrap();

        let callgraph_query = Query::new(
            language,
            r#"
            (
                (call_expression
                    function: (_) @fn-name)
                (#match? @fn-name "_")
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

            log::trace!("Getting matches for AST");
            let all_matches = query_cursor.matches(&query, root_node, source_code.as_slice());

            //let mut calls: Vec<FunctionCall> = vec![];

            log::trace!("Iterating over matches and saving metadata per node");
            let raise_idx = query.capture_index_for_name("raise").unwrap();
            for each_match in all_matches {
                for capture in each_match.captures.iter().filter(|c| c.index == raise_idx) {
                    log::trace!("Parsing top-level declarator node for function");
                    let declarator = match capture.node.child_by_field_name("declarator") {
                        Some(child) => {

                            // recovers the actual name
                            // TODO: is there a better way to do this?
                            let name = match child.child_by_field_name("declarator") {
                                Some(val) => val,
                                None => {
                                    continue;
                                }
                            };

                            let params = match child.child_by_field_name("parameters") {
                                Some(params) => {
                                    println!("Getting params");
                                    let mut cursor = child.walk();
                                    for param in params.children_by_field_name("parameter_declaration", &mut cursor) {
                                        println!("{:?}", param);
                                    }
                                    params
                                },
                                None => {
                                    continue;
                                }
                            };
                            name
                        }
                        None => {
                            log::warn!("No declarator node for function");
                            continue;
                        }
                    };

                    let range = declarator.range();
                    let text = &source_code[range.start_byte..range.end_byte];
                    let name = std::str::from_utf8(text).unwrap();
                    println!("{}", name);

                    log::trace!("Parsing body of function for callgraph");
                    let body = match capture.node.child_by_field_name("body") {
                        Some(child) => child,
                        None => {
                            log::warn!("No body available for function {}", name);
                            continue;
                        }
                    };

                    let mut query_cursor = QueryCursor::new();
                    let cg = query_cursor.matches(&callgraph_query, root_node, source_code.as_slice());
                    for each_match in cg {
                        for capture in each_match.captures.iter() {
                            println!("{:?}", capture.node);
                        }
                    }
                }
            }
        }
        Ok(())
    }
}
