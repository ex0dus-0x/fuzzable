pub mod binja;
pub mod source;

// Interesting patterns to parse for in unstripped symbols when determining fuzzability
const INTERESTING_PATTERNS: [&'static str; 6] = ["Parse", "Read", "Buf", "File", "Input", "String"];

const INTERSTING_CALLS: [&'static str; 3] = ["strcpy", "strcat", "memcpy"];

/// Wraps and handles analysis of a single valid function from a binary view,
/// calculating a fuzzability score based on varying metrics, and outputs a
/// markdown row for final table output.
pub trait FuzzableAnalysis {
    fn get_callgraph_complexity(&self);

    fn contains_loop(&self) -> bool;

    fn get_fuzzability_score(&self) -> u32;

    fn generate_csv_row(&self);
}

pub use source::FuzzableSource;
pub use binja::FuzzableBinja;
