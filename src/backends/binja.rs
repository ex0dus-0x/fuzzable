use binaryninja::{
    binaryview::{BinaryView, BinaryViewExt},
    command::{self, Command},
    function::Function,
};

use std::fs::File;
use std::path::PathBuf;

pub struct BinjaFuzzable;

impl BinjaFuzzable {
    fn new(path: PathBuf) {
        binaryninja::headless::init();
        let bv = binaryninja::open_view(path).expect("Couldn't open file");
        binaryninja::headless::shutdown();
    }
}

/*
impl Command for BinjaFuzzable {
    fn action(&self, view: &BinaryView) {
        //dump_dwarf(view);
    }
}
*/

fn run_fuzzable(bv: &BinaryView) {
    for func in &bv.functions() {
        log::trace!("{}", func.symbol().full_name());
    }
}

fn run_export_report(bv: &BinaryView) {
    let csv_file = binaryninja::interaction::get_save_filename_input("Filename to export as CSV?", "csv", "Save CSV");
    let mut file = File::create("foo.txt");
}

fn run_harness_generation(bv: &BinaryView, func: &Function) {}

#[no_mangle]
pub extern "C" fn UIPluginInit() -> bool {
    command::register(
        "Fuzzable\\Analyze fuzzable targets",
        "Identify and generate targets for fuzzing",
        run_fuzzable,
    );
    command::register(
        "Fuzzable\\Export fuzzability report as CSV",
        "Identify and generate targets for fuzzing",
        run_export_report,
    );
    command::register_for_function(
        "Fuzzable\\Generate fuzzing harness (EXPERIMENTAL, C/C++ ONLY)",
        "For a target function, generate a AFL/libFuzzer C++ harness",
        run_harness_generation,
    );
    true
}
