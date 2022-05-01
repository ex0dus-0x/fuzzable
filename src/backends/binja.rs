use binaryninja::{
    binaryview::{BinaryView, BinaryViewExt},
    command,
    function::Function,
};

use std::collections::BTreeMap;
use std::fs::File;
use std::path::PathBuf;

use crate::backends::Candidate;
use crate::errors::FuzzResult;

pub struct FuzzableBinja {
    candidates: BTreeMap<String, Candidate>,
    ranked: Vec<Candidate>,
}

impl FuzzableBinja {
    pub fn excavate(path: PathBuf) -> FuzzResult<()> {
        binaryninja::headless::init();
        let bv = binaryninja::open_view(path).expect("Couldn't open file");
        bv.update_analysis_and_wait();
        run_fuzzable(&bv);
        binaryninja::headless::shutdown();
        Ok(())
    }
}

fn run_fuzzable(bv: &BinaryView) {
    for func in &bv.functions() {
        log::trace!("{}", func.symbol().full_name());
        //log::trace!("{}", (*func.handle).callers);
    }
}

fn run_export_report(bv: &BinaryView) {
    let csv_file = binaryninja::interaction::get_save_filename_input(
        "Filename to export as CSV?",
        "csv",
        "Save CSV",
    )
    .unwrap();
    let mut file = File::create(csv_file);
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
