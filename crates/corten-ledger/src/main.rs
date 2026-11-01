//! `corten-ledger check|totals [PATH]`.
//!
//! `check` also checks the `strategy` column against
//! `audit/residual/strategies.csv`, found relative to the ledger
//! (`<root>/ledger/cwe-ledger.csv` → `<root>/audit/residual/strategies.csv`).
//!
//! Exit status: 0 the gate passes (or totals printed), 1 the ledger has
//! problems, 2 usage error or unreadable file.

use std::env;
use std::fs;
use std::path::Path;
use std::process::ExitCode;

use corten_ledger::{Ledger, Record, parse_csv};

/// The `strategy` column of audit/residual/strategies.csv.
fn strategy_ids(records: &[Record]) -> Result<Vec<String>, String> {
    let (header, rows) = records.split_first().ok_or("empty file")?;
    let column = header
        .iter()
        .position(|h| h == "strategy")
        .ok_or("no strategy column")?;
    let ids: Vec<String> = rows.iter().filter_map(|r| r.get(column).cloned()).collect();
    if ids.is_empty() {
        return Err("no strategies".to_owned());
    }
    Ok(ids)
}

const DEFAULT_PATH: &str = "ledger/cwe-ledger.csv";
const USAGE: &str =
    "Usage: corten-ledger <check|totals> [PATH]  (default PATH: ledger/cwe-ledger.csv)";

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let (command, path) = match args.as_slice() {
        [c] => (c.as_str(), DEFAULT_PATH),
        [c, p] => (c.as_str(), p.as_str()),
        _ => {
            eprintln!("{USAGE}");
            return ExitCode::from(2);
        }
    };
    if !matches!(command, "check" | "totals") {
        eprintln!("unknown command {command:?}\n{USAGE}");
        return ExitCode::from(2);
    }
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(e) => {
            eprintln!("error: cannot read {path}: {e}");
            return ExitCode::from(2);
        }
    };
    let ledger = match parse_csv(&text)
        .map_err(|e| e.to_string())
        .and_then(|records| Ledger::from_records(records).map_err(|e| e.to_string()))
    {
        Ok(ledger) => ledger,
        Err(e) => {
            eprintln!("error: {path}: {e}");
            return ExitCode::from(1);
        }
    };
    if command == "totals" {
        print!("{}", ledger.totals());
        return ExitCode::SUCCESS;
    }
    // The strategies sit beside the ledger: <root>/audit/residual/strategies.csv.
    let strategies_path = Path::new(path)
        .parent()
        .and_then(Path::parent)
        .unwrap_or_else(|| Path::new(""))
        .join("audit/residual/strategies.csv");
    let known = match fs::read_to_string(&strategies_path)
        .map_err(|e| e.to_string())
        .and_then(|text| parse_csv(&text).map_err(|e| e.to_string()))
        .and_then(|records| strategy_ids(&records))
    {
        Ok(known) => known,
        Err(e) => {
            eprintln!("error: {}: {e}", strategies_path.display());
            return ExitCode::from(2);
        }
    };
    let known: Vec<&str> = known.iter().map(String::as_str).collect();
    let mut problems = ledger.check();
    match ledger.check_strategies(&known) {
        Ok(found) => problems.extend(found),
        Err(e) => {
            eprintln!("error: {path}: {e}");
            return ExitCode::from(1);
        }
    }
    for problem in &problems {
        eprintln!("{problem}");
    }
    let e_rows = ledger.e_rows().len();
    if problems.is_empty() {
        println!(
            "ledger gate passes: {} rows checked, {e_rows} E rows each name a mechanism, TCB assumption and proof test",
            ledger.len()
        );
        ExitCode::SUCCESS
    } else {
        eprintln!(
            "ledger gate fails: {} problems in {} rows",
            problems.len(),
            ledger.len()
        );
        ExitCode::from(1)
    }
}
