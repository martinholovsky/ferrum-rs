//! Reads `ledger/cwe-ledger.csv`, checks it against the roadmap gates and
//! computes totals, so no number in the docs is typed by hand.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

/// One parsed CSV record: field values in header order.
pub type Record = Vec<String>;

/// Why the CSV text could not be parsed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParseError {
    /// 1-based line on which the problem was found.
    pub line: usize,
    /// What was wrong.
    pub message: &'static str,
}

impl fmt::Display for ParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "line {}: {}", self.line, self.message)
    }
}

impl std::error::Error for ParseError {}

/// Parses RFC 4180 CSV: comma separated, `"` quoting with `""` escapes,
/// LF or CRLF record ends. Quoted fields may span lines.
///
/// # Errors
///
/// Returns [`ParseError`] for a quote inside an unquoted field, text after a
/// closing quote, or an unterminated quoted field.
pub fn parse_csv(text: &str) -> Result<Vec<Record>, ParseError> {
    let mut records = Vec::new();
    let mut record = Vec::new();
    let mut field = String::new();
    let mut line = 1usize;
    let mut chars = text.chars().peekable();
    let mut in_quotes = false;
    let mut field_was_quoted = false;
    while let Some(c) = chars.next() {
        if c == '\n' {
            line = line.saturating_add(1);
        }
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    chars.next();
                    field.push('"');
                } else {
                    in_quotes = false;
                }
            } else {
                field.push(c);
            }
            continue;
        }
        match c {
            '"' if field.is_empty() && !field_was_quoted => {
                in_quotes = true;
                field_was_quoted = true;
            }
            '"' => {
                return Err(ParseError {
                    line,
                    message: "quote inside an unquoted field",
                });
            }
            ',' => {
                record.push(std::mem::take(&mut field));
                field_was_quoted = false;
            }
            '\r' if chars.peek() == Some(&'\n') => {}
            '\n' => {
                record.push(std::mem::take(&mut field));
                field_was_quoted = false;
                records.push(std::mem::take(&mut record));
            }
            _ if field_was_quoted => {
                return Err(ParseError {
                    line,
                    message: "text after a closing quote",
                });
            }
            _ => field.push(c),
        }
    }
    if in_quotes {
        return Err(ParseError {
            line,
            message: "unterminated quoted field",
        });
    }
    if !field.is_empty() || field_was_quoted || !record.is_empty() {
        record.push(field);
        records.push(record);
    }
    Ok(records)
}

/// Writes records as RFC 4180 CSV with LF line ends, quoting a field only
/// when it contains a comma, quote, CR or LF (the ledger's existing style).
#[must_use]
pub fn write_csv(records: &[Record]) -> String {
    let mut out = String::new();
    for record in records {
        for (i, field) in record.iter().enumerate() {
            if i > 0 {
                out.push(',');
            }
            if field.contains([',', '"', '\r', '\n']) {
                out.push('"');
                out.push_str(&field.replace('"', "\"\""));
                out.push('"');
            } else {
                out.push_str(field);
            }
        }
        out.push('\n');
    }
    out
}

/// Why `set_status` could not update the ledger.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetStatusError {
    /// The text is not valid CSV.
    Parse(ParseError),
    /// The header has no `cwe_id` or `status` column.
    MissingColumn(&'static str),
    /// An id to update is not in the ledger.
    UnknownId(String),
}

impl fmt::Display for SetStatusError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Parse(e) => write!(f, "{e}"),
            Self::MissingColumn(c) => write!(f, "ledger has no column {c:?}"),
            Self::UnknownId(id) => write!(f, "{id} is not in the ledger"),
        }
    }
}

impl std::error::Error for SetStatusError {}

/// Returns the ledger text with `status` set to `verified` for `verified`
/// ids and `unverified` for `unverified` ids; every other byte is kept.
///
/// # Errors
///
/// Returns [`SetStatusError`] if the text does not parse, lacks a column, or
/// an id is not in it.
pub fn set_status(
    text: &str,
    verified: &[&str],
    unverified: &[&str],
) -> Result<String, SetStatusError> {
    let mut records = parse_csv(text).map_err(SetStatusError::Parse)?;
    let header = records.first().cloned().unwrap_or_default();
    let col = |name: &'static str| {
        header
            .iter()
            .position(|h| h == name)
            .ok_or(SetStatusError::MissingColumn(name))
    };
    let id_col = col("cwe_id")?;
    let status_col = col("status")?;
    for (ids, value) in [(verified, "verified"), (unverified, "unverified")] {
        for id in ids {
            let row = records
                .iter_mut()
                .skip(1)
                .find(|r| r.get(id_col).is_some_and(|v| v == id))
                .ok_or_else(|| SetStatusError::UnknownId((*id).to_owned()))?;
            if let Some(cell) = row.get_mut(status_col) {
                value.clone_into(cell);
            }
        }
    }
    Ok(write_csv(&records))
}

/// The ledger: the header and one row per CWE id.
#[derive(Debug, Clone)]
pub struct Ledger {
    header: Vec<String>,
    rows: Vec<Record>,
}

/// A field lookup failed: the ledger lacks a column the tool needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MissingColumn(pub &'static str);

impl fmt::Display for MissingColumn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ledger has no column {:?}", self.0)
    }
}

impl std::error::Error for MissingColumn {}

/// Columns the gate checks read.
pub const REQUIRED_COLUMNS: &[&str] = &[
    "cwe_id",
    "drafted_bucket",
    "bucket",
    "bucket_reason",
    "phase",
    "proof_kind",
    "mechanism",
    "tcb_assumption",
    "prelude_only",
    "proof_test",
    "review",
    "status",
];

/// Allowed values of `status`.
pub const STATUSES: &[&str] = &["unverified", "verified"];

/// Allowed values of `proof_kind`: the checker rejects the bad program (and
/// plain cargo builds it), or the language itself rejects it.
pub const PROOF_KINDS: &[&str] = &["checker", "language"];

impl Ledger {
    /// Builds a ledger from parsed CSV records, the first being the header.
    ///
    /// # Errors
    ///
    /// Returns [`MissingColumn`] if the header lacks a required column.
    pub fn from_records(mut records: Vec<Record>) -> Result<Self, MissingColumn> {
        let header = if records.is_empty() {
            Vec::new()
        } else {
            records.remove(0)
        };
        for name in REQUIRED_COLUMNS {
            if !header.iter().any(|h| h == name) {
                return Err(MissingColumn(name));
            }
        }
        Ok(Self {
            header,
            rows: records,
        })
    }

    /// A ledger with only the columns a test needs.
    #[cfg(test)]
    fn from_records_unchecked(mut records: Vec<Record>) -> Self {
        let header = if records.is_empty() {
            Vec::new()
        } else {
            records.remove(0)
        };
        Self {
            header,
            rows: records,
        }
    }

    fn column(&self, name: &'static str) -> usize {
        // from_records guarantees every required column exists.
        self.header.iter().position(|h| h == name).unwrap_or(0)
    }

    /// Value of `name` in `row`, or "" for a short row.
    fn get<'a>(&self, row: &'a Record, name: &'static str) -> &'a str {
        row.get(self.column(name)).map_or("", String::as_str)
    }

    /// Number of data rows.
    #[must_use]
    pub fn len(&self) -> usize {
        self.rows.len()
    }

    /// Whether the ledger has no data rows.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    /// Checks the Phase 0 gate and the ledger's internal consistency.
    /// Returns one message per problem; empty means the gate passes.
    #[must_use]
    pub fn check(&self) -> Vec<String> {
        let mut problems = Vec::new();
        let mut seen = BTreeSet::new();
        for row in &self.rows {
            let id = self.get(row, "cwe_id");
            if row.len() != self.header.len() {
                problems.push(format!(
                    "{id}: {} fields, header has {}",
                    row.len(),
                    self.header.len()
                ));
            }
            if !seen.insert(id) {
                problems.push(format!("{id}: duplicate id"));
            }
            let bucket = self.get(row, "bucket");
            if !["E", "C", "O", "N"].contains(&bucket) {
                problems.push(format!("{id}: bucket {bucket:?} is not E, C, O or N"));
            }
            if bucket != self.get(row, "drafted_bucket")
                && self.get(row, "bucket_reason").is_empty()
            {
                problems.push(format!(
                    "{id}: bucket differs from drafted_bucket without a bucket_reason"
                ));
            }
            for value in row {
                if starts_like_formula(value) {
                    problems.push(format!(
                        "{id}: cell {:?} starts with a spreadsheet formula character",
                        value.chars().take(20).collect::<String>()
                    ));
                }
            }
            let status = self.get(row, "status");
            if !STATUSES.contains(&status) {
                problems.push(format!(
                    "{id}: status {status:?} is not one of {STATUSES:?}"
                ));
            }
            if bucket == "E" {
                for column in [
                    "mechanism",
                    "tcb_assumption",
                    "prelude_only",
                    "proof_test",
                    "phase",
                    "proof_kind",
                ] {
                    if self.get(row, column).is_empty() {
                        problems.push(format!("{id}: E row with empty {column}"));
                    }
                }
                let kind = self.get(row, "proof_kind");
                if !kind.is_empty() && !PROOF_KINDS.contains(&kind) {
                    problems.push(format!(
                        "{id}: proof_kind {kind:?} is not one of {PROOF_KINDS:?}"
                    ));
                }
                if status == "verified" && self.get(row, "review") == "required" {
                    problems.push(format!(
                        "{id}: verified, but its encoder still needs the independent review the Phase 2 gate requires"
                    ));
                }
            } else if status == "verified" {
                problems.push(format!(
                    "{id}: only E rows carry a proof, but status is verified"
                ));
            }
        }
        problems
    }

    /// Checks the `strategy` column (spec section 8, question 15): every CWE
    /// that safe Rust can still write under Corten (`rust_applicability` is
    /// `applies` and the row is not a verified E) names one of `known`, and a
    /// CWE safe Rust cannot write names none. A verified E row may keep its
    /// strategy, so a later demotion does not leave it without one.
    ///
    /// # Errors
    ///
    /// Returns [`MissingColumn`] if the ledger has no `rust_applicability`
    /// or `strategy` column.
    pub fn check_strategies(&self, known: &[&str]) -> Result<Vec<String>, MissingColumn> {
        let position = |name: &'static str| {
            self.header
                .iter()
                .position(|h| h == name)
                .ok_or(MissingColumn(name))
        };
        let (applicability, strategy) = (position("rust_applicability")?, position("strategy")?);
        let mut problems = Vec::new();
        for row in &self.rows {
            let id = self.get(row, "cwe_id");
            let value = cell(row, strategy);
            let writable = cell(row, applicability) == "applies";
            let verified = self.get(row, "bucket") == "E" && self.get(row, "status") == "verified";
            if writable && !verified && value.is_empty() {
                problems.push(format!(
                    "{id}: safe Rust can still write it under Corten, but it names no strategy"
                ));
            } else if !writable && !value.is_empty() {
                problems.push(format!(
                    "{id}: strategy {value:?} set, but safe Rust cannot write it"
                ));
            }
            if !value.is_empty() && !known.contains(&value) {
                problems.push(format!("{id}: unknown strategy {value:?}"));
            }
        }
        Ok(problems)
    }

    /// Ids of rows in `bucket` whose `status` is `verified`, with their proof test.
    #[must_use]
    pub fn verified(&self) -> Vec<(&str, &str)> {
        self.rows
            .iter()
            .filter(|r| self.get(r, "status") == "verified")
            .map(|r| (self.get(r, "cwe_id"), self.get(r, "proof_test")))
            .collect()
    }

    /// Rows whose bucket is E, as (id, phase, proof kind, proof test).
    #[must_use]
    pub fn e_rows(&self) -> Vec<ERow<'_>> {
        self.rows
            .iter()
            .filter(|r| self.get(r, "bucket") == "E")
            .map(|r| ERow {
                id: self.get(r, "cwe_id"),
                phase: self.get(r, "phase"),
                proof_kind: self.get(r, "proof_kind"),
                proof_test: self.get(r, "proof_test"),
                review: self.get(r, "review"),
                status: self.get(r, "status"),
            })
            .collect()
    }

    /// Totals, recomputed from the rows.
    #[must_use]
    pub fn totals(&self) -> Totals {
        let mut totals = Totals::default();
        for row in &self.rows {
            let bucket = self.get(row, "bucket").to_owned();
            let drafted = self.get(row, "drafted_bucket").to_owned();
            add(&mut totals.by_bucket, bucket.clone());
            if bucket != drafted {
                add(&mut totals.moves, format!("{drafted}->{bucket}"));
            }
            if bucket == "E" {
                add(
                    &mut totals.e_by_phase,
                    format!(
                        "phase {} {}",
                        self.get(row, "phase"),
                        self.get(row, "proof_kind")
                    ),
                );
                add(&mut totals.e_by_status, self.get(row, "status").to_owned());
            }
        }
        totals.rows = self.rows.len();
        totals
    }
}

/// Whether a spreadsheet would treat `value` as a formula (CWE-1236): a
/// leading `= + - @`, tab, CR, LF, NUL or a full-width `＝ ＋ － ＠`.
#[must_use]
pub fn starts_like_formula(value: &str) -> bool {
    value.chars().next().is_some_and(|c| {
        matches!(
            c,
            '=' | '+' | '-' | '@' | '\t' | '\r' | '\n' | '\0' | '＝' | '＋' | '－' | '＠'
        )
    })
}

/// Field `i` of `row`, or "" for a short row.
fn cell(row: &Record, i: usize) -> &str {
    row.get(i).map_or("", String::as_str)
}

fn add(map: &mut BTreeMap<String, usize>, key: String) {
    let count = map.entry(key).or_insert(0);
    *count = count.saturating_add(1);
}

/// One E row, as the corpus runner needs it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ERow<'a> {
    /// `CWE-n`.
    pub id: &'a str,
    /// Roadmap phase that delivers the mechanism.
    pub phase: &'a str,
    /// `checker` or `language`.
    pub proof_kind: &'a str,
    /// Path of the compile-fail case, relative to the repository root.
    pub proof_test: &'a str,
    /// `required` when an independent review of the encoder must precede
    /// verification; empty otherwise.
    pub review: &'a str,
    /// `unverified` or `verified`.
    pub status: &'a str,
}

/// Counts recomputed from the ledger.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Totals {
    /// Data rows.
    pub rows: usize,
    /// Rows per current bucket.
    pub by_bucket: BTreeMap<String, usize>,
    /// Rows whose bucket differs from the drafted one, per `drafted->bucket`.
    pub moves: BTreeMap<String, usize>,
    /// E rows per phase and proof kind.
    pub e_by_phase: BTreeMap<String, usize>,
    /// E rows per status.
    pub e_by_status: BTreeMap<String, usize>,
}

impl fmt::Display for Totals {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "rows: {}", self.rows)?;
        for (title, map) in [
            ("bucket", &self.by_bucket),
            ("moved from drafted", &self.moves),
            ("E by phase", &self.e_by_phase),
            ("E by status", &self.e_by_status),
        ] {
            writeln!(f, "{title}:")?;
            for (key, count) in map {
                writeln!(f, "  {key}: {count}")?;
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_quotes_escapes_and_crlf() {
        let text = "a,b\r\n\"x, y\",\"say \"\"hi\"\"\"\n\"multi\nline\",\n";
        let records = parse_csv(text).unwrap();
        assert_eq!(
            records,
            vec![
                vec!["a".to_owned(), "b".to_owned()],
                vec!["x, y".to_owned(), "say \"hi\"".to_owned()],
                vec!["multi\nline".to_owned(), String::new()],
            ]
        );
    }

    #[test]
    fn rejects_malformed_quoting() {
        assert!(parse_csv("a\"b\n").is_err());
        assert!(parse_csv("\"a\"b\n").is_err());
        assert!(parse_csv("\"open\n").is_err());
    }

    fn ledger(rows: &[&str]) -> Ledger {
        let header = REQUIRED_COLUMNS.join(",");
        let text = std::iter::once(header.as_str())
            .chain(rows.iter().copied())
            .collect::<Vec<_>>()
            .join("\n");
        Ledger::from_records(parse_csv(&text).unwrap()).unwrap()
    }

    const GOOD_E: &str = "CWE-1,E,E,,1,checker,m,t,no,corpus/CWE-1,,unverified";

    #[test]
    fn complete_e_row_passes() {
        assert_eq!(ledger(&[GOOD_E]).check(), Vec::<String>::new());
    }

    #[test]
    fn e_row_without_proof_test_fails() {
        let problems = ledger(&["CWE-1,E,E,,1,checker,m,t,no,,,unverified"]).check();
        assert_eq!(problems, ["CWE-1: E row with empty proof_test"]);
    }

    #[test]
    fn move_without_reason_fails() {
        let problems = ledger(&["CWE-2,E,C,,,,,,,,,unverified"]).check();
        assert_eq!(
            problems,
            ["CWE-2: bucket differs from drafted_bucket without a bucket_reason"]
        );
    }

    #[test]
    fn duplicate_and_bad_status_fail() {
        let problems = ledger(&[GOOD_E, &GOOD_E.replace("unverified", "done")]).check();
        assert_eq!(problems.len(), 2, "{problems:?}");
    }

    #[test]
    fn verified_row_awaiting_review_fails() {
        let row = "CWE-4,E,E,,2,language,m,t,yes,corpus/CWE-4,required,verified";
        assert_eq!(ledger(&[row]).check().len(), 1);
        let reviewed = "CWE-4,E,E,,2,language,m,t,yes,corpus/CWE-4,docs/reviews/x.md,verified";
        assert_eq!(ledger(&[reviewed]).check(), Vec::<String>::new());
    }

    #[test]
    fn formula_leading_cell_fails() {
        let problems = ledger(&[&GOOD_E.replace(",m,", ",=cmd(),")]).check();
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(starts_like_formula("＠x"));
        assert!(!starts_like_formula("x=1"));
    }

    #[test]
    fn verified_non_e_row_fails() {
        let problems = ledger(&["CWE-3,C,C,,,,,,,,,verified"]).check();
        assert_eq!(problems.len(), 1, "{problems:?}");
    }

    #[test]
    fn missing_column_is_reported() {
        let records = parse_csv("cwe_id,bucket\nCWE-1,E\n").unwrap();
        assert_eq!(
            Ledger::from_records(records).err(),
            Some(MissingColumn("drafted_bucket"))
        );
    }

    #[test]
    fn writer_round_trips_and_set_status_changes_one_cell() {
        let text =
            "cwe_id,name,status\nCWE-1,\"a, \"\"b\"\"\",unverified\nCWE-2,plain,unverified\n";
        assert_eq!(write_csv(&parse_csv(text).unwrap()), text);
        let updated = set_status(text, &["CWE-2"], &[]).unwrap();
        assert_eq!(
            updated,
            "cwe_id,name,status\nCWE-1,\"a, \"\"b\"\"\",unverified\nCWE-2,plain,verified\n"
        );
        assert!(set_status(text, &["CWE-9"], &[]).is_err());
    }

    fn strategy_ledger(rows: &[&str]) -> Ledger {
        let text = std::iter::once("cwe_id,bucket,status,rust_applicability,strategy")
            .chain(rows.iter().copied())
            .collect::<Vec<_>>()
            .join("\n");
        Ledger::from_records_unchecked(parse_csv(&text).unwrap())
    }

    #[test]
    fn strategy_rules() {
        let known = ["budgets", "lints"];
        let check = |rows: &[&str]| strategy_ledger(rows).check_strategies(&known).unwrap();
        // A remaining row with a known strategy, a verified E row with or
        // without one, and an unwritable row without one all pass.
        assert_eq!(
            check(&[
                "CWE-1,C,unverified,applies,budgets",
                "CWE-2,E,verified,applies,",
                "CWE-3,E,verified,applies,lints",
                "CWE-4,C,unverified,not-applicable,",
            ]),
            Vec::<String>::new()
        );
        assert_eq!(
            check(&["CWE-5,C,unverified,applies,"]),
            ["CWE-5: safe Rust can still write it under Corten, but it names no strategy"]
        );
        assert_eq!(
            check(&["CWE-6,E,unverified,applies,"]).len(),
            1,
            "a claimed E row still remains"
        );
        assert_eq!(
            check(&["CWE-7,C,unverified,unsafe-rust-only,lints"]),
            ["CWE-7: strategy \"lints\" set, but safe Rust cannot write it"]
        );
        assert_eq!(
            check(&["CWE-8,C,unverified,applies,nope"]),
            ["CWE-8: unknown strategy \"nope\""]
        );
    }

    #[test]
    fn strategy_check_needs_its_columns() {
        let records = parse_csv("cwe_id,bucket,status\nCWE-1,C,unverified\n").unwrap();
        let ledger = Ledger::from_records_unchecked(records);
        assert_eq!(
            ledger.check_strategies(&[]).err(),
            Some(MissingColumn("rust_applicability"))
        );
    }

    #[test]
    fn real_ledger_round_trips_byte_for_byte() {
        let text = include_str!("../../../ledger/cwe-ledger.csv");
        assert_eq!(write_csv(&parse_csv(text).unwrap()), text);
    }

    #[test]
    fn totals_count_moves_and_phases() {
        let t = ledger(&[GOOD_E, "CWE-2,E,C,why,,,,,,,,unverified"]).totals();
        assert_eq!(t.rows, 2);
        assert_eq!(t.by_bucket.get("E"), Some(&1));
        assert_eq!(t.moves.get("E->C"), Some(&1));
        assert_eq!(t.e_by_phase.get("phase 1 checker"), Some(&1));
    }
}
