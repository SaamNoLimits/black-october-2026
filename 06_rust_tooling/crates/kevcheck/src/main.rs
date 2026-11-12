//! kevcheck — Black October 2026 vulnerability-management triage.
//!
//! DEFENSIVE TOOL. Compares your own asset inventory against a ruleset of October 2026
//! fixed versions and flags assets running below the fix. It does not touch any target,
//! send any traffic, or run any exploit — it is pure local version arithmetic.
//!
//! Usage:
//!   kevcheck --rules <rules.tsv> --inventory <inventory.csv> [--only-vuln]
//! Defaults (relative to the workspace):
//!   --rules      ../../data/october2026_kev.tsv
//!   --inventory  ../../data/sample_inventory.csv
//!
//! Ruleset TSV columns (tab-separated; lines starting with '#' ignored):
//!   product_key <TAB> cve <TAB> fixed_version <TAB> severity <TAB> note
//! Inventory CSV columns (comma-separated; header auto-skipped if present):
//!   asset_id , product_key , version
//!
//! product_key ties the two files together (e.g. "php-8.3", "cisco-ftd-7.4", "gitlab-19.4").
//! Keep each product on a single fix "train" so version comparison is apples-to-apples.

use std::collections::HashMap;
use std::env;
use std::fs;
use std::process;

#[derive(Clone)]
struct Rule {
    cve: String,
    fixed: String,
    severity: String,
    note: String,
}

struct Asset {
    id: String,
    product: String,
    version: String,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut rules_path = String::from("../../data/october2026_kev.tsv");
    let mut inv_path = String::from("../../data/sample_inventory.csv");
    let mut only_vuln = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--rules" => { i += 1; rules_path = arg_value(&args, i); }
            "--inventory" => { i += 1; inv_path = arg_value(&args, i); }
            "--only-vuln" => { only_vuln = true; }
            "-h" | "--help" => { print_help(); return; }
            other => { eprintln!("kevcheck: unknown argument '{}'", other); print_help(); process::exit(2); }
        }
        i += 1;
    }

    let rules = load_rules(&rules_path).unwrap_or_else(|e| {
        eprintln!("kevcheck: failed to read rules '{}': {}", rules_path, e);
        process::exit(1);
    });
    let assets = load_inventory(&inv_path).unwrap_or_else(|e| {
        eprintln!("kevcheck: failed to read inventory '{}': {}", inv_path, e);
        process::exit(1);
    });

    println!("kevcheck — Black October 2026 triage");
    println!("rules: {}  ({} product keys)", rules_path, rules.len());
    println!("inventory: {}  ({} assets)\n", inv_path, assets.len());

    let mut vuln = 0usize;
    let mut ok = 0usize;
    let mut unknown = 0usize;

    for a in &assets {
        let key = a.product.to_lowercase();
        match rules.get(&key) {
            Some(rule_list) => {
                for r in rule_list {
                    let cmp = cmp_version(&a.version, &r.fixed);
                    if cmp < 0 {
                        vuln += 1;
                        println!("[VULNERABLE] {:<18} {:<16} {} < fixed {}  {}  ({})",
                                 a.id, a.product, a.version, r.fixed, r.cve, r.severity);
                        if !r.note.is_empty() {
                            println!("             action: {}", r.note);
                        }
                    } else if !only_vuln {
                        ok += 1;
                        println!("[ok]         {:<18} {:<16} {} >= fixed {}  {}",
                                 a.id, a.product, a.version, r.fixed, r.cve);
                    } else {
                        ok += 1;
                    }
                }
            }
            None => {
                unknown += 1;
                if !only_vuln {
                    println!("[no-rule]    {:<18} {:<16} {}  (no October rule for this product key)",
                             a.id, a.product, a.version);
                }
            }
        }
    }

    println!("\nsummary: {} vulnerable, {} ok, {} with no matching rule", vuln, ok, unknown);
    if vuln > 0 {
        println!("NOTE: version arithmetic is a triage aid. Confirm against the vendor advisory and CISA KEV before closing.");
        process::exit(3); // non-zero so CI can gate on findings
    }
}

fn arg_value(args: &[String], i: usize) -> String {
    if i >= args.len() {
        eprintln!("kevcheck: missing value after '{}'", args[i - 1]);
        process::exit(2);
    }
    args[i].clone()
}

fn load_rules(path: &str) -> Result<HashMap<String, Vec<Rule>>, std::io::Error> {
    let text = fs::read_to_string(path)?;
    let mut map: HashMap<String, Vec<Rule>> = HashMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let cols: Vec<&str> = line.split('\t').collect();
        if cols.len() < 3 { continue; }
        let key = cols[0].trim().to_lowercase();
        let rule = Rule {
            cve: cols[1].trim().to_string(),
            fixed: cols[2].trim().to_string(),
            severity: cols.get(3).map(|s| s.trim().to_string()).unwrap_or_default(),
            note: cols.get(4).map(|s| s.trim().to_string()).unwrap_or_default(),
        };
        map.entry(key).or_default().push(rule);
    }
    Ok(map)
}

fn load_inventory(path: &str) -> Result<Vec<Asset>, std::io::Error> {
    let text = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 3 { continue; }
        // Skip a header row if present.
        if n == 0 && cols[2].trim().eq_ignore_ascii_case("version") { continue; }
        out.push(Asset {
            id: cols[0].trim().to_string(),
            product: cols[1].trim().to_string(),
            version: cols[2].trim().to_string(),
        });
    }
    Ok(out)
}

/// Compare dotted versions numerically, component by component.
/// Returns -1 if a < b, 0 if equal, 1 if a > b. Non-digit characters within a
/// component are ignored after the leading number (e.g. "7.4.9p1" -> 7,4,9).
fn cmp_version(a: &str, b: &str) -> i32 {
    let va = parse_version(a);
    let vb = parse_version(b);
    let n = va.len().max(vb.len());
    for i in 0..n {
        let x = *va.get(i).unwrap_or(&0);
        let y = *vb.get(i).unwrap_or(&0);
        if x < y { return -1; }
        if x > y { return 1; }
    }
    0
}

fn parse_version(v: &str) -> Vec<u64> {
    v.split(|c: char| c == '.' || c == '-' || c == '_')
        .map(|part| {
            let digits: String = part.chars().take_while(|c| c.is_ascii_digit()).collect();
            digits.parse::<u64>().unwrap_or(0)
        })
        .collect()
}

fn print_help() {
    println!("kevcheck — compare an asset inventory against October 2026 fixed-version rules");
    println!();
    println!("USAGE:");
    println!("  kevcheck --rules <rules.tsv> --inventory <inventory.csv> [--only-vuln]");
    println!();
    println!("Exit code 3 means at least one asset is below its fixed version (useful in CI).");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn versions() {
        assert_eq!(cmp_version("8.3.35", "8.3.36"), -1);
        assert_eq!(cmp_version("8.3.36", "8.3.36"), 0);
        assert_eq!(cmp_version("8.4.0", "8.3.36"), 1);
        assert_eq!(cmp_version("9.18.4.95", "9.18.4.96"), -1);
        assert_eq!(cmp_version("7.4.9p1", "7.4.9"), 0);
        assert_eq!(cmp_version("19.4.1", "19.4.2"), -1);
    }
}
