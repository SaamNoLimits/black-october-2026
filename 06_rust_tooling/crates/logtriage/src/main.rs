//! logtriage — Black October 2026 web/access-log heuristics.
//!
//! DEFENSIVE TOOL. Reads a web/access log (file or stdin) and flags lines that match
//! exploitation *patterns* from the October 2026 cases. These are heuristics for hunting and
//! triage — they surface candidates for a human to review, not confirmed compromise. The tool
//! only reads your log lines; it sends nothing and attacks nothing.
//!
//! Heuristics:
//!   - php2shell   : multipart POST to a .php endpoint (CVE-2026-109618/109619 effect surface)
//!   - oracle-ebs  : request to /OA_HTML/ carrying SQL-injection markers (CVE-2026-101767)
//!   - litellm     : any reference to the litellm.dev exfil domain (Case 04)
//!   - fortigate   : config-download / backup URIs (FortiBleed config-export step)
//!   - webshell    : request to a suspicious lone .php often used as a shell name
//!
//! Usage:
//!   logtriage <access.log>
//!   cat access.log | logtriage -

use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::{self, Read};
use std::process;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 || args[1] == "-h" || args[1] == "--help" {
        help();
        if args.len() < 2 { process::exit(2); }
        return;
    }
    let path = &args[1];

    let content = if path == "-" {
        let mut s = String::new();
        if let Err(e) = io::stdin().read_to_string(&mut s) {
            eprintln!("logtriage: stdin read error: {}", e);
            process::exit(1);
        }
        s
    } else {
        match fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => { eprintln!("logtriage: cannot read '{}': {}", path, e); process::exit(1); }
        }
    };

    let mut counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut flagged = 0usize;

    for (n, line) in content.lines().enumerate() {
        let reasons = classify(line);
        if !reasons.is_empty() {
            flagged += 1;
            for r in &reasons { *counts.entry(r).or_insert(0) += 1; }
            println!("[{}] line {}: {}", reasons.join(","), n + 1, truncate(line, 240));
        }
    }

    println!("\n--- logtriage summary ---");
    println!("source: {}", path);
    println!("flagged lines: {}", flagged);
    for (k, v) in &counts {
        println!("  {:<12} {}", k, v);
    }
    if flagged > 0 { process::exit(3); }
}

fn classify(line: &str) -> Vec<&'static str> {
    let l = line.to_lowercase();
    let mut reasons = Vec::new();

    let is_post = l.contains("post");

    // php2shell: multipart POST to a .php path
    if is_post && l.contains(".php") && l.contains("multipart/form-data") {
        reasons.push("php2shell");
    }

    // oracle-ebs: /OA_HTML/ with SQLi markers
    if l.contains("/oa_html/") && has_sqli_marker(&l) {
        reasons.push("oracle-ebs");
    }

    // litellm exfil domain
    if l.contains("litellm.dev") {
        reasons.push("litellm");
    }

    // fortigate config export / backup endpoints
    if l.contains("/api/v2/monitor/system/config/backup")
        || l.contains("global/system/config/backup")
        || (l.contains("config") && l.contains("backup") && l.contains("fgt"))
    {
        reasons.push("fortigate");
    }

    // webshell-ish filenames frequently seen post-exploit
    for shell in ["/shell.php", "/cmd.php", "/up.php", "/x.php", "/wso.php", "/alfa.php", "/0.php"] {
        if l.contains(shell) {
            reasons.push("webshell");
            break;
        }
    }

    reasons
}

fn has_sqli_marker(l: &str) -> bool {
    let markers = [
        "union select", "union%20select",
        "or 1=1", "or%201=1", "'%20or", "%27%20or", "%27or", "' or",
        "waitfor delay", "waitfor%20delay", "sleep(", "information_schema",
    ];
    markers.iter().any(|m| l.contains(m))
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max { return s.to_string(); }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

fn help() {
    println!("logtriage — flag October 2026 exploitation patterns in a web/access log");
    println!();
    println!("USAGE:");
    println!("  logtriage <access.log>");
    println!("  cat access.log | logtriage -");
    println!();
    println!("Heuristics: php2shell, oracle-ebs, litellm, fortigate, webshell.");
    println!("These surface candidates for review; they are not proof of compromise.");
    println!("Exit code 3 means at least one line was flagged.");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn flags_expected() {
        assert!(classify(
            "1.2.3.4 - - [21/Oct/2026] \"POST /up.php HTTP/1.1\" 200 content-type: multipart/form-data"
        ).contains(&"php2shell"));
        assert!(classify(
            "5.6.7.8 - - \"GET /OA_HTML/x?p=1'%20OR%201=1 HTTP/1.1\" 200"
        ).contains(&"oracle-ebs"));
        assert!(classify("9.9.9.9 - - \"POST /healthcheck HTTP/1.1\" host: litellm.dev")
            .contains(&"litellm"));
        assert!(classify("10.0.0.1 - - \"GET /index.html HTTP/1.1\" 200").is_empty());
    }
}
