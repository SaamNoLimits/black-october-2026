//! iocmatch — Black October 2026 indicator matcher.
//!
//! DEFENSIVE TOOL. Loads the package IOC list (04_iocs/iocs.csv) and hunts for those
//! indicators in your own data:
//!   - `--logs <file>`  : substring-match text indicators (domains, IPs, URLs, paths, filenames)
//!                        against each line of a log file (or stdin with `-`).
//!   - `--scan <dir>`   : walk a directory, SHA-256 each file, and match file hashes and
//!                        file names against the IOC list.
//!
//! SHA-256 is implemented in-crate (std-only) so the tool builds offline with no dependencies.
//! It never connects anywhere; all matching is local.
//!
//! Usage:
//!   iocmatch --iocs <iocs.csv> --logs <access.log>
//!   iocmatch --iocs <iocs.csv> --scan /path/to/dir
//!   cat access.log | iocmatch --iocs <iocs.csv> --logs -

use std::env;
use std::fs;
use std::io::{self, Read};
use std::path::{Path, PathBuf};
use std::process;

#[derive(Clone)]
struct Ioc {
    indicator: String,
    itype: String,
    case: String,
    context: String,
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut iocs_path = String::from("../../04_iocs/iocs.csv");
    let mut logs: Option<String> = None;
    let mut scan: Option<String> = None;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--iocs" => { i += 1; iocs_path = need(&args, i); }
            "--logs" => { i += 1; logs = Some(need(&args, i)); }
            "--scan" => { i += 1; scan = Some(need(&args, i)); }
            "-h" | "--help" => { help(); return; }
            other => { eprintln!("iocmatch: unknown arg '{}'", other); help(); process::exit(2); }
        }
        i += 1;
    }

    if logs.is_none() && scan.is_none() {
        eprintln!("iocmatch: supply --logs <file|-> and/or --scan <dir>");
        help();
        process::exit(2);
    }

    let iocs = load_iocs(&iocs_path).unwrap_or_else(|e| {
        eprintln!("iocmatch: cannot read iocs '{}': {}", iocs_path, e);
        process::exit(1);
    });
    println!("iocmatch — loaded {} indicators from {}\n", iocs.len(), iocs_path);

    let mut hits = 0usize;

    if let Some(l) = logs {
        hits += scan_logs(&l, &iocs);
    }
    if let Some(d) = scan {
        hits += scan_dir(Path::new(&d), &iocs);
    }

    println!("\nsummary: {} indicator hit(s)", hits);
    if hits > 0 { process::exit(3); }
}

fn need(args: &[String], i: usize) -> String {
    if i >= args.len() { eprintln!("iocmatch: missing value after '{}'", args[i - 1]); process::exit(2); }
    args[i].clone()
}

fn load_iocs(path: &str) -> Result<Vec<Ioc>, io::Error> {
    let text = fs::read_to_string(path)?;
    let mut out = Vec::new();
    for (n, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') { continue; }
        let cols: Vec<&str> = line.split(',').collect();
        if cols.len() < 4 { continue; }
        if n == 0 && cols[0].eq_ignore_ascii_case("indicator") { continue; } // header
        out.push(Ioc {
            indicator: cols[0].trim().to_string(),
            itype: cols[1].trim().to_string(),
            case: cols[2].trim().to_string(),
            context: cols[3].trim().to_string(),
        });
    }
    Ok(out)
}

/// Indicators that make sense to substring-match against a log line.
fn is_text_indicator(t: &str) -> bool {
    matches!(t, "ipv4" | "domain" | "url" | "filepath" | "filename"
                | "container_tag" | "package" | "github_account" | "entra_app_id")
}

fn scan_logs(path: &str, iocs: &[Ioc]) -> usize {
    let content = if path == "-" {
        let mut s = String::new();
        if io::stdin().read_to_string(&mut s).is_err() { return 0; }
        s
    } else {
        match fs::read_to_string(path) {
            Ok(s) => s,
            Err(e) => { eprintln!("iocmatch: cannot read logs '{}': {}", path, e); return 0; }
        }
    };

    let mut hits = 0usize;
    for (lineno, line) in content.lines().enumerate() {
        for ioc in iocs {
            if !is_text_indicator(&ioc.itype) { continue; }
            if ioc.indicator.is_empty() { continue; }
            if line.contains(&ioc.indicator) {
                hits += 1;
                println!("[LOG HIT] {}:{}  <{}> {}  (case {} — {})",
                         path, lineno + 1, ioc.itype, ioc.indicator, ioc.case, ioc.context);
            }
        }
    }
    hits
}

fn scan_dir(root: &Path, iocs: &[Ioc]) -> usize {
    let mut files: Vec<PathBuf> = Vec::new();
    collect_files(root, &mut files);
    println!("scanning {} file(s) under {}", files.len(), root.display());

    // Pre-split IOCs we care about for file scanning.
    let hash_iocs: Vec<&Ioc> = iocs.iter().filter(|i| i.itype == "sha256").collect();
    let name_iocs: Vec<&Ioc> = iocs.iter().filter(|i| i.itype == "filename" || i.itype == "filepath").collect();

    let mut hits = 0usize;
    for f in &files {
        let fname = f.file_name().and_then(|s| s.to_str()).unwrap_or("");
        let fpath = f.to_string_lossy();

        for ioc in &name_iocs {
            // Match on: exact full-path suffix, OR basename equality (so absolute-path IOCs
            // are still found when a collected/exported tree has a different parent path).
            let ind_base = ioc.indicator.rsplit('/').next().unwrap_or(&ioc.indicator);
            let suffix_hit = fpath.ends_with(&ioc.indicator);
            let base_hit = !ind_base.is_empty() && fname == ind_base;
            if suffix_hit || base_hit {
                hits += 1;
                println!("[NAME HIT] {}  <{}> {}  (case {} — {})",
                         fpath, ioc.itype, ioc.indicator, ioc.case, ioc.context);
            }
        }

        if !hash_iocs.is_empty() {
            match fs::read(f) {
                Ok(bytes) => {
                    let digest = sha256_hex(&bytes);
                    for ioc in &hash_iocs {
                        if digest.eq_ignore_ascii_case(&ioc.indicator) {
                            hits += 1;
                            println!("[HASH HIT] {}  sha256 {}  (case {} — {})",
                                     fpath, digest, ioc.case, ioc.context);
                        }
                    }
                }
                Err(_) => { /* skip unreadable */ }
            }
        }
    }
    hits
}

fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let entries = match fs::read_dir(dir) { Ok(e) => e, Err(_) => return };
    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            // Don't follow into VCS / build dirs.
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if matches!(name, ".git" | "target" | "node_modules") { continue; }
            collect_files(&p, out);
        } else if p.is_file() {
            out.push(p);
        }
    }
}

fn help() {
    println!("iocmatch — match Black October 2026 IOCs against your logs and files");
    println!();
    println!("USAGE:");
    println!("  iocmatch --iocs <iocs.csv> --logs <access.log|->");
    println!("  iocmatch --iocs <iocs.csv> --scan <directory>");
    println!();
    println!("Exit code 3 means at least one indicator matched.");
}

// --------------------------------------------------------------------------------------
// Minimal, dependency-free SHA-256 (FIPS 180-4). Correctness covered by the unit test below.
// --------------------------------------------------------------------------------------

const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

fn sha256_hex(data: &[u8]) -> String {
    let mut h: [u32; 8] = [
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
        0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ];

    // Pre-processing (padding).
    let bitlen = (data.len() as u64).wrapping_mul(8);
    let mut msg = data.to_vec();
    msg.push(0x80);
    while msg.len() % 64 != 56 { msg.push(0); }
    msg.extend_from_slice(&bitlen.to_be_bytes());

    for chunk in msg.chunks_exact(64) {
        let mut w = [0u32; 64];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([chunk[i*4], chunk[i*4+1], chunk[i*4+2], chunk[i*4+3]]);
        }
        for i in 16..64 {
            let s0 = w[i-15].rotate_right(7) ^ w[i-15].rotate_right(18) ^ (w[i-15] >> 3);
            let s1 = w[i-2].rotate_right(17) ^ w[i-2].rotate_right(19) ^ (w[i-2] >> 10);
            w[i] = w[i-16].wrapping_add(s0).wrapping_add(w[i-7]).wrapping_add(s1);
        }

        let (mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut hh) =
            (h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7]);

        for i in 0..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let t1 = hh.wrapping_add(s1).wrapping_add(ch).wrapping_add(K[i]).wrapping_add(w[i]);
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let t2 = s0.wrapping_add(maj);
            hh = g; g = f; f = e;
            e = d.wrapping_add(t1);
            d = c; c = b; b = a;
            a = t1.wrapping_add(t2);
        }

        h[0] = h[0].wrapping_add(a); h[1] = h[1].wrapping_add(b);
        h[2] = h[2].wrapping_add(c); h[3] = h[3].wrapping_add(d);
        h[4] = h[4].wrapping_add(e); h[5] = h[5].wrapping_add(f);
        h[6] = h[6].wrapping_add(g); h[7] = h[7].wrapping_add(hh);
    }

    let mut out = String::with_capacity(64);
    for word in &h {
        out.push_str(&format!("{:08x}", word));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn sha256_known_vectors() {
        assert_eq!(sha256_hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855");
        assert_eq!(sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
        assert_eq!(sha256_hex(b"The quick brown fox jumps over the lazy dog"),
            "d7a8fbb307d7809469ca9abcb0082e4f8d5651e46d3cdb762d02d0bf37c9e592");
    }
}
