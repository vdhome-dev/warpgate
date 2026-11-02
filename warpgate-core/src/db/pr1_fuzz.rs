//! Test branch only: the path `sqlite_url` writes is the file `connect_to_db` opens, whatever the directory is called.
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use sea_orm::sqlx::{Connection, SqliteConnection};

use super::{sqlite_connect_options, sqlite_db_path, sqlite_url};

const SEGMENTS: &[&str] = &[
    "warpgate", "data", "Program Files", "my db", "a%20b", "100%", "x#y", "q?r", "semi;colon", "caf\u{e9}",
    "\u{65e5}\u{672c}", "dot.dir", "with'quote", "plus+sign", "amp&er", "brack[1]", "at@host", "~user", "eq=val",
];

struct XorShift(u64);
impl XorShift {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

fn dir(rng: &mut XorShift, base: &Path, real_files: bool) -> Option<PathBuf> {
    let mut d = base.to_path_buf();
    for _ in 0..=(rng.next() % 3) {
        let s = SEGMENTS[(rng.next() % SEGMENTS.len() as u64) as usize];
        if real_files && cfg!(windows) && s.contains(['?']) {
            return None; // not a legal Windows file name
        }
        d.push(s);
    }
    Some(d)
}

fn category(d: &Path) -> &'static str {
    let s = d.to_string_lossy();
    if !s.is_ascii() {
        "non-ascii"
    } else if s.contains('%') {
        "percent"
    } else if s.contains(['#', '?']) {
        "hash-or-question"
    } else if s.contains(' ') {
        "space"
    } else {
        "other"
    }
}

#[tokio::test]
#[allow(clippy::unwrap_used, clippy::print_stderr)]
async fn pr1_fuzz_paths() {
    let iters: usize = std::env::var("WG_FUZZ_ITERS").ok().and_then(|x| x.parse().ok()).unwrap_or(20_000);
    let temp = std::env::temp_dir().join("pr1 fuzz");
    let bases = [temp.clone(), temp.join("Program Files").join("caf\u{e9}")];
    let mut rng = XorShift(0x9E37_79B9_7F4A_7C15);
    let mut tally: BTreeMap<&str, (usize, usize)> = BTreeMap::new();
    let mut failures = vec![];

    for i in 0..iters {
        let base = &bases[i % bases.len()];
        let d = dir(&mut rng, base, false).unwrap();
        let t = tally.entry(category(&d)).or_default();
        t.0 += 1;
        let got = url::Url::parse(&sqlite_url(&d))
            .map_err(|e| e.to_string())
            .and_then(|u| sqlite_db_path(&u, base).map_err(|e| e.to_string()));
        if got.as_ref().ok() != Some(&d.join("db.sqlite3")) {
            t.1 += 1;
            failures.push(format!("PATH {d:?} -> {got:?}"));
        }
    }

    // Real files on a sample: SQLite must create the database exactly there.
    let (mut opened, mut sample) = (0, 0);
    while sample < 2_000 {
        let base = &bases[sample % bases.len()];
        let Some(d) = dir(&mut rng, base, true) else { continue };
        sample += 1;
        let t = tally.entry("real-file").or_default();
        t.0 += 1;
        let file = d.join("db.sqlite3");
        std::fs::create_dir_all(&d).unwrap();
        let _ = std::fs::remove_file(&file);
        let path = sqlite_db_path(&url::Url::parse(&sqlite_url(&d)).unwrap(), base).unwrap();
        match SqliteConnection::connect_with(&sqlite_connect_options(&path)).await {
            Ok(c) => {
                let _ = c.close().await;
                if file.is_file() {
                    opened += 1;
                } else {
                    t.1 += 1;
                    failures.push(format!("MISSING {file:?}, opened {path:?}"));
                }
            }
            Err(e) => {
                t.1 += 1;
                failures.push(format!("OPEN {file:?}: {e}"));
            }
        }
    }

    for (k, (n, f)) in &tally {
        eprintln!("TALLY {k}: {f} of {n} failed");
    }
    eprintln!("real files opened: {opened} of {sample}");
    for f in failures.iter().take(20) {
        eprintln!("{f}");
    }
    let _ = std::fs::remove_dir_all(&temp);
    assert!(failures.is_empty(), "{} failures", failures.len());
}
