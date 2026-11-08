//! Check results.

use std::collections::BTreeMap;
use std::fmt::Write as _;

/// Result of one check.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Status {
    /// The implementation behaved as required.
    Pass,
    /// It did not.
    Fail,
    /// The check did not apply or the implementation does not support it.
    Skip,
}

/// One check's outcome.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Outcome {
    /// Group, e.g. `vie` or `server.transport`.
    pub group: String,
    /// Stable identifier within the group.
    pub id: String,
    /// Result.
    pub status: Status,
    /// What was expected and what happened (for failures and skips).
    pub detail: String,
}

/// All outcomes of a run.
#[derive(Debug, Clone, Default)]
pub struct Report {
    /// Outcomes in the order the checks ran.
    pub outcomes: Vec<Outcome>,
}

impl Report {
    /// Records an outcome.
    pub fn add(
        &mut self,
        group: &str,
        id: impl Into<String>,
        status: Status,
        detail: impl Into<String>,
    ) {
        self.outcomes.push(Outcome {
            group: group.to_owned(),
            id: id.into(),
            status,
            detail: detail.into(),
        });
    }

    /// Records a pass.
    pub fn pass(&mut self, group: &str, id: impl Into<String>) {
        self.add(group, id, Status::Pass, "");
    }

    /// Records a failure.
    pub fn fail(&mut self, group: &str, id: impl Into<String>, detail: impl Into<String>) {
        self.add(group, id, Status::Fail, detail);
    }

    /// Records a skipped check.
    pub fn skip(&mut self, group: &str, id: impl Into<String>, detail: impl Into<String>) {
        self.add(group, id, Status::Skip, detail);
    }

    /// Records `Pass` if `ok`, else `Fail` with `detail`.
    pub fn check(
        &mut self,
        group: &str,
        id: impl Into<String>,
        ok: bool,
        detail: impl Into<String>,
    ) {
        if ok {
            self.pass(group, id);
        } else {
            self.fail(group, id, detail);
        }
    }

    /// Appends another report.
    pub fn extend(&mut self, other: Report) {
        self.outcomes.extend(other.outcomes);
    }

    /// Number of outcomes with `status`.
    pub fn count(&self, status: Status) -> usize {
        self.outcomes.iter().filter(|o| o.status == status).count()
    }

    /// Whether nothing failed.
    pub fn passed(&self) -> bool {
        self.count(Status::Fail) == 0
    }

    /// Human-readable summary: per-group counts, then every failure (and, with
    /// `verbose`, every skip and pass).
    pub fn render(&self, verbose: bool, max_failures: usize) -> String {
        let mut groups: BTreeMap<&str, [usize; 3]> = BTreeMap::new();
        for o in &self.outcomes {
            let g = groups.entry(&o.group).or_default();
            g[o.status as usize] += 1;
        }
        let mut s = String::new();
        let _ = writeln!(
            s,
            "{:<28} {:>7} {:>7} {:>7}",
            "group", "pass", "fail", "skip"
        );
        for (g, [p, f, k]) in &groups {
            let _ = writeln!(s, "{g:<28} {p:>7} {f:>7} {k:>7}");
        }
        let mut shown = 0;
        for o in &self.outcomes {
            let show = match o.status {
                Status::Fail => true,
                _ => verbose,
            };
            if !show {
                continue;
            }
            if o.status == Status::Fail {
                shown += 1;
                if shown > max_failures {
                    continue;
                }
            }
            let tag = match o.status {
                Status::Pass => "PASS",
                Status::Fail => "FAIL",
                Status::Skip => "SKIP",
            };
            let _ = write!(s, "{tag} {} {}", o.group, o.id);
            if !o.detail.is_empty() {
                let _ = write!(s, ": {}", o.detail);
            }
            s.push('\n');
        }
        if shown > max_failures {
            let _ = writeln!(s, "... and {} more failures", shown - max_failures);
        }
        let _ = writeln!(
            s,
            "{} passed, {} failed, {} skipped",
            self.count(Status::Pass),
            self.count(Status::Fail),
            self.count(Status::Skip)
        );
        s
    }
}
