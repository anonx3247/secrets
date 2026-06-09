//! Install the sx usage skill into AI coding agents' skills directories.
//!
//! All three supported agents implement the Agent Skills standard (`SKILL.md`
//! with `name`/`description` frontmatter, loaded by progressive disclosure);
//! only the directory differs:
//!   * Claude Code — `~/.claude/skills/sx/SKILL.md`
//!   * Codex — `~/.codex/skills/sx/SKILL.md`
//!   * Pi — `~/.pi/agent/skills/sx/SKILL.md`
//!
//! The `sx` skill name matches its parent directory, as the standard requires.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

/// The full `SKILL.md` (frontmatter + instructions), embedded at compile time.
const SKILL_MD: &str = include_str!("../../../SKILL.md");

/// Which agents to (un)install for. No flag set means "all of them".
#[derive(Clone, Copy)]
pub struct Targets {
    pub claude: bool,
    pub codex: bool,
    pub pi: bool,
}

impl Targets {
    fn resolved(self) -> Targets {
        if self.claude || self.codex || self.pi {
            self
        } else {
            Targets {
                claude: true,
                codex: true,
                pi: true,
            }
        }
    }

    /// (label, skill-file path) for each selected agent.
    fn paths(self, home: &Path) -> Vec<(&'static str, PathBuf)> {
        let mut out = Vec::new();
        if self.claude {
            out.push(("Claude Code", home.join(".claude/skills/sx/SKILL.md")));
        }
        if self.codex {
            out.push(("Codex", home.join(".codex/skills/sx/SKILL.md")));
        }
        if self.pi {
            out.push(("Pi", home.join(".pi/agent/skills/sx/SKILL.md")));
        }
        out
    }
}

fn home() -> io::Result<PathBuf> {
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "$HOME is not set"))
}

pub fn install(targets: Targets, dry_run: bool) -> io::Result<()> {
    let home = home()?;
    for (label, path) in targets.resolved().paths(&home) {
        if dry_run {
            println!("{label}: would write {}", path.display());
            continue;
        }
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::write(&path, SKILL_MD)?;
        println!("{label}: wrote {}", path.display());
    }
    if dry_run {
        println!("\n(dry run — nothing written)");
    } else {
        println!("\nRestart any running agent session to pick up the skill.");
    }
    Ok(())
}

pub fn uninstall(targets: Targets) -> io::Result<()> {
    let home = home()?;
    for (label, path) in targets.resolved().paths(&home) {
        if fs::remove_file(&path).is_ok() {
            // Remove the now-empty `sx/` skill dir if nothing else is in it.
            if let Some(parent) = path.parent() {
                let _ = fs::remove_dir(parent);
            }
            println!("{label}: removed {}", path.display());
        } else {
            println!("{label}: nothing to remove ({})", path.display());
        }
    }
    Ok(())
}
