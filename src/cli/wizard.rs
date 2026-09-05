//! Ask common options and write a minimal config file.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};

use anyhow::{bail, Context as _};

use crate::argument::WizardArgs;
use crate::config::{
    self, FetchSection, FileConfig, GlobalSection, OutputSection, ValidateSection,
};
use crate::RunOutcome;

// Mirror CLI defaults so generated files only carry changed values.
const DEFAULT_FORMAT: &str = "default";
const DEFAULT_LIMIT: usize = 0;
const DEFAULT_CACHE_TTL: u64 = 15;
const DEFAULT_TYPES: &[&str] = &["HTTP"];

/// Collect answers from questions or `--yes` defaults.
#[derive(Debug, Clone, PartialEq)]
struct Answers {
    providers: Vec<String>,
    countries: Vec<String>,
    format: String,
    limit: usize,
    min_anonymity: Option<String>,
    types: Vec<String>,
    cache_ttl: u64,
    quiet: bool,
}

impl Default for Answers {
    fn default() -> Self {
        Self {
            providers: Vec::new(),
            countries: Vec::new(),
            format: DEFAULT_FORMAT.to_owned(),
            limit: DEFAULT_LIMIT,
            min_anonymity: None,
            types: DEFAULT_TYPES.iter().map(|s| (*s).to_owned()).collect(),
            cache_ttl: DEFAULT_CACHE_TTL,
            quiet: false,
        }
    }
}

fn formats_hint() -> String {
    config::FORMATS.join(", ")
}

fn anonymity_hint() -> String {
    config::ANONYMITY_LEVELS.join(", ")
}

pub fn run_wizard<R: BufRead, W: Write>(
    args: WizardArgs,
    home: &Path,
    cwd: &Path,
    reader: &mut R,
    writer: &mut W,
) -> anyhow::Result<RunOutcome> {
    let interactive = !args.yes;
    let target = resolve_target(&args, home, cwd, reader, writer)?;
    let answers = if args.yes {
        Answers::default()
    } else {
        run_questions(reader, writer)?
    };
    validate(&answers)?;
    let text = config::to_toml(&build_config(&answers));
    config::parse(&text).context("generated config failed to re-parse")?;

    if target.exists() && !args.force {
        if args.yes {
            bail!(
                "config file already exists at {} (use --force to overwrite)",
                target.display()
            );
        }
        if !ask_yn(
            reader,
            writer,
            "Config file already exists. Overwrite",
            false,
        )? {
            writeln!(writer, "aborted")?;
            return Ok(RunOutcome::Finished);
        }
    }
    if interactive
        && !ask_yn(
            reader,
            writer,
            &format!("Write config to {}", target.display()),
            true,
        )?
    {
        writeln!(writer, "aborted")?;
        return Ok(RunOutcome::Finished);
    }
    write_config(&target, &text)?;
    writeln!(writer, "wrote config to {}", target.display())?;
    Ok(RunOutcome::Finished)
}

fn resolve_target<R: BufRead, W: Write>(
    args: &WizardArgs,
    home: &Path,
    cwd: &Path,
    reader: &mut R,
    writer: &mut W,
) -> anyhow::Result<PathBuf> {
    if let Some(path) = &args.path {
        return Ok(path.clone());
    }
    if args.user {
        return Ok(home.join("flx").join("config.toml"));
    }
    let project = cwd.join(".flx.toml");
    if args.yes {
        return Ok(project);
    }
    let user = home.join("flx").join("config.toml");
    writeln!(writer, "Where should the config be written?")?;
    writeln!(writer, "  [1] {} (project)", project.display())?;
    writeln!(writer, "  [2] {} (user)", user.display())?;
    let choice = ask(reader, writer, "Choice", "1")?;
    Ok(if choice.trim() == "2" { user } else { project })
}

fn run_questions<R: BufRead, W: Write>(reader: &mut R, writer: &mut W) -> anyhow::Result<Answers> {
    let providers_raw = ask(
        reader,
        writer,
        "Providers to scrape, comma-separated ('all' = every provider)",
        "all",
    )?;
    let providers = if providers_raw.eq_ignore_ascii_case("all") {
        Vec::new()
    } else {
        split_list(&providers_raw)
    };

    let countries_raw = ask(
        reader,
        writer,
        "Country codes to keep, comma-separated ('all' = no filter)",
        "all",
    )?;
    let countries = if countries_raw.eq_ignore_ascii_case("all") {
        Vec::new()
    } else {
        split_list(&countries_raw)
            .into_iter()
            .map(|c| c.to_uppercase())
            .collect()
    };

    let format = ask(
        reader,
        writer,
        &format!("Output format ({})", formats_hint()),
        DEFAULT_FORMAT,
    )?;
    let limit = ask(
        reader,
        writer,
        "Maximum number of results (0 = unlimited)",
        "0",
    )?
    .parse::<usize>()
    .context("limit must be a number")?;

    let anonymity_raw = ask(
        reader,
        writer,
        &format!(
            "Minimum anonymity ({}; 'none' = no filter)",
            anonymity_hint()
        ),
        "none",
    )?;
    let min_anonymity = if anonymity_raw.eq_ignore_ascii_case("none") || anonymity_raw.is_empty() {
        None
    } else {
        Some(anonymity_raw)
    };

    let types = split_list(&ask(
        reader,
        writer,
        "Proxy types to validate, comma-separated (e.g. HTTP, SOCKS5, HTTP:Elite)",
        "HTTP",
    )?)
    .into_iter()
    .map(|t| t.to_uppercase())
    .collect();

    let cache_ttl = ask(reader, writer, "Cache freshness in minutes", "15")?
        .parse::<u64>()
        .context("cache TTL must be a number")?;

    let quiet = ask_yn(reader, writer, "Suppress non-essential output", false)?;

    Ok(Answers {
        providers,
        countries,
        format,
        limit,
        min_anonymity,
        types,
        cache_ttl,
        quiet,
    })
}

/// Build a config listing only non-default values.
fn build_config(a: &Answers) -> FileConfig {
    let mut cfg = FileConfig::default();
    if a.quiet {
        cfg.global = Some(GlobalSection {
            quiet: Some(true),
            ..Default::default()
        });
    }
    let mut fetch = FetchSection::default();
    if !a.providers.is_empty() {
        fetch.providers = Some(a.providers.clone());
    }
    if !a.countries.is_empty() {
        fetch.countries = Some(a.countries.clone());
    }
    if a.cache_ttl != DEFAULT_CACHE_TTL {
        fetch.cache_ttl = Some(a.cache_ttl);
    }
    if fetch.providers.is_some() || fetch.countries.is_some() || fetch.cache_ttl.is_some() {
        cfg.fetch = Some(fetch);
    }
    let mut output = OutputSection::default();
    if a.format != DEFAULT_FORMAT {
        output.format = Some(a.format.clone());
    }
    if a.limit != DEFAULT_LIMIT {
        output.limit = Some(a.limit);
    }
    if let Some(level) = &a.min_anonymity {
        output.min_anonymity = Some(level.clone());
    }
    if output.format.is_some() || output.limit.is_some() || output.min_anonymity.is_some() {
        cfg.output = Some(output);
    }
    if a.types
        != DEFAULT_TYPES
            .iter()
            .map(|s| (*s).to_owned())
            .collect::<Vec<_>>()
    {
        cfg.validate = Some(ValidateSection {
            types: Some(a.types.clone()),
            ..Default::default()
        });
    }
    cfg
}

/// Reject answers that would fail at config load time.
fn validate(a: &Answers) -> anyhow::Result<()> {
    if a.format != DEFAULT_FORMAT && !config::FORMATS.contains(&a.format.as_str()) {
        bail!(
            "unknown output format `{}` (allowed: {})",
            a.format,
            formats_hint()
        );
    }
    if let Some(level) = &a.min_anonymity {
        if !config::ANONYMITY_LEVELS.contains(&level.as_str()) {
            bail!(
                "unknown anonymity level `{level}` (allowed: {})",
                anonymity_hint()
            );
        }
    }
    for token in &a.types {
        if !crate::argument::is_valid_type_value(token) {
            bail!("invalid proxy type `{token}`");
        }
    }
    let known: Vec<String> = flx::all_providers()
        .into_iter()
        .map(|p| p.name().to_owned())
        .collect();
    for provider in &a.providers {
        if !known.iter().any(|k| k.eq_ignore_ascii_case(provider)) {
            bail!(
                "unknown provider `{provider}` (known: {})",
                known.join(", ")
            );
        }
    }
    Ok(())
}

fn write_config(target: &Path, text: &str) -> anyhow::Result<()> {
    if let Some(parent) = target.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(target, text)?;
    Ok(())
}

fn split_list(s: &str) -> Vec<String> {
    s.split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .map(str::to_owned)
        .collect()
}

fn ask<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    prompt: &str,
    default: &str,
) -> anyhow::Result<String> {
    write!(writer, "{prompt} [{default}]: ")?;
    writer.flush()?;
    let mut line = String::new();
    reader.read_line(&mut line)?;
    let trimmed = line.trim().to_owned();
    Ok(if trimmed.is_empty() {
        default.to_owned()
    } else {
        trimmed
    })
}

fn ask_yn<R: BufRead, W: Write>(
    reader: &mut R,
    writer: &mut W,
    prompt: &str,
    default: bool,
) -> anyhow::Result<bool> {
    let answer = ask(reader, writer, prompt, if default { "y" } else { "n" })?;
    Ok(match answer.to_lowercase().as_str() {
        "y" | "yes" | "1" | "true" => true,
        "n" | "no" | "0" | "false" => false,
        _ => default,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;
    use std::sync::atomic::{AtomicU64, Ordering};

    fn unique_dir(stem: &str) -> PathBuf {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        std::env::temp_dir().join(format!(
            "flx_wizard_{stem}_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn run_wizard_with(
        input: &str,
        args: WizardArgs,
        dir: &Path,
    ) -> anyhow::Result<(RunOutcome, String)> {
        let home = dir.join("xdg");
        let cwd = dir.join("work");
        let mut reader = Cursor::new(input.as_bytes().to_vec());
        let mut writer = Vec::new();
        let outcome = run_wizard(args, &home, &cwd, &mut reader, &mut writer)?;
        Ok((outcome, String::from_utf8(writer).unwrap()))
    }

    #[test]
    fn yes_writes_minimal_project_config() {
        let dir = unique_dir("yes_minimal");
        let (outcome, _) = run_wizard_with(
            "",
            WizardArgs {
                yes: true,
                ..Default::default()
            },
            &dir,
        )
        .unwrap();
        assert_eq!(outcome, RunOutcome::Finished);
        let text = std::fs::read_to_string(dir.join("work/.flx.toml")).unwrap();
        assert!(text.contains("# no config values set"), "{text}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn yes_existing_file_requires_force() {
        let dir = unique_dir("yes_exists");
        let cwd = dir.join("work");
        std::fs::create_dir_all(&cwd).unwrap();
        std::fs::write(cwd.join(".flx.toml"), "old").unwrap();
        let error = run_wizard_with(
            "",
            WizardArgs {
                yes: true,
                ..Default::default()
            },
            &dir,
        )
        .unwrap_err();
        assert!(error.to_string().contains("already exists"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn yes_force_overwrites_existing_file() {
        let dir = unique_dir("yes_force");
        let path = dir.join("custom.toml");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(&path, "old").unwrap();
        let args = WizardArgs {
            yes: true,
            force: true,
            path: Some(path.clone()),
            ..Default::default()
        };
        let (outcome, _) = run_wizard_with("", args, &dir).unwrap();
        assert_eq!(outcome, RunOutcome::Finished);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(!text.contains("old"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn interactive_answers_land_in_the_written_toml() {
        let dir = unique_dir("interactive");
        let path = dir.join("wiz.toml");
        let input = "geonode\nus, de\ncsv\n50\nelite\nsocks5\n30\ny\ny\n";
        let args = WizardArgs {
            path: Some(path.clone()),
            ..Default::default()
        };
        let (outcome, _) = run_wizard_with(input, args, &dir).unwrap();
        assert_eq!(outcome, RunOutcome::Finished);
        let text = std::fs::read_to_string(&path).unwrap();
        let cfg = config::parse(&text).unwrap();
        let fetch = cfg.fetch.unwrap();
        assert_eq!(
            fetch.providers.as_deref(),
            Some(&["geonode".to_owned()][..])
        );
        assert_eq!(
            fetch.countries.as_deref(),
            Some(&["US".to_owned(), "DE".to_owned()][..])
        );
        assert_eq!(fetch.cache_ttl, Some(30));
        let output = cfg.output.unwrap();
        assert_eq!(output.format.as_deref(), Some("csv"));
        assert_eq!(output.limit, Some(50));
        assert_eq!(output.min_anonymity.as_deref(), Some("elite"));
        let validate = cfg.validate.unwrap();
        assert_eq!(validate.types.as_deref(), Some(&["SOCKS5".to_owned()][..]));
        assert_eq!(cfg.global.unwrap().quiet, Some(true));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn interactive_aborts_on_declined_confirm() {
        let dir = unique_dir("abort");
        let path = dir.join("wiz.toml");
        let input = "\n\n\n\n\n\n\n\nn\n";
        let args = WizardArgs {
            path: Some(path.clone()),
            ..Default::default()
        };
        let (outcome, _) = run_wizard_with(input, args, &dir).unwrap();
        assert_eq!(outcome, RunOutcome::Finished);
        assert!(!path.exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn defaults_answer_without_typed_input() {
        let mut reader = Cursor::new(Vec::<u8>::new());
        let mut writer = Vec::new();
        let answers = run_questions(&mut reader, &mut writer).unwrap();
        assert_eq!(answers, Answers::default());
    }

    #[test]
    fn build_config_defaults_are_minimal() {
        let cfg = build_config(&Answers::default());
        assert!(cfg.global.is_none());
        assert!(cfg.fetch.is_none());
        assert!(cfg.output.is_none());
        assert!(cfg.validate.is_none());
    }

    #[test]
    fn build_config_skips_default_values() {
        let answers = Answers {
            providers: vec!["geonode".to_owned()],
            countries: vec!["US".to_owned()],
            cache_ttl: 15, // default: must not be written
            ..Default::default()
        };
        let cfg = build_config(&answers);
        let fetch = cfg.fetch.unwrap();
        assert_eq!(fetch.cache_ttl, None);
        assert_eq!(
            fetch.providers.as_deref(),
            Some(&["geonode".to_owned()][..])
        );
    }

    #[test]
    fn split_list_trims_and_drops_empty() {
        assert_eq!(split_list(" a, b ,, c "), vec!["a", "b", "c"]);
        assert!(split_list("").is_empty());
        assert!(split_list(",").is_empty());
    }

    #[test]
    fn validate_rejects_bad_format() {
        let err = validate(&Answers {
            format: "bogus".into(),
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.to_string().contains("unknown output format"));
    }

    #[test]
    fn validate_rejects_bad_anonymity() {
        let err = validate(&Answers {
            min_anonymity: Some("super".into()),
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.to_string().contains("unknown anonymity level"));
    }

    #[test]
    fn validate_rejects_bad_type() {
        let err = validate(&Answers {
            types: vec!["NOPE".into()],
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.to_string().contains("invalid proxy type"));
    }

    #[test]
    fn validate_rejects_unknown_provider() {
        let err = validate(&Answers {
            providers: vec!["nope-provider".into()],
            ..Default::default()
        })
        .unwrap_err();
        assert!(err.to_string().contains("unknown provider"));
    }

    #[test]
    fn resolve_target_path_flag() {
        let dir = unique_dir("resolve_path");
        let args = WizardArgs {
            path: Some(dir.join("x.toml")),
            ..Default::default()
        };
        let mut reader = Cursor::new(Vec::new());
        let mut writer = Vec::new();
        let target = resolve_target(&args, &dir, &dir, &mut reader, &mut writer).unwrap();
        assert_eq!(target, dir.join("x.toml"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_target_user_flag() {
        let dir = unique_dir("resolve_user");
        let args = WizardArgs {
            user: true,
            ..Default::default()
        };
        let mut reader = Cursor::new(Vec::new());
        let mut writer = Vec::new();
        let target = resolve_target(&args, &dir, &dir, &mut reader, &mut writer).unwrap();
        assert_eq!(target, dir.join("flx").join("config.toml"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_target_yes_flag() {
        let dir = unique_dir("resolve_yes");
        let args = WizardArgs {
            yes: true,
            ..Default::default()
        };
        let mut reader = Cursor::new(Vec::new());
        let mut writer = Vec::new();
        let target = resolve_target(&args, &dir, &dir, &mut reader, &mut writer).unwrap();
        assert_eq!(target, dir.join(".flx.toml"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_target_interactive_choice_2() {
        let dir = unique_dir("resolve_choice2");
        let args = WizardArgs::default();
        let mut reader = Cursor::new(b"2\n" as &[u8]);
        let mut writer = Vec::new();
        let target = resolve_target(&args, &dir, &dir, &mut reader, &mut writer).unwrap();
        assert_eq!(target, dir.join("flx").join("config.toml"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
