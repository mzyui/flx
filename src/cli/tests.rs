use super::argument::OutputOptions;
use super::filters::ProxyFilter;
use super::*;
use clap::Parser;
use flx::proxy::models::Anonymity;
use futures_util::stream;

fn fetch_from(args: &[&str]) -> FetchArgs {
    let mut full = vec!["flx", "grab"];
    full.extend_from_slice(args);
    match Cli::parse_from(full).command {
        Some(Command::Grab(grab)) => grab,
        _ => panic!("expected a grab subcommand"),
    }
}

fn find_from(args: &[&str]) -> FindArgs {
    let mut full = vec!["flx", "find"];
    full.extend_from_slice(args);
    match Cli::parse_from(full).command {
        Some(Command::Find(find)) => find,
        _ => panic!("expected a find subcommand"),
    }
}

#[test]
fn bare_flx_has_no_subcommand() {
    // A bare invocation parses with no command; `run_application` turns
    // that into a help message instead of an implicit run.
    let cli = Cli::parse_from(["flx"]);
    assert!(cli.command.is_none());
}

#[test]
fn bare_flx_rejects_fetch_flags() {
    // Fetch-only flags must be spelled `flx grab ...`; a bare invocation
    // that carries no subcommand cannot carry subcommand-scoped flags.
    assert!(Cli::try_parse_from(["flx", "--dry-run"]).is_err());
}

#[test]
fn countries_enable_geo_lookup_for_fetcher() {
    let without_countries = fetch_from(&[]);
    assert!(!fetcher_config(&without_countries.fetcher).enable_geo_lookup);

    let with_countries = fetch_from(&["--countries", "ID"]);
    assert!(fetcher_config(&with_countries.fetcher).enable_geo_lookup);
}

#[test]
fn with_geo_enables_geo_lookup_without_country_filter() {
    let geo_only = fetch_from(&["--with-geo"]);
    let config = fetcher_config(&geo_only.fetcher);
    assert!(config.enable_geo_lookup);
    assert!(config.countries.is_empty());

    let combined = fetch_from(&["--with-geo", "--countries", "ID"]);
    let config = fetcher_config(&combined.fetcher);
    assert!(config.enable_geo_lookup);
    assert_eq!(config.countries.as_ref(), ["ID".to_owned()]);
}

#[test]
fn with_ip_type_enables_detection_without_filter() {
    let ip_type_only = fetch_from(&["--with-ip-type"]);
    let config = fetcher_config(&ip_type_only.fetcher);
    assert!(config.enable_geo_lookup);
    assert!(config.enable_ip_type);
    assert_eq!(config.ip_type_filter, None);
}

#[test]
fn ip_type_filter_parses_and_implies_detection() {
    let filtered = fetch_from(&["--ip-type", "residential"]);
    let config = fetcher_config(&filtered.fetcher);
    assert!(config.enable_geo_lookup);
    assert!(config.enable_ip_type);
    assert_eq!(config.ip_type_filter, Some(flx::IpType::Residential));
}

#[test]
fn invalid_ip_type_value_is_rejected() {
    assert!(Cli::try_parse_from(["flx", "find", "--ip-type", "bogus"]).is_err());
}

#[test]
fn cache_ttl_maps_to_minutes_and_zero_disables() {
    let enabled = fetch_from(&["--cache-ttl", "10"]);
    assert_eq!(
        fetcher_config(&enabled.fetcher).cache_ttl,
        Some(std::time::Duration::from_secs(600))
    );

    let disabled = fetch_from(&["--cache-ttl", "0"]);
    assert_eq!(fetcher_config(&disabled.fetcher).cache_ttl, None);

    let default = fetch_from(&[]);
    assert_eq!(
        fetcher_config(&default.fetcher).cache_ttl,
        Some(std::time::Duration::from_secs(900))
    );
}

#[test]
fn refresh_cache_flag_bypasses_cache() {
    let refreshed = fetch_from(&["--refresh-cache"]);
    assert!(fetcher_config(&refreshed.fetcher).refresh_cache);

    let default = fetch_from(&[]);
    assert!(fetcher_config(&default.fetcher).providers.is_empty());
    assert!(fetcher_config(&default.fetcher)
        .excluded_providers
        .is_empty());
}

#[test]
fn source_url_flag_lands_in_fetcher_config() {
    let args = fetch_from(&[
        "--source-url",
        "http://127.0.0.1:9999/a.txt",
        "--source-url",
        "http://127.0.0.1:9999/b.txt",
    ]);
    assert_eq!(
        fetcher_config(&args.fetcher).custom_sources.as_ref(),
        [
            "http://127.0.0.1:9999/a.txt".to_owned(),
            "http://127.0.0.1:9999/b.txt".to_owned()
        ]
    );
}

#[test]
fn offline_flag_lands_in_fetcher_config() {
    assert!(fetch_from(&["--offline"]).fetcher.offline);
    assert!(!fetch_from(&[]).fetcher.offline);
}

#[test]
fn fetch_delay_flag_lands_in_fetcher_config() {
    let set = fetch_from(&["--fetch-delay-ms", "250"]);
    assert_eq!(
        fetcher_config(&set.fetcher).fetch_delay,
        Some(std::time::Duration::from_millis(250))
    );

    let default = fetch_from(&[]);
    assert_eq!(fetcher_config(&default.fetcher).fetch_delay, None);
}

#[test]
fn fallback_threshold_flag_lands_in_fetcher_config() {
    let set = fetch_from(&["--fallback-threshold", "10"]);
    assert_eq!(fetcher_config(&set.fetcher).fallback_threshold, Some(10));

    let default = fetch_from(&[]);
    assert_eq!(fetcher_config(&default.fetcher).fallback_threshold, None);
}

#[test]
fn fetch_phase_timeout_flag_lands_in_fetcher_config() {
    let set = fetch_from(&["--fetch-phase-timeout", "5"]);
    assert_eq!(
        fetcher_config(&set.fetcher).fallback_phase_timeout,
        Some(std::time::Duration::from_secs(5))
    );

    let default = fetch_from(&[]);
    assert_eq!(
        fetcher_config(&default.fetcher).fallback_phase_timeout,
        Some(std::time::Duration::from_secs(30))
    );

    let unbounded = fetch_from(&["--fetch-phase-timeout", "0"]);
    assert_eq!(
        fetcher_config(&unbounded.fetcher).fallback_phase_timeout,
        None
    );
}

#[test]
fn provider_timeout_flag_lands_in_fetcher_config() {
    let set = fetch_from(&["--provider-timeout", "7"]);
    assert_eq!(
        fetcher_config(&set.fetcher).provider_timeout,
        Some(std::time::Duration::from_secs(7))
    );

    let default = fetch_from(&[]);
    assert_eq!(fetcher_config(&default.fetcher).provider_timeout, None);
}

#[test]
fn retry_delay_flag_lands_in_validator_config() {
    let set = find_from(&["--retry-delay-ms", "250"]);
    assert_eq!(
        validator_config(&set.validator, vec![], Vec::new(), false).retry_delay,
        std::time::Duration::from_millis(250)
    );

    let default = find_from(&[]);
    assert_eq!(
        validator_config(&default.validator, vec![], Vec::new(), false).retry_delay,
        std::time::Duration::ZERO
    );
}

#[test]
fn report_failures_flag_lands_in_validator_config() {
    let set = find_from(&["--report-failures", "failures.jsonl"]);
    assert!(validator_config(&set.validator, vec![], Vec::new(), false).report_failures);

    let default = find_from(&[]);
    assert!(!validator_config(&default.validator, vec![], Vec::new(), false).report_failures);
}

#[test]
fn needs_missed_probe_mirrors_validator_gating() {
    let http = Proxy::with_expected_types(
        std::net::Ipv4Addr::LOCALHOST,
        1111,
        std::sync::Arc::from([Protocol::Http(Anonymity::Unknown)]),
    );
    assert!(!needs_missed_probe(
        &http,
        &[Protocol::Http(Anonymity::Unknown)]
    ));
    assert!(!needs_missed_probe(
        &http,
        &[Protocol::Http(Anonymity::Elite)]
    ));
    assert!(needs_missed_probe(&http, &[Protocol::Socks5]));

    let empty = Proxy::with_expected_types(
        std::net::Ipv4Addr::LOCALHOST,
        1111,
        std::sync::Arc::from([]),
    );
    assert!(needs_missed_probe(
        &empty,
        &[Protocol::Http(Anonymity::Unknown)]
    ));

    let mixed = Proxy::with_expected_types(
        std::net::Ipv4Addr::LOCALHOST,
        1111,
        std::sync::Arc::from([Protocol::Http(Anonymity::Unknown), Protocol::Socks5]),
    );
    assert!(!needs_missed_probe(&mixed, &[Protocol::Socks5]));
    assert!(needs_missed_probe(&mixed, &[Protocol::Connect(9)]));

    let connect80 = Proxy::with_expected_types(
        std::net::Ipv4Addr::LOCALHOST,
        1111,
        std::sync::Arc::from([Protocol::Connect(80)]),
    );
    assert!(!needs_missed_probe(&connect80, &[Protocol::Connect(80)]));
    assert!(needs_missed_probe(&connect80, &[Protocol::Connect(25)]));
}

#[test]
fn no_dedup_flag_disables_uniqueness() {
    let disabled = fetch_from(&["--no-dedup"]);
    assert!(!fetcher_config(&disabled.fetcher).enforce_unique_ip);

    let default = fetch_from(&[]);
    assert!(fetcher_config(&default.fetcher).enforce_unique_ip);
}

#[test]
fn provider_flags_land_in_fetcher_config() {
    let args = fetch_from(&["--provider", "geonode", "--provider", "proxyscrape"]);
    assert_eq!(
        fetcher_config(&args.fetcher).providers.as_ref(),
        ["geonode".to_owned(), "proxyscrape".to_owned()]
    );

    let excluded = fetch_from(&["--exclude-provider", "github-raw"]);
    assert_eq!(
        fetcher_config(&excluded.fetcher)
            .excluded_providers
            .as_ref(),
        ["github-raw".to_owned()]
    );

    let default = fetch_from(&[]);
    assert!(fetcher_config(&default.fetcher).providers.is_empty());
    assert!(fetcher_config(&default.fetcher)
        .excluded_providers
        .is_empty());
}

#[test]
fn dry_run_flag_is_accepted() {
    assert!(fetch_from(&["--dry-run"]).fetcher.dry_run);
    assert!(!fetch_from(&[]).fetcher.dry_run);
}

#[test]
fn list_providers_flag_is_accepted() {
    assert!(fetch_from(&["--list-providers"]).fetcher.list_providers);
    assert!(!fetch_from(&[]).fetcher.list_providers);
}

#[test]
fn validation_filter_flags_are_accepted() {
    let args = find_from(&[
        "--min-anonymity",
        "anonymous",
        "--max-response-time",
        "1.5",
        "--min-response-time",
        "0.5",
    ]);
    assert_eq!(args.output.min_anonymity.as_deref(), Some("anonymous"));
    assert_eq!(args.output.max_response_time, Some(1.5));
    assert_eq!(args.output.min_response_time, Some(0.5));
    assert!(Cli::try_parse_from(["flx", "find", "--min-anonymity", "super"]).is_err());
}

#[test]
fn tls_verification_is_on_by_default() {
    let plain = find_from(&["SOCKS5"]);
    let config = validator_config(&plain.validator, Vec::new(), Vec::new(), false);
    assert!(!config.insecure);

    let opt_out = find_from(&["SOCKS5", "--no-verify-tls"]);
    let config = validator_config(&opt_out.validator, Vec::new(), Vec::new(), false);
    assert!(config.insecure);
}

#[test]
fn support_header_flags_map_to_validator_config() {
    let none = find_from(&["SOCKS5"]);
    let config = validator_config(&none.validator, Vec::new(), Vec::new(), false);
    assert!(!config.support_cookies);
    assert!(!config.support_referer);

    let both = find_from(&["SOCKS5", "--support-cookies", "--support-referer"]);
    let config = validator_config(&both.validator, Vec::new(), Vec::new(), false);
    assert!(config.support_cookies);
    assert!(config.support_referer);
}

#[test]
fn levels_flag_parses_anonymity_levels() {
    let args = find_from(&["--levels", "elite", "anonymous"]);
    assert_eq!(
        args.output.levels,
        vec!["elite".to_owned(), "anonymous".to_owned()]
    );
    let unknown = find_from(&["--levels", "unknown"]);
    assert_eq!(unknown.output.levels, vec!["unknown".to_owned()]);
    let default = find_from(&[]);
    assert!(default.output.levels.is_empty());
    assert!(Cli::try_parse_from(["flx", "find", "--levels", "super"]).is_err());
}

#[test]
fn levels_filter_keeps_only_matching_anonymity() {
    let mut options = find_from(&[]).output;
    options.levels = vec!["elite".to_owned()];
    let filter = ProxyFilter::from_options(&options);

    let mut elite = sample_proxy(1);
    elite.proxy_types = vec![flx::proxy::models::ProxyType::new(Protocol::Http(
        Anonymity::Elite,
    ))];
    let mut anonymous = sample_proxy(2);
    anonymous.proxy_types = vec![flx::proxy::models::ProxyType::new(Protocol::Http(
        Anonymity::Anonymous,
    ))];
    let mut socks = sample_proxy(3);
    socks.proxy_types = vec![flx::proxy::models::ProxyType::new(Protocol::Socks5)];

    assert!(filter.matches(&elite));
    assert!(!filter.matches(&anonymous));
    assert!(!filter.matches(&socks));

    options.levels = vec!["unknown".to_owned()];
    let filter = ProxyFilter::from_options(&options);
    let mut unknown = sample_proxy(4);
    unknown.proxy_types = vec![flx::proxy::models::ProxyType::new(Protocol::Http(
        Anonymity::Unknown,
    ))];
    assert!(filter.matches(&unknown));
    assert!(!filter.matches(&elite));
}

#[test]
fn levels_filter_defaults_to_no_op() {
    let filter = ProxyFilter::from_options(&find_from(&[]).output);
    let mut proxy = sample_proxy(1);
    proxy.proxy_types = vec![flx::proxy::models::ProxyType::new(Protocol::Socks5)];
    assert!(filter.matches(&proxy));
}

#[test]
fn files_flag_accepts_multiple_paths_and_file_alias() {
    let args = find_from(&["--files", "a.txt", "b.txt", "c.txt"]);
    assert_eq!(args.validator.files.len(), 3);
    assert!(args.validator.files[0].ends_with("a.txt"));
    assert!(args.validator.files[2].ends_with("c.txt"));

    let aliased = find_from(&["--file", "a.txt"]);
    assert_eq!(aliased.validator.files.len(), 1);
    assert!(aliased.validator.files[0].ends_with("a.txt"));
}

#[test]
fn skip_version_check_flag_is_accepted() {
    let cli = Cli::parse_from(["flx", "--skip-version-check", "find", "SOCKS5"]);
    assert!(cli.skip_version_check);
    let cli = Cli::parse_from(["flx", "find", "SOCKS5"]);
    assert!(!cli.skip_version_check);
}

#[test]
fn check_version_compares_semantic_versions() {
    assert!(check_version("0.2.4", "0.2.5"));
    assert!(check_version("0.2.4", "0.3.0"));
    assert!(check_version("0.2.4", "1.0.0"));
    assert!(!check_version("0.2.5", "0.2.4"));
    assert!(!check_version("0.3.0", "0.2.9"));
    assert!(!check_version("0.2.4", "0.2.4"));
    assert!(check_version("0.2.4", "0.2.4.1"));
    assert!(check_version("0.2.4", "v0.2.5"));
    assert!(!check_version("0.2.4", "0.2"));
}

#[test]
fn cache_ttl_max_value_does_not_overflow() {
    let huge = fetch_from(&["--cache-ttl", "18446744073709551615"]);
    assert_eq!(
        fetcher_config(&huge.fetcher).cache_ttl,
        Some(std::time::Duration::from_secs(u64::MAX))
    );
}

#[test]
fn https_judge_urls_flag_parses_custom_value() {
    let cli = find_from(&[
        "SOCKS5",
        "--https-judge-urls",
        "https://example.com/azenv.php",
    ]);
    assert_eq!(
        cli.validator.https_judge_urls,
        vec!["https://example.com/azenv.php".to_owned()]
    );
    // default still intact when flag omitted
    let defaults = find_from(&["SOCKS5"]);
    assert_eq!(
        defaults.validator.https_judge_urls,
        vec![
            "https://aranguren.org/azenv.php".to_owned(),
            "https://wfuchs.de/azenv.php".to_owned(),
        ]
    );
}

fn output_options(format: &str, limit: usize) -> (OutputOptions, std::path::PathBuf) {
    let out = std::env::temp_dir().join(format!(
        "flx_json_test_{}_{}.json",
        std::process::id(),
        uuidish()
    ));
    (
        OutputOptions {
            format: format.to_owned(),
            limit,
            output_file: Some(out.clone()),
            min_anonymity: None,
            levels: Vec::new(),
            min_response_time: None,
            max_response_time: None,
            sort: None,
            order: "asc".to_owned(),
            exclude_type: Vec::new(),
            shuffle: false,
            append: false,
        },
        out,
    )
}

fn uuidish() -> u64 {
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(0);
    C.fetch_add(1, Ordering::Relaxed)
}

fn sample_proxy(ip: u8) -> Proxy {
    Proxy::new(
        std::net::Ipv4Addr::new(192, 168, 0, ip),
        8080 + u16::from(ip),
    )
}

#[test]
fn invalid_type_does_not_stop_following_types() {
    let types = vec![
        "HTTP".to_owned(),
        "NOT_A_PROTOCOL".to_owned(),
        "SOCKS5".to_owned(),
    ];
    let protocols = convert_protocols(&types);

    assert_eq!(protocols.len(), 2);
    assert_eq!(protocols[0], Protocol::Http(Anonymity::Unknown));
    assert_eq!(protocols[1], Protocol::Socks5);
}

#[test]
fn find_without_types_parses_cleanly() {
    let cli = find_from(&[]);
    assert!(cli.validator.types.is_empty());
}

#[test]
fn types_split_into_singletons_and_and_groups() {
    let (types, groups) = split_type_groups(&[
        "HTTP".to_owned(),
        "HTTP+HTTPS".to_owned(),
        "SOCKS5".to_owned(),
    ]);
    assert_eq!(
        types,
        vec![Protocol::Http(Anonymity::Unknown), Protocol::Socks5]
    );
    assert_eq!(
        groups,
        vec![vec![
            Protocol::Http(Anonymity::Unknown),
            Protocol::Https(Anonymity::Unknown)
        ]]
    );
}

#[test]
fn anonymity_annotated_types_parse_and_validate_at_cli() {
    let args = find_from(&[
        "HTTP:Elite",
        "HTTP:Anonymous",
        "SOCKS5",
        "HTTP:Anonymous+SOCKS5",
    ]);
    let (types, groups) = split_type_groups(&args.validator.types);
    assert_eq!(
        types,
        vec![
            Protocol::Http(Anonymity::Elite),
            Protocol::Http(Anonymity::Anonymous),
            Protocol::Socks5
        ]
    );
    assert_eq!(groups.len(), 1);
    assert_eq!(
        groups[0],
        vec![Protocol::Http(Anonymity::Anonymous), Protocol::Socks5]
    );
}

#[test]
fn and_group_deduplicates_repeated_members() {
    let (types, groups) = split_type_groups(&["HTTP+HTTPS+HTTP".to_owned()]);
    assert!(types.is_empty());
    assert_eq!(groups.len(), 1);
    assert_eq!(groups[0].len(), 2);
}

#[test]
fn default_format_switches_to_json_lines_when_piped() {
    assert_eq!(effective_format("default", None, true), "default");
    assert_eq!(effective_format("default", None, false), "json-lines");
    // Explicit formats are never overridden.
    assert_eq!(effective_format("json", None, false), "json");
    assert_eq!(effective_format("pretty-json", None, false), "pretty-json");
}

#[test]
fn default_format_follows_output_file_extension() {
    let f = |name: &'static str| Some(std::path::Path::new(name));
    assert_eq!(effective_format("default", f("a.json"), true), "json");
    assert_eq!(effective_format("default", f("a.JSON"), true), "json");
    assert_eq!(
        effective_format("default", f("a.jsonl"), true),
        "json-lines"
    );
    assert_eq!(
        effective_format("default", f("a.ndjson"), true),
        "json-lines"
    );
    assert_eq!(effective_format("default", f("a.csv"), true), "csv");
    assert_eq!(effective_format("default", f("a.pac"), true), "pac");
    assert_eq!(effective_format("default", f("a.txt"), true), "default");
    // The extension only infers when the format is still `default`.
    assert_eq!(effective_format("json", f("a.txt"), true), "json");
}

#[test]
fn geo_update_subcommand_is_accepted() {
    let cli = Cli::parse_from(["flx", "geo-update"]);
    assert!(matches!(cli.command, Some(Command::GeoUpdate)));
    // a bare invocation carries no command
    let bare = Cli::parse_from(["flx"]);
    assert!(bare.command.is_none());
}

#[test]
fn cli_rejects_zero_max_attempts() {
    let result = Cli::try_parse_from(["flx", "find", "SOCKS5", "--max-attempts", "0"]);
    assert!(result.is_err());
}

fn parse_json_lines(content: &str) -> Vec<serde_json::Value> {
    content
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| serde_json::from_str(line).unwrap())
        .collect()
}

fn run_json_lines(proxies: &[Proxy], limit: usize) -> String {
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    let (options, path) = output_options("json-lines", limit);
    rt.block_on(async {
        let s = stream::iter(proxies.to_vec());
        process_result(
            s,
            options,
            Arc::new(tokio::sync::Notify::new()),
            &NoopGuard,
            FinalizeOpts::default(),
        )
        .await
        .unwrap();
    });
    let content = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    content
}

fn run_csv(proxies: &[Proxy], limit: usize) -> String {
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    let (options, path) = output_options("csv", limit);
    rt.block_on(async {
        let s = stream::iter(proxies.to_vec());
        process_result(
            s,
            options,
            Arc::new(tokio::sync::Notify::new()),
            &NoopGuard,
            FinalizeOpts::default(),
        )
        .await
        .unwrap();
    });
    let content = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    content
}

fn run_json(proxies: &[Proxy], limit: usize) -> String {
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    let (options, path) = output_options("json", limit);
    rt.block_on(async {
        let s = stream::iter(proxies.to_vec());
        // Tests never cancel: use a notify that never fires.
        process_result(
            s,
            options,
            Arc::new(tokio::sync::Notify::new()),
            &NoopGuard,
            FinalizeOpts::default(),
        )
        .await
        .unwrap();
    });
    let content = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    content
}

#[test]
fn json_empty_yields_empty_array() {
    let out = run_json(&[], 0);
    assert_eq!(out, "[]\n", "empty source must produce valid []");
    // must parse as JSON
    serde_json::from_str::<serde_json::Value>(&out).unwrap();
}

#[test]
fn json_empty_is_suppressed_when_requested() {
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    let (options, path) = output_options("json", 0);
    rt.block_on(async {
        let s = stream::iter(Vec::<Proxy>::new());
        process_result(
            s,
            options,
            Arc::new(tokio::sync::Notify::new()),
            &NoopGuard,
            FinalizeOpts {
                suppress_empty_json: true,
                emit_csv_header: true,
                stats: None,
                continue_json: None,
            },
        )
        .await
        .unwrap();
    });
    let content = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    // The empty document is left to a later pass, so nothing is written.
    assert_eq!(content, "");
}

// Runs the two chained passes of `find`'s fallback flow against one output
// file and returns the resulting file contents.
fn run_chained_passes(format: &str, pass1: &[Proxy], pass2: &[Proxy]) -> String {
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    let (options, path) = output_options(format, 0);
    rt.block_on(async {
        let doc = Arc::new(JsonDoc::default());
        process_result(
            stream::iter(pass1.to_vec()),
            options.clone(),
            Arc::new(tokio::sync::Notify::new()),
            &NoopGuard,
            FinalizeOpts {
                suppress_empty_json: true,
                emit_csv_header: true,
                stats: None,
                continue_json: Some(JsonContinuation {
                    doc: Arc::clone(&doc),
                    leave_open: true,
                }),
            },
        )
        .await
        .unwrap();
        process_result(
            stream::iter(pass2.to_vec()),
            options.clone(),
            Arc::new(tokio::sync::Notify::new()),
            &NoopGuard,
            FinalizeOpts {
                suppress_empty_json: false,
                emit_csv_header: false,
                stats: None,
                continue_json: Some(JsonContinuation {
                    doc,
                    leave_open: false,
                }),
            },
        )
        .await
        .unwrap();
    });
    let content = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    content
}

#[test]
fn fallback_pass_extends_the_json_array_instead_of_truncating() {
    let pass1: Vec<Proxy> = (1u8..=3).map(sample_proxy).collect();
    let pass2: Vec<Proxy> = (4u8..=5).map(sample_proxy).collect();
    let out = run_chained_passes("json", &pass1, &pass2);
    let parsed: serde_json::Value = serde_json::from_str(&out).expect("one valid JSON document");
    assert_eq!(
        parsed.as_array().map(Vec::len),
        Some(5),
        "pass 2 must extend, not replace, the array written by pass 1"
    );
}

#[test]
fn skipped_fallback_after_partial_pass_closes_the_open_array() {
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    let (options, path) = output_options("json", 0);
    rt.block_on(async {
        let doc = Arc::new(JsonDoc::default());
        process_result(
            stream::iter(vec![sample_proxy(1), sample_proxy(2)]),
            options.clone(),
            Arc::new(tokio::sync::Notify::new()),
            &NoopGuard,
            FinalizeOpts {
                suppress_empty_json: true,
                emit_csv_header: true,
                stats: None,
                continue_json: Some(JsonContinuation {
                    doc: Arc::clone(&doc),
                    leave_open: true,
                }),
            },
        )
        .await
        .unwrap();
        close_chained_json(&options, doc.items()).await.unwrap();
    });
    let content = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    let parsed: serde_json::Value =
        serde_json::from_str(&content).expect("a single closed document");
    assert_eq!(parsed.as_array().map(Vec::len), Some(2));
    assert_eq!(content.matches('[').count(), 1, "exactly one array opener");
}

#[test]
fn skipped_fallback_with_an_empty_pass_emits_one_empty_array() {
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    let (options, path) = output_options("json", 0);
    rt.block_on(async {
        let doc = Arc::new(JsonDoc::default());
        process_result(
            stream::iter(Vec::<Proxy>::new()),
            options.clone(),
            Arc::new(tokio::sync::Notify::new()),
            &NoopGuard,
            FinalizeOpts {
                suppress_empty_json: true,
                emit_csv_header: true,
                stats: None,
                continue_json: Some(JsonContinuation {
                    doc: Arc::clone(&doc),
                    leave_open: true,
                }),
            },
        )
        .await
        .unwrap();
        close_chained_json(&options, doc.items()).await.unwrap();
    });
    let content = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(content, "[]\n");
}

#[test]
fn fallback_pass_appends_text_output_without_truncating_pass_1() {
    let pass1: Vec<Proxy> = (1u8..=3).map(sample_proxy).collect();
    let pass2: Vec<Proxy> = (4u8..=5).map(sample_proxy).collect();
    let out = run_chained_passes("text", &pass1, &pass2);
    assert_eq!(out.lines().count(), 5, "pass-1 rows must survive pass 2");
}

#[test]
fn fallback_pass_preserves_the_csv_header_and_pass_1_rows() {
    let pass1: Vec<Proxy> = (1u8..=3).map(sample_proxy).collect();
    let pass2: Vec<Proxy> = (4u8..=5).map(sample_proxy).collect();
    let out = run_chained_passes("csv", &pass1, &pass2);
    let mut lines = out.lines();
    assert!(
        lines.next().unwrap().starts_with("ip,port,"),
        "the header written by pass 1 must survive pass 2"
    );
    assert_eq!(lines.count(), 5);
}

#[test]
fn tee_recorder_forwards_and_records_candidates() {
    let proxies: Vec<Proxy> = (1u16..=3)
        .map(|port| Proxy::new(std::net::Ipv4Addr::LOCALHOST, port))
        .collect();
    let recordings: Arc<std::sync::Mutex<Vec<Proxy>>> = Arc::default();
    // Plain `Proxy::new` candidates advertise nothing, so every one of them
    // is a missed-probe candidate regardless of the requested list.
    let requested: Arc<[Protocol]> = Arc::from(vec![Protocol::Http(Anonymity::Unknown)]);
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    let forwarded = rt.block_on(async {
        let s = tee_recorder(
            stream::iter(proxies.clone()),
            Arc::clone(&recordings),
            requested,
        );
        s.collect::<Vec<_>>().await
    });
    let recorded = recordings.lock().unwrap();
    assert_eq!(forwarded.len(), 3);
    assert_eq!(recorded.len(), 3);
    assert_eq!(forwarded[0].ip, proxies[0].ip);
    assert_eq!(forwarded[1].port, proxies[1].port);
    assert_eq!(recorded[2].port, proxies[2].port);
}

#[test]
fn tee_recorder_skips_candidates_the_fallback_would_discard() {
    // An advertised set covering every requested type can never yield a
    // missed probe, so the recorder must not pay a deep copy for it.
    let covering = Proxy::with_expected_types(
        std::net::Ipv4Addr::new(192, 168, 0, 9),
        9000,
        std::sync::Arc::from([Protocol::Http(Anonymity::Unknown)]),
    );
    let plain = sample_proxy(1);
    let plain_port = plain.port;
    let recordings: Arc<std::sync::Mutex<Vec<Proxy>>> = Arc::default();
    let requested: Arc<[Protocol]> = Arc::from(vec![Protocol::Http(Anonymity::Unknown)]);
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    let forwarded = rt.block_on(async {
        let s = tee_recorder(
            stream::iter(vec![covering, plain]),
            Arc::clone(&recordings),
            requested,
        );
        s.collect::<Vec<_>>().await
    });
    assert_eq!(
        forwarded.len(),
        2,
        "every candidate must still stream through"
    );
    let recorded = recordings.lock().unwrap();
    assert_eq!(
        recorded.len(),
        1,
        "only missed-probe candidates are recorded"
    );
    assert_eq!(recorded[0].port, plain_port);
}

#[test]
fn json_single_has_no_trailing_comma() {
    let out = run_json(&[sample_proxy(1)], 0);
    assert!(out.starts_with("[\n"), "must open array");
    assert!(out.trim_end().ends_with("]"), "must close array");
    assert!(!out.contains(",]"), "no trailing comma before ]");
    let _: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
}

#[test]
fn json_multiple_is_valid_array() {
    let proxies = [sample_proxy(1), sample_proxy(2), sample_proxy(3)];
    let out = run_json(&proxies, 0);
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed.len(), 3);
    assert!(!out.contains(",]"));
}

#[test]
fn json_one_entry_per_line_with_trailing_commas() {
    // Regression: entries used to leave a blank line and put the comma on
    // its own removed line. Each proxy must sit on its own line with the
    // comma at the end of the previous line and `]` alone on the last.
    let proxies = [sample_proxy(1), sample_proxy(2), sample_proxy(3)];
    let out = run_json(&proxies, 0);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 5, "expected [ + entry + entry + entry + ]");
    assert_eq!(lines[0], "[", "array must open on its own line");
    assert_eq!(lines[4], "]", "array must close on its own line");
    for body in &lines[1..4] {
        assert!(body.starts_with("  {"), "entries must be indented");
    }
    assert!(lines[1].ends_with(','));
    assert!(lines[2].ends_with(','));
    assert!(!lines[3].ends_with(','), "no comma on the last entry");
    assert!(!out.contains("\n\n"), "no blank lines between entries");
}

#[test]
fn json_limit_truncates_without_trailing_comma() {
    let proxies = [
        sample_proxy(1),
        sample_proxy(2),
        sample_proxy(3),
        sample_proxy(4),
    ];
    // limit 2 -> exactly 2 elements, valid JSON, no trailing comma
    let out = run_json(&proxies, 2);
    let parsed: Vec<serde_json::Value> = serde_json::from_str(&out).unwrap();
    assert_eq!(parsed.len(), 2);
    assert!(!out.contains(",]"));
}

#[test]
fn quiet_flag_is_accepted() {
    let cli = Cli::parse_from(["flx", "--quiet"]);
    assert!(cli.quiet);
    assert!(!Cli::parse_from(["flx"]).quiet);
}

#[test]
fn no_color_flag_is_accepted() {
    let cli = Cli::parse_from(["flx", "--no-color"]);
    assert!(cli.no_color);
    assert!(!Cli::parse_from(["flx"]).no_color);
}

#[test]
fn quiet_with_json_format_is_valid() {
    let cli = Cli::parse_from(["flx", "--quiet", "grab", "--format", "json"]);
    assert!(cli.quiet);
    match cli.command {
        Some(Command::Grab(grab)) => assert_eq!(grab.output.format, "json"),
        _ => panic!("expected grab subcommand"),
    }
}

#[test]
fn json_lines_empty_yields_nothing() {
    let out = run_json_lines(&[], 0);
    assert_eq!(out, "", "empty source must produce empty output");
}

#[test]
fn json_lines_one_proxy_produces_one_line() {
    let out = run_json_lines(&[sample_proxy(1)], 0);
    let parsed = parse_json_lines(&out);
    assert_eq!(parsed.len(), 1);
    // No array brackets, no trailing comma
    assert!(!out.contains('['));
    assert!(!out.contains(']'));
}

#[test]
fn json_lines_multiple_proxies_produce_one_per_line() {
    let proxies = [sample_proxy(1), sample_proxy(2), sample_proxy(3)];
    let out = run_json_lines(&proxies, 0);
    let parsed = parse_json_lines(&out);
    assert_eq!(parsed.len(), 3);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3);
    for line in &lines {
        assert!(serde_json::from_str::<serde_json::Value>(line).is_ok());
    }
}

#[test]
fn json_lines_limit_truncates() {
    let proxies = [sample_proxy(1), sample_proxy(2), sample_proxy(3)];
    let out = run_json_lines(&proxies, 2);
    let parsed = parse_json_lines(&out);
    assert_eq!(parsed.len(), 2);
}

#[test]
fn csv_empty_yields_header_only() {
    let out = run_csv(&[], 0);
    assert_eq!(out, "ip,port,type,response_time,country,ip_type\n");
}

#[test]
fn csv_one_proxy_produces_header_and_one_row() {
    let out = run_csv(&[sample_proxy(1)], 0);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 2);
    assert_eq!(lines[0], "ip,port,type,response_time,country,ip_type");
    assert!(lines[1].starts_with("192.168.0.1,8081,"));
    assert!(lines[1].ends_with(",unknown"));
}

#[test]
fn csv_multiple_proxies_produce_one_row_each() {
    let proxies = [sample_proxy(1), sample_proxy(2), sample_proxy(3)];
    let out = run_csv(&proxies, 0);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 4, "header + 3 rows");
    assert_eq!(lines[0], "ip,port,type,response_time,country,ip_type");
    assert!(lines[1].contains("192.168.0.1"));
    assert!(lines[2].contains("192.168.0.2"));
    assert!(lines[3].contains("192.168.0.3"));
}

#[test]
fn csv_limit_truncates_rows() {
    let proxies = [sample_proxy(1), sample_proxy(2), sample_proxy(3)];
    let out = run_csv(&proxies, 2);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "header + 2 rows");
}

fn validated_proxy(ip: u8, anonymity: &str, response_time: f64) -> Proxy {
    use flx::proxy::models::ProxyType;
    let mut proxy = Proxy::new(std::net::Ipv4Addr::new(10, 0, 0, ip), 8080 + u16::from(ip));
    proxy
        .proxy_types
        .push(ProxyType::checked(anonymity.parse::<Protocol>().unwrap()));
    proxy.runtimes.record(response_time);
    proxy
}

fn run_filtered(
    proxies: &[Proxy],
    min_anonymity: Option<&str>,
    min_response_time: Option<f64>,
    max_response_time: Option<f64>,
) -> Vec<serde_json::Value> {
    let (options, path) = output_options("json-lines", 0);
    let options = OutputOptions {
        min_anonymity: min_anonymity.map(str::to_owned),
        min_response_time,
        max_response_time,
        ..options
    };
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    rt.block_on(async {
        let s = stream::iter(proxies.to_vec());
        process_result(
            s,
            options,
            Arc::new(tokio::sync::Notify::new()),
            &NoopGuard,
            FinalizeOpts::default(),
        )
        .await
        .unwrap();
    });
    let content = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    parse_json_lines(&content)
}

#[test]
fn process_result_filters_by_min_anonymity() {
    let proxies = [
        validated_proxy(1, "HTTP:Transparent", 0.2),
        validated_proxy(2, "HTTP:Anonymous", 0.2),
        validated_proxy(3, "HTTP:Elite", 0.2),
    ];
    let kept = run_filtered(&proxies, Some("anonymous"), None, None);
    assert_eq!(kept.len(), 2);
    assert!(kept[0]["ip"].as_str().unwrap().ends_with(".2"));
    assert!(kept[1]["ip"].as_str().unwrap().ends_with(".3"));
}

#[test]
fn process_result_filters_by_response_time_bounds() {
    let proxies = [
        validated_proxy(1, "HTTP:Anonymous", 0.1),
        validated_proxy(2, "HTTP:Anonymous", 2.0),
        validated_proxy(3, "HTTP:Anonymous", 0.7),
    ];
    let kept = run_filtered(&proxies, None, Some(0.5), Some(1.0));
    assert_eq!(kept.len(), 1);
    assert!(kept[0]["ip"].as_str().unwrap().ends_with(".3"));
}

#[test]
fn process_result_filters_with_all_bounds_combined() {
    let proxies = [
        validated_proxy(1, "HTTP:Transparent", 0.3),
        validated_proxy(2, "HTTP:Anonymous", 0.9),
        validated_proxy(3, "HTTP:Elite", 1.5),
    ];
    let kept = run_filtered(&proxies, Some("anonymous"), Some(0.5), Some(1.0));
    assert_eq!(kept.len(), 1);
    assert!(kept[0]["ip"].as_str().unwrap().ends_with(".2"));
}

#[test]
fn process_result_default_keeps_socks_and_conntype_anonymity_free_proxies() {
    use flx::proxy::models::ProxyType;
    let mut proxy = Proxy::new(std::net::Ipv4Addr::new(10, 0, 0, 9), 1080);
    proxy.proxy_types.push(ProxyType::checked(Protocol::Socks5));
    proxy.runtimes.record(0.4);

    let kept = run_filtered(&[proxy], Some("elite"), None, None);
    assert_eq!(kept.len(), 1, "types without anonymity pass any threshold");
}

fn run_sorted(proxies: &[Proxy], sort: &str, order: &str) -> Vec<serde_json::Value> {
    let (options, path) = output_options("json-lines", 0);
    let options = OutputOptions {
        sort: Some(sort.to_owned()),
        order: order.to_owned(),
        ..options
    };
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    rt.block_on(async {
        let s = stream::iter(proxies.to_vec());
        process_result(
            s,
            options,
            Arc::new(tokio::sync::Notify::new()),
            &NoopGuard,
            FinalizeOpts::default(),
        )
        .await
        .unwrap();
    });
    let content = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    parse_json_lines(&content)
}

fn proxy_country(ip: u8, country: &str) -> Proxy {
    let mut proxy = Proxy::new(std::net::Ipv4Addr::new(10, 1, 0, ip), 8080);
    proxy.geo = Arc::new(flx::GeoData {
        iso_code: Some(country.to_owned().into()),
        ..flx::GeoData::default()
    });
    proxy
}

#[test]
fn process_result_sorts_by_response_time() {
    let proxies = [
        validated_proxy(1, "HTTP:Anonymous", 0.9),
        validated_proxy(2, "HTTP:Anonymous", 0.1),
        validated_proxy(3, "HTTP:Anonymous", 0.5),
    ];
    let asc = run_sorted(&proxies, "avg-response", "asc");
    assert!(asc[0]["average_response_time"].as_f64().unwrap() < 0.5);
    assert!(asc[2]["average_response_time"].as_f64().unwrap() > 0.5);

    let desc = run_sorted(&proxies, "avg-response", "desc");
    assert!(desc[0]["average_response_time"].as_f64().unwrap() > 0.5);
    assert!(desc[2]["average_response_time"].as_f64().unwrap() < 0.5);

    let alias = run_sorted(&proxies, "response-time", "asc");
    assert!(alias[0]["average_response_time"].as_f64().unwrap() < 0.5);
    assert!(alias[2]["average_response_time"].as_f64().unwrap() > 0.5);

    let alias_desc = run_sorted(&proxies, "response-time", "desc");
    assert!(alias_desc[0]["average_response_time"].as_f64().unwrap() > 0.5);
    assert!(alias_desc[2]["average_response_time"].as_f64().unwrap() < 0.5);
}

#[test]
fn process_result_sorts_by_anonymity_rank() {
    let proxies = [
        validated_proxy(1, "HTTP:Anonymous", 0.2),
        validated_proxy(2, "HTTP:Transparent", 0.2),
        validated_proxy(3, "HTTP:Elite", 0.2),
    ];
    let asc = run_sorted(&proxies, "anonymity", "asc");
    assert!(asc[0]["type"]["protocol"]["Http"].as_str().unwrap() == "Transparent");
    assert!(asc[2]["type"]["protocol"]["Http"].as_str().unwrap() == "Elite");
}

#[test]
fn process_result_sorts_by_country() {
    let proxies = [
        proxy_country(1, "US"),
        proxy_country(2, "ID"),
        proxy_country(3, "DE"),
    ];
    let asc = run_sorted(&proxies, "country", "asc");
    assert!(asc[0]["geo"]["iso_code"].as_str().unwrap() == "DE");
    assert!(asc[2]["geo"]["iso_code"].as_str().unwrap() == "US");

    let desc = run_sorted(&proxies, "country", "desc");
    assert!(
        asc[0]["geo"]["iso_code"].as_str().unwrap() != desc[0]["geo"]["iso_code"].as_str().unwrap()
    );
}

#[test]
fn sort_and_order_flags_are_accepted() {
    let args = find_from(&["--sort", "country", "--order", "desc"]);
    assert_eq!(args.output.sort.as_deref(), Some("country"));
    assert_eq!(args.output.order, "desc");
    assert!(Cli::try_parse_from(["flx", "find", "--sort", "bogus"]).is_err());
    assert!(Cli::try_parse_from(["flx", "find", "--order", "sideways"]).is_err());
}

#[test]
fn format_judge_health_renders_compact_summary() {
    let report = flx::JudgeHealthReport {
        candidates: 4,
        healthy: 1,
        failed: vec![
            ("http://a".to_owned(), "timeout".to_owned()),
            ("http://b".to_owned(), "timeout".to_owned()),
        ],
    };
    assert_eq!(
        format_judge_health(&report),
        "1/4 judges healthy; 2 failed (timeout)"
    );
}

#[test]
fn no_color_with_json_format_is_valid() {
    let cli = Cli::parse_from(["flx", "--no-color", "grab", "--format", "json"]);
    assert!(cli.no_color);
    match cli.command {
        Some(Command::Grab(grab)) => assert_eq!(grab.output.format, "json"),
        _ => panic!("expected grab subcommand"),
    }
}

fn run_proxychains(proxies: &[Proxy], limit: usize) -> String {
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    let (options, path) = output_options("proxychains", limit);
    rt.block_on(async {
        let s = stream::iter(proxies.to_vec());
        process_result(
            s,
            options,
            Arc::new(tokio::sync::Notify::new()),
            &NoopGuard,
            FinalizeOpts::default(),
        )
        .await
        .unwrap();
    });
    let content = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    content
}

fn run_prefix(proxies: &[Proxy], limit: usize) -> String {
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    let (options, path) = output_options("prefix", limit);
    rt.block_on(async {
        let s = stream::iter(proxies.to_vec());
        process_result(
            s,
            options,
            Arc::new(tokio::sync::Notify::new()),
            &NoopGuard,
            FinalizeOpts::default(),
        )
        .await
        .unwrap();
    });
    let content = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    content
}

fn run_pac(proxies: &[Proxy], limit: usize) -> String {
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    let (options, path) = output_options("pac", limit);
    rt.block_on(async {
        let s = stream::iter(proxies.to_vec());
        process_result(
            s,
            options,
            Arc::new(tokio::sync::Notify::new()),
            &NoopGuard,
            FinalizeOpts::default(),
        )
        .await
        .unwrap();
    });
    let content = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    content
}

#[test]
fn proxychains_renders_type_ip_port() {
    let mut proxy = sample_proxy(1);
    proxy
        .proxy_types
        .push(flx::proxy::models::ProxyType::checked(Protocol::Socks5));
    let out = run_proxychains(&[proxy], 0);
    assert_eq!(out, "socks5 192.168.0.1 8081\n");
}

#[test]
fn proxychains_falls_back_to_http_for_http_proxy() {
    let mut proxy = sample_proxy(2);
    proxy
        .proxy_types
        .push(flx::proxy::models::ProxyType::checked(Protocol::Http(
            Anonymity::Anonymous,
        )));
    let out = run_proxychains(&[proxy], 0);
    assert_eq!(out, "http 192.168.0.2 8082\n");
}

#[test]
fn prefix_defaults_to_http_scheme_without_types() {
    // A bare proxy carries no validated type; the URI must not claim SOCKS.
    let out = run_prefix(&[sample_proxy(3)], 0);
    assert_eq!(out, "http://192.168.0.3:8083\n");
}

#[test]
fn prefix_renders_socks5_url_for_socks5_proxy() {
    let mut proxy = sample_proxy(3);
    proxy
        .proxy_types
        .push(flx::proxy::models::ProxyType::checked(Protocol::Socks5));
    let out = run_prefix(&[proxy], 0);
    assert_eq!(out, "socks5://192.168.0.3:8083\n");
}

#[test]
fn prefix_multiple_proxies_match_each_type() {
    let mut socks4 = sample_proxy(2);
    socks4
        .proxy_types
        .push(flx::proxy::models::ProxyType::checked(Protocol::Socks4));
    let mut socks5 = sample_proxy(3);
    socks5
        .proxy_types
        .push(flx::proxy::models::ProxyType::checked(Protocol::Socks5));

    let out = run_prefix(&[sample_proxy(1), socks4, socks5], 0);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3);
    assert_eq!(lines[0], "http://192.168.0.1:8081");
    assert_eq!(lines[1], "socks4://192.168.0.2:8082");
    assert_eq!(lines[2], "socks5://192.168.0.3:8083");
}

#[test]
fn pac_empty_yields_direct_only() {
    let out = run_pac(&[], 0);
    assert!(out.contains("FindProxyForURL"));
    assert!(out.contains("DIRECT"));
    assert!(!out.contains("PROXY"));
}

#[test]
fn pac_renders_proxy_directives() {
    let mut proxy = sample_proxy(1);
    proxy
        .proxy_types
        .push(flx::proxy::models::ProxyType::checked(Protocol::Http(
            Anonymity::Anonymous,
        )));
    let out = run_pac(&[proxy], 0);
    assert!(out.contains("PROXY 192.168.0.1:8081"));
    assert!(out.contains("DIRECT"));
}

#[test]
fn pac_respects_limit() {
    let proxies: Vec<_> = (1..=5).map(sample_proxy).collect();
    let out = run_pac(&proxies, 3);
    assert_eq!(out.matches("PROXY").count(), 3);
}

#[test]
fn exclude_country_flag_lands_in_fetcher_config() {
    let args = fetch_from(&["--exclude-country", "CN", "RU"]);
    let config = fetcher_config(&args.fetcher);
    assert_eq!(
        config.excluded_countries.as_ref(),
        ["CN".to_owned(), "RU".to_owned()]
    );
    assert!(config.enable_geo_lookup);

    let default = fetch_from(&[]);
    let config = fetcher_config(&default.fetcher);
    assert!(config.excluded_countries.is_empty());
    assert!(!config.enable_geo_lookup);
}

#[test]
fn exclude_type_flag_parses_and_validates() {
    let args = find_from(&["--exclude-type", "SOCKS4", "HTTP:Elite"]);
    assert_eq!(
        args.output.exclude_type,
        vec!["SOCKS4".to_owned(), "HTTP:Elite".to_owned()]
    );
    assert!(Cli::try_parse_from(["flx", "find", "--exclude-type", "bogus"]).is_err());
}

#[test]
fn exclude_type_filter_drops_matching_families() {
    let mut options = find_from(&[]).output;
    options.exclude_type = vec!["HTTP".to_owned()];
    let filter = ProxyFilter::from_options(&options);

    let mut elite = sample_proxy(1);
    elite.proxy_types = vec![flx::proxy::models::ProxyType::new(Protocol::Http(
        Anonymity::Elite,
    ))];
    let mut socks5 = sample_proxy(2);
    socks5.proxy_types = vec![flx::proxy::models::ProxyType::new(Protocol::Socks5)];

    assert!(
        !filter.matches(&elite),
        "HTTP:Elite must match exclude HTTP"
    );
    assert!(filter.matches(&socks5));
}

#[test]
fn exclude_type_filter_uses_advertised_types_when_unvalidated() {
    let mut options = find_from(&[]).output;
    options.exclude_type = vec!["SOCKS4".to_owned()];
    let filter = ProxyFilter::from_options(&options);

    let socks4 = Proxy::with_expected_types(
        std::net::Ipv4Addr::LOCALHOST,
        1111,
        std::sync::Arc::from([Protocol::Socks4]),
    );
    let http = Proxy::with_expected_types(
        std::net::Ipv4Addr::LOCALHOST,
        1112,
        std::sync::Arc::from([Protocol::Http(Anonymity::Unknown)]),
    );

    assert!(!filter.matches(&socks4));
    assert!(filter.matches(&http));
}

#[test]
fn shuffle_flag_is_accepted_and_preserves_the_set() {
    let proxies: Vec<_> = (1..=10).map(sample_proxy).collect();
    let mut shuffled = proxies.clone();
    flx::shuffle_proxies(&mut shuffled);

    let mut expected: Vec<u8> = proxies.iter().map(|p| p.ip.octets()[3]).collect();
    expected.sort_unstable();
    let mut actual: Vec<u8> = shuffled.iter().map(|p| p.ip.octets()[3]).collect();
    actual.sort_unstable();
    assert_eq!(expected, actual, "shuffle must be a permutation");

    let args = fetch_from(&["--shuffle"]);
    assert!(args.output.shuffle);
    assert!(!fetch_from(&[]).output.shuffle);
}

fn run_text(proxies: &[Proxy], append: bool, existing: Option<&str>) -> String {
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    let (options, path) = output_options("text", 0);
    let options = OutputOptions { append, ..options };
    if let Some(content) = existing {
        std::fs::write(&path, content).unwrap();
    }
    rt.block_on(async {
        let s = stream::iter(proxies.to_vec());
        process_result(
            s,
            options,
            Arc::new(tokio::sync::Notify::new()),
            &NoopGuard,
            FinalizeOpts::default(),
        )
        .await
        .unwrap();
    });
    let content = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    content
}

#[test]
fn append_flag_appends_to_existing_output_file() {
    let first = run_text(&[sample_proxy(1)], false, None);
    assert_eq!(first, "192.168.0.1:8081\n");

    let combined = run_text(&[sample_proxy(2)], true, Some(&first));
    assert_eq!(combined, "192.168.0.1:8081\n192.168.0.2:8082\n");
}

#[test]
fn append_without_existing_file_creates_it() {
    let out = run_text(&[sample_proxy(1)], true, None);
    assert_eq!(out, "192.168.0.1:8081\n");
}

#[test]
fn append_rejects_json_formats() {
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    let (options, path) = output_options("json", 0);
    let options = OutputOptions {
        append: true,
        ..options
    };
    let result = rt.block_on(async {
        process_result(
            stream::iter(Vec::<Proxy>::new()),
            options,
            Arc::new(tokio::sync::Notify::new()),
            &NoopGuard,
            FinalizeOpts::default(),
        )
        .await
    });
    let _ = std::fs::remove_file(&path);
    assert!(result.is_err());
}

#[test]
fn append_csv_skips_duplicate_header() {
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    let (options, path) = output_options("csv", 0);
    let options = OutputOptions {
        append: true,
        ..options
    };
    std::fs::write(
        &path,
        "ip,port,type,response_time,country,ip_type\n1.2.3.4,80,,\n",
    )
    .unwrap();
    rt.block_on(async {
        process_result(
            stream::iter(vec![sample_proxy(1)]),
            options,
            Arc::new(tokio::sync::Notify::new()),
            &NoopGuard,
            FinalizeOpts::default(),
        )
        .await
        .unwrap();
    });
    let content = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(
        content,
        "ip,port,type,response_time,country,ip_type\n1.2.3.4,80,,\n192.168.0.1,8081,,0.00,,unknown\n"
    );
}

// Yields its items, fires the graceful-cancel permit once they are done,
// and never completes afterwards — the shape of an upstream run that keeps
// going after Ctrl+C was pressed.
struct CancelAfterStream {
    items: std::vec::IntoIter<Proxy>,
    cancel: Arc<tokio::sync::Notify>,
    fired: bool,
}

impl CancelAfterStream {
    fn new(items: Vec<Proxy>, cancel: Arc<tokio::sync::Notify>) -> Self {
        Self {
            items: items.into_iter(),
            cancel,
            fired: false,
        }
    }
}

impl futures_util::Stream for CancelAfterStream {
    type Item = Proxy;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Proxy>> {
        if let Some(proxy) = self.items.next() {
            return std::task::Poll::Ready(Some(proxy));
        }
        if !self.fired {
            self.fired = true;
            // Like the SIGINT task: a stored permit survives until polled.
            self.cancel.notify_one();
            cx.waker().wake_by_ref();
        }
        std::task::Poll::Pending
    }
}

#[test]
fn process_result_cancel_during_sorted_collect_keeps_partial_sorted_output() {
    let proxies = vec![
        validated_proxy(1, "HTTP:Anonymous", 0.9),
        validated_proxy(2, "HTTP:Anonymous", 0.1),
    ];
    let (options, path) = output_options("json-lines", 0);
    let options = OutputOptions {
        sort: Some("avg-response".to_owned()),
        order: "asc".to_owned(),
        ..options
    };
    let cancel = Arc::new(tokio::sync::Notify::new());
    let source = CancelAfterStream::new(proxies, Arc::clone(&cancel));
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    let outcome = rt.block_on(async {
        process_result(source, options, cancel, &NoopGuard, FinalizeOpts::default())
            .await
            .unwrap()
    });
    assert_eq!(outcome, RunOutcome::Cancelled);

    let content = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    let rows = parse_json_lines(&content);
    assert_eq!(
        rows.len(),
        2,
        "every proxy collected before the cancel must be emitted"
    );
    let first = rows[0]["average_response_time"].as_f64().unwrap();
    let second = rows[1]["average_response_time"].as_f64().unwrap();
    assert!(first <= second, "the partial output must stay sorted");
}

#[test]
fn process_result_cancel_during_shuffle_collect_preserves_the_set() {
    let proxies = vec![sample_proxy(1), sample_proxy(2), sample_proxy(3)];
    let (options, path) = output_options("json-lines", 0);
    let options = OutputOptions {
        shuffle: true,
        ..options
    };
    let cancel = Arc::new(tokio::sync::Notify::new());
    let source = CancelAfterStream::new(proxies, Arc::clone(&cancel));
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    let outcome = rt.block_on(async {
        process_result(source, options, cancel, &NoopGuard, FinalizeOpts::default())
            .await
            .unwrap()
    });
    assert_eq!(outcome, RunOutcome::Cancelled);

    let content = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    let mut got: Vec<String> = parse_json_lines(&content)
        .iter()
        .map(|row| row["ip"].as_str().unwrap().to_owned())
        .collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            "192.168.0.1".to_owned(),
            "192.168.0.2".to_owned(),
            "192.168.0.3".to_owned()
        ],
        "shuffle under cancel must remain a permutation"
    );
}

#[test]
fn second_ctrl_c_press_forces_the_exit() {
    // One press stays on the graceful path; another press must quit.
    assert!(!should_force_exit(1));
    assert!(should_force_exit(2));
    assert!(should_force_exit(3));
}

// Yields its items in order and records whether any item past `allowed`
// ever left the stream — the marker of an upstream that kept running after
// the output limit had already been satisfied.
struct EarlyStopProbe {
    items: std::vec::IntoIter<Proxy>,
    allowed: usize,
    yielded: usize,
    over_limit_polled: Arc<std::sync::atomic::AtomicBool>,
}

impl EarlyStopProbe {
    fn new(items: Vec<Proxy>, allowed: usize) -> (Self, Arc<std::sync::atomic::AtomicBool>) {
        let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
        (
            Self {
                items: items.into_iter(),
                allowed,
                yielded: 0,
                over_limit_polled: Arc::clone(&flag),
            },
            flag,
        )
    }
}

impl futures_util::Stream for EarlyStopProbe {
    type Item = Proxy;

    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Proxy>> {
        match self.items.next() {
            Some(proxy) => {
                self.yielded += 1;
                if self.yielded > self.allowed {
                    self.over_limit_polled
                        .store(true, std::sync::atomic::Ordering::Relaxed);
                }
                std::task::Poll::Ready(Some(proxy))
            }
            None => std::task::Poll::Ready(None),
        }
    }
}

#[test]
fn process_result_sort_stops_collecting_once_the_limit_is_reached() {
    let proxies = vec![
        validated_proxy(1, "HTTP:Anonymous", 0.9),
        validated_proxy(2, "HTTP:Anonymous", 0.1),
        validated_proxy(3, "HTTP:Anonymous", 0.7),
        validated_proxy(4, "HTTP:Anonymous", 0.2),
        validated_proxy(5, "HTTP:Anonymous", 0.8),
    ];
    let (options, path) = output_options("json-lines", 3);
    let options = OutputOptions {
        sort: Some("avg-response".to_owned()),
        order: "asc".to_owned(),
        ..options
    };
    let (source, over_limit_polled) = EarlyStopProbe::new(proxies, options.limit);
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    let outcome = rt.block_on(async {
        process_result(
            source,
            options,
            Arc::new(tokio::sync::Notify::new()),
            &NoopGuard,
            FinalizeOpts::default(),
        )
        .await
        .unwrap()
    });
    assert_eq!(outcome, RunOutcome::Finished);

    assert!(
        !over_limit_polled.load(std::sync::atomic::Ordering::Relaxed),
        "the upstream must be dropped once enough results exist"
    );

    // First-arrival semantics: the first three matches are kept and sorted
    // among themselves — a global best-of-three would be [0.1, 0.2, 0.7].
    let content = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    let rows = parse_json_lines(&content);
    assert_eq!(rows.len(), 3);
    let times: Vec<f64> = rows
        .iter()
        .map(|row| row["average_response_time"].as_f64().unwrap())
        .collect();
    assert_eq!(times, vec![0.1, 0.7, 0.9]);
}

#[test]
fn process_result_shuffle_stops_collecting_once_the_limit_is_reached() {
    let proxies = vec![sample_proxy(1), sample_proxy(2), sample_proxy(3)];
    let (options, path) = output_options("json-lines", 2);
    let options = OutputOptions {
        shuffle: true,
        ..options
    };
    let (source, over_limit_polled) = EarlyStopProbe::new(proxies, options.limit);
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    let outcome = rt.block_on(async {
        process_result(
            source,
            options,
            Arc::new(tokio::sync::Notify::new()),
            &NoopGuard,
            FinalizeOpts::default(),
        )
        .await
        .unwrap()
    });
    assert_eq!(outcome, RunOutcome::Finished);
    assert!(
        !over_limit_polled.load(std::sync::atomic::Ordering::Relaxed),
        "shuffle must not keep the upstream running past the limit"
    );
    let content = std::fs::read_to_string(&path).unwrap();
    let _ = std::fs::remove_file(&path);
    assert_eq!(parse_json_lines(&content).len(), 2);
}

#[test]
fn clap_defaults_match_facade_defaults_field_by_field() {
    use clap::CommandFactory;

    fn clap_default(cmd: &clap::Command, id: &str) -> String {
        fn argument_default(cmd: &clap::Command, id: &str) -> Option<String> {
            let own = cmd
                .get_arguments()
                .find(|argument| argument.get_id() == id)
                .and_then(|argument| argument.get_default_values().first())
                .map(|value| value.to_string_lossy().into_owned());
            own.or_else(|| {
                cmd.get_subcommands()
                    .find_map(|sub| argument_default(sub, id))
            })
        }
        argument_default(cmd, id).unwrap_or_else(|| panic!("argument `{id}` has no default value"))
    }

    let command = Cli::command();
    let fetcher = flx::FetcherConfig::default();
    let validator = flx::ValidatorConfig::default();

    assert_eq!(
        clap_default(&command, "fetch_concurrency"),
        fetcher.concurrency_limit.to_string(),
        "--fetch-concurrency must track FetcherConfig::default()"
    );
    assert_eq!(
        clap_default(&command, "cache_ttl"),
        flx::fetcher::DEFAULT_CACHE_TTL_MINUTES.to_string(),
        "--cache-ttl must track DEFAULT_CACHE_TTL_MINUTES"
    );
    assert_eq!(
        fetcher.cache_ttl,
        Some(std::time::Duration::from_secs(15 * 60))
    );
    assert_eq!(
        clap_default(&command, "fetch_phase_timeout"),
        flx::fetcher::PRIMARY_PHASE_TIMEOUT.as_secs().to_string(),
        "--fetch-phase-timeout must track PRIMARY_PHASE_TIMEOUT"
    );
    assert_eq!(
        clap_default(&command, "max_connections"),
        validator.concurrency_limit.to_string(),
        "--max-connections must track ValidatorConfig::default()"
    );
    assert_eq!(
        clap_default(&command, "timeout"),
        validator.request_timeout.to_string(),
        "--timeout must track ValidatorConfig request_timeout"
    );

    let http_judges: Vec<String> = clap_default(&command, "http_judge_urls")
        .split(',')
        .map(str::to_owned)
        .collect();
    assert_eq!(
        http_judges,
        flx::validator::DEFAULT_HTTP_JUDGE_URLS
            .iter()
            .map(|url| url.to_string())
            .collect::<Vec<_>>(),
        "--http-judge-urls must track DEFAULT_HTTP_JUDGE_URLS"
    );
    let https_judges: Vec<String> = clap_default(&command, "https_judge_urls")
        .split(',')
        .map(str::to_owned)
        .collect();
    assert_eq!(
        https_judges,
        flx::validator::DEFAULT_HTTPS_JUDGE_URLS
            .iter()
            .map(|url| url.to_string())
            .collect::<Vec<_>>(),
        "--https-judge-urls must track DEFAULT_HTTPS_JUDGE_URLS"
    );
}

fn run_with_stats(proxies: &[Proxy]) -> Option<String> {
    let stats = super::output::RunStats::new();
    let (options, path) = output_options("json-lines", 0);
    let rt = runtime::Builder::new_current_thread().build().unwrap();
    rt.block_on(async {
        let s = stream::iter(proxies.to_vec());
        process_result(
            s,
            options,
            Arc::new(tokio::sync::Notify::new()),
            &NoopGuard,
            FinalizeOpts {
                stats: Some(Arc::clone(&stats)),
                ..FinalizeOpts::default()
            },
        )
        .await
        .unwrap();
    });
    let _ = std::fs::remove_file(&path);
    stats.summary()
}

#[test]
fn run_stats_aggregates_protocol_families_and_countries() {
    use flx::proxy::models::ProxyType;
    let mut mixed = validated_proxy(1, "HTTP:Anonymous", 0.2);
    mixed.proxy_types.push(ProxyType::checked(Protocol::Socks5));
    let mut elite = validated_proxy(2, "HTTP:Elite", 0.2);
    elite.geo = Arc::new(flx::GeoData {
        iso_code: Some("ID".into()),
        ..flx::GeoData::default()
    });
    let mut socks = validated_proxy(3, "SOCKS4", 0.2);
    socks.geo = Arc::new(flx::GeoData {
        iso_code: Some("US".into()),
        ..flx::GeoData::default()
    });

    let summary = run_with_stats(&[mixed, elite, socks]).expect("non-empty summary");
    assert!(summary.contains("HTTP: 2"), "{summary}");
    assert!(summary.contains("SOCKS5: 1"), "{summary}");
    assert!(summary.contains("SOCKS4: 1"), "{summary}");
    assert!(summary.contains("top: ID 1, US 1"), "{summary}");
}

#[test]
fn run_stats_summary_is_none_for_an_empty_run() {
    assert!(run_with_stats(&[]).is_none());
}
