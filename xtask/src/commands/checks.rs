fn examples_check() -> Result<()> {
    let workspace_root = workspace_root()?;
    let examples_dir = workspace_root.join("crates/privacy-pools-sdk/examples");
    let examples = discover_example_names(&examples_dir)?;
    validate_required_examples(&examples)?;

    for example in required_example_names() {
        run_command(
            "cargo",
            &["run", "--locked", "-p", "privacy-pools-sdk", "--example", example],
            &workspace_root,
            &format!("Rust SDK example `{example}` failed"),
        )?;
    }

    println!("examples-check ok");
    Ok(())
}

fn feature_check() -> Result<()> {
    let workspace_root = workspace_root()?;

    for command in feature_check_commands() {
        run_command(
            command.program,
            command.args,
            &workspace_root,
            command.error_context,
        )?;
    }

    println!("feature-check ok");
    Ok(())
}

fn package_check() -> Result<()> {
    use cargo_metadata::MetadataCommand;

    let workspace_root = workspace_root()?;
    let metadata = MetadataCommand::new()
        .current_dir(&workspace_root)
        .no_deps()
        .exec()
        .context("failed to load cargo metadata for package-check")?;
    let workspace_members: std::collections::BTreeSet<_> =
        metadata.workspace_members.iter().cloned().collect();
    let publishable_packages: Vec<_> = metadata
        .packages
        .iter()
        .filter(|package| workspace_members.contains(&package.id))
        .filter(|package| {
            !matches!(
                package.publish.as_ref(),
                Some(registries) if registries.is_empty()
            )
        })
        .map(|package| package.name.to_string())
        .collect();

    ensure!(
        !publishable_packages.is_empty(),
        "package-check could not find any publishable workspace crates"
    );

    let package_args = package_check_args(&publishable_packages);
    let package_args_ref: Vec<&str> = package_args.iter().map(String::as_str).collect();
    run_command(
        "cargo",
        &package_args_ref,
        &workspace_root,
        "workspace package dry run failed",
    )?;

    println!("package-check ok");
    Ok(())
}

fn dependency_check() -> Result<()> {
    let workspace_root = workspace_root()?;
    let policy = read_advisory_policy(&workspace_root)?;
    let deny_ignore = read_deny_advisory_ids(&workspace_root)?;

    ensure!(
        deny_ignore == policy.cargo_deny_ignore,
        "deny.toml advisory ignore set is out of sync with security/advisories.toml: expected {:?}, found {:?}",
        policy.cargo_deny_ignore,
        deny_ignore
    );

    let audit_args = audit_command_args(&policy.cargo_audit_ignore);
    let audit_args_ref: Vec<&str> = audit_args.iter().map(String::as_str).collect();
    let audit_stdout = command_stdout(
        "cargo",
        &audit_args_ref,
        &workspace_root,
        "cargo audit failed",
    )?;
    let audit_json: Value =
        serde_json::from_str(&audit_stdout).context("failed to parse cargo audit JSON output")?;

    let vulnerabilities_found = audit_json
        .get("vulnerabilities")
        .and_then(|value| value.get("found"))
        .and_then(Value::as_bool)
        .unwrap_or(false);
    ensure!(
        !vulnerabilities_found,
        "cargo audit reported blocking vulnerabilities"
    );

    let mut advisory_ids = collect_advisory_ids(&audit_json, "unmaintained");
    advisory_ids.extend(collect_advisory_ids(&audit_json, "unsound"));
    advisory_ids.sort_unstable();

    ensure!(
        advisory_ids == policy.dependency_check_warnings,
        "unexpected dependency advisory set: expected {:?}, found {:?}",
        policy.dependency_check_warnings,
        advisory_ids
    );

    if advisory_ids
        .iter()
        .any(|advisory| advisory == "RUSTSEC-2026-0097")
    {
        let rand_tree = command_stdout(
            "cargo",
            &[
                "tree",
                "-e",
                "features",
                "-i",
                "rand@0.8.5",
                "-p",
                "privacy-pools-sdk",
            ],
            &workspace_root,
            "cargo tree for rand 0.8.5 failed",
        )?;
        ensure!(
            !rand_tree.contains("rand feature \"log\""),
            "rand 0.8.5 advisory became reachable because the `log` feature is enabled"
        );
    }

    println!("dependency-check ok");
    println!("accepted advisories: {}", advisory_ids.join(", "));
    println!(
        "cargo audit ignores: {}",
        policy.cargo_audit_ignore.join(", ")
    );
    println!(
        "cargo deny ignores: {}",
        policy.cargo_deny_ignore.join(", ")
    );
    println!("rand 0.8.5 reachable condition: `log` feature disabled");
    Ok(())
}

fn docs_check() -> Result<()> {
    let workspace_root = workspace_root()?;
    let policy = read_advisory_policy(&workspace_root)?;

    let dependency_audit =
        read_required_text_file(&workspace_root.join("docs/dependency-audit.md"))?;
    ensure!(
        dependency_audit.contains("security/advisories.toml"),
        "docs/dependency-audit.md must reference security/advisories.toml"
    );
    ensure!(
        collect_rustsec_ids(&dependency_audit) == policy.all_ids(),
        "docs/dependency-audit.md advisory IDs are out of sync with security/advisories.toml"
    );

    let release_checklist = read_required_text_file(&workspace_root.join("RELEASE_CHECKLIST.md"))?;
    ensure!(
        release_checklist.contains("security/advisories.toml"),
        "RELEASE_CHECKLIST.md must reference security/advisories.toml"
    );
    ensure!(
        release_checklist.contains("cargo vet"),
        "RELEASE_CHECKLIST.md must mention cargo vet"
    );

    let security_policy = read_required_text_file(&workspace_root.join("SECURITY.md"))?;
    ensure!(
        security_policy.contains("security/advisories.toml"),
        "SECURITY.md must reference security/advisories.toml"
    );

    println!("docs-check ok");
    Ok(())
}

fn preflight() -> Result<()> {
    assurance(vec![
        "--profile".to_owned(),
        "pr".to_owned(),
        "--runtime".to_owned(),
        "rust".to_owned(),
    ])
}

fn action_pins() -> Result<()> {
    let workspace_root = workspace_root()?;
    let github_root = workspace_root.join(".github");
    let mut files = Vec::new();
    collect_files_recursive(&github_root, &mut files)?;
    files.sort();

    let mut offenders = Vec::new();
    for path in files {
        let is_yaml = matches!(path.extension(), Some("yml" | "yaml"));
        let is_composite_action = path.file_name() == Some("action.yml");
        if !is_yaml && !is_composite_action {
            continue;
        }

        let contents = read_required_text_file(&path)?;
        let display_path = path
            .strip_prefix(&workspace_root)
            .unwrap_or_else(|_| path.as_path());
        for (index, line) in contents.lines().enumerate() {
            let trimmed = line.trim_start();
            if !trimmed.starts_with("uses:") {
                continue;
            }
            let raw_value = trimmed.trim_start_matches("uses:").trim();
            let value = raw_value.split_whitespace().next().unwrap_or(raw_value);
            if value.starts_with("./") {
                continue;
            }

            let Some((_, pin)) = value.rsplit_once('@') else {
                offenders.push(format!("{display_path}:{}: {value}", index + 1));
                continue;
            };
            if pin.len() == 40 && pin.bytes().all(|byte| byte.is_ascii_hexdigit()) {
                continue;
            }

            offenders.push(format!("{display_path}:{}: {value}", index + 1));
        }
    }

    ensure!(
        offenders.is_empty(),
        "Actions must be pinned to a 40-char SHA:\n{}",
        offenders.join("\n")
    );
    println!("action-pins ok");
    Ok(())
}

fn check_internal_cycles() -> Result<()> {
    use cargo_metadata::{DependencyKind, MetadataCommand, PackageId};
    use std::collections::{BTreeMap, BTreeSet};

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum VisitState {
        Visiting,
        Visited,
    }

    fn package_label(names: &BTreeMap<PackageId, String>, package_id: &PackageId) -> String {
        names
            .get(package_id)
            .cloned()
            .unwrap_or_else(|| package_id.repr.clone())
    }

    fn find_cycle(
        node: &PackageId,
        edges: &BTreeMap<PackageId, Vec<PackageId>>,
        names: &BTreeMap<PackageId, String>,
        states: &mut BTreeMap<PackageId, VisitState>,
        stack: &mut Vec<PackageId>,
    ) -> Option<String> {
        states.insert(node.clone(), VisitState::Visiting);
        stack.push(node.clone());

        if let Some(children) = edges.get(node) {
            for child in children {
                match states.get(child) {
                    Some(VisitState::Visiting) => {
                        let start = stack.iter().position(|entry| entry == child).unwrap_or(0);
                        let mut cycle: Vec<String> = stack[start..]
                            .iter()
                            .map(|package_id| package_label(names, package_id))
                            .collect();
                        cycle.push(package_label(names, child));
                        return Some(cycle.join(" -> "));
                    }
                    Some(VisitState::Visited) => {}
                    None => {
                        if let Some(cycle) = find_cycle(child, edges, names, states, stack) {
                            return Some(cycle);
                        }
                    }
                }
            }
        }

        stack.pop();
        states.insert(node.clone(), VisitState::Visited);
        None
    }

    let workspace_root = workspace_root()?;
    let metadata = MetadataCommand::new()
        .current_dir(&workspace_root)
        .exec()
        .context("failed to load cargo metadata for cycle detection")?;
    let resolve = metadata
        .resolve
        .context("cargo metadata did not include a dependency graph")?;
    let workspace_members: BTreeSet<_> = metadata.workspace_members.iter().cloned().collect();
    let package_names: BTreeMap<_, _> = metadata
        .packages
        .iter()
        .filter(|package| workspace_members.contains(&package.id))
        .map(|package| (package.id.clone(), package.name.to_string()))
        .collect();

    let mut edges: BTreeMap<PackageId, Vec<PackageId>> = BTreeMap::new();
    for node in resolve.nodes {
        if !workspace_members.contains(&node.id) {
            continue;
        }

        let mut deps = Vec::new();
        for dependency in node.deps {
            if !workspace_members.contains(&dependency.pkg) {
                continue;
            }
            let include_edge = dependency.dep_kinds.is_empty()
                || dependency
                    .dep_kinds
                    .iter()
                    .any(|kind| kind.kind != DependencyKind::Development);
            if include_edge {
                deps.push(dependency.pkg);
            }
        }
        deps.sort();
        deps.dedup();
        edges.insert(node.id, deps);
    }

    let mut states = BTreeMap::new();
    let mut stack = Vec::new();
    for package_id in package_names.keys() {
        if states.contains_key(package_id) {
            continue;
        }
        if let Some(cycle) = find_cycle(package_id, &edges, &package_names, &mut states, &mut stack)
        {
            bail!("workspace-internal dependency cycle detected: {cycle}");
        }
    }

    println!("check-internal-cycles ok");
    Ok(())
}

#[derive(Debug, Default, Deserialize)]
struct BindingParityAllowlist {
    #[serde(default)]
    safe_exports: BindingParityExportAllowlist,
    #[serde(default)]
    error_variants: BindingParityVariantAllowlist,
}

#[derive(Debug, Default, Deserialize)]
struct BindingParityExportAllowlist {
    #[serde(default)]
    browser: Vec<String>,
    #[serde(default)]
    node: Vec<String>,
    #[serde(default)]
    dts: Vec<String>,
    #[serde(default)]
    react_native: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct BindingParityVariantAllowlist {
    #[serde(default)]
    web: Vec<String>,
    #[serde(default)]
    node: Vec<String>,
}

fn check_binding_parity() -> Result<()> {
    use syn::{
        ItemEnum, parse_file,
        visit::{self, Visit},
    };

    struct ErrorEnumCollector<'a> {
        target_name: &'a str,
        variants: Vec<String>,
    }

    impl<'ast> Visit<'ast> for ErrorEnumCollector<'_> {
        fn visit_item_enum(&mut self, item: &'ast ItemEnum) {
            if item.ident == self.target_name {
                self.variants = item
                    .variants
                    .iter()
                    .map(|variant| variant.ident.to_string())
                    .collect();
            }
            visit::visit_item_enum(self, item);
        }
    }

    #[derive(Clone, Copy, PartialEq, Eq)]
    enum ExportBlockKind {
        Runtime,
        TypeOnly,
    }

    fn as_set(values: &[String]) -> BTreeSet<String> {
        values.iter().cloned().collect()
    }

    fn parse_export_name(fragment: &str) -> Option<String> {
        let fragment = fragment.trim().trim_end_matches(',').trim();
        if fragment.is_empty() {
            return None;
        }
        let fragment = fragment
            .split_once(" as ")
            .map(|(name, _)| name)
            .unwrap_or(fragment)
            .trim()
            .trim_matches('`');
        if fragment.is_empty() {
            None
        } else {
            Some(fragment.to_owned())
        }
    }

    fn parse_export_block_line(exports: &mut BTreeSet<String>, line: &str) {
        for fragment in line.split(',') {
            if let Some(name) = parse_export_name(fragment) {
                exports.insert(name);
            }
        }
    }

    fn collect_runtime_exports(path: &Utf8PathBuf) -> Result<BTreeSet<String>> {
        let contents = read_required_text_file(path)?;
        let mut exports = BTreeSet::new();
        let mut block_kind = None;

        for line in contents.lines() {
            let trimmed = line.trim();
            if let Some(kind) = block_kind {
                if let Some((before_close, _)) = trimmed.split_once('}') {
                    if kind == ExportBlockKind::Runtime {
                        parse_export_block_line(&mut exports, before_close);
                    }
                    block_kind = None;
                    continue;
                }
                if kind == ExportBlockKind::Runtime {
                    parse_export_block_line(&mut exports, trimmed);
                }
                continue;
            }

            if let Some(rest) = trimmed.strip_prefix("export function ") {
                if let Some((name, _)) = rest.split_once('(') {
                    exports.insert(name.trim().to_owned());
                }
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("export class ") {
                if let Some(name) = rest.split_whitespace().next() {
                    exports.insert(name.trim().to_owned());
                }
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("export const ") {
                if let Some((name, _)) = rest.split_once([' ', ':', '=']) {
                    exports.insert(name.trim().to_owned());
                }
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("export interface ") {
                if let Some(name) = rest.split_whitespace().next() {
                    exports.insert(name.trim().to_owned());
                }
                continue;
            }
            if trimmed.starts_with("export type {") {
                block_kind = Some(ExportBlockKind::TypeOnly);
                continue;
            }
            if let Some(rest) = trimmed.strip_prefix("export {") {
                if let Some((inline, _)) = rest.split_once('}') {
                    parse_export_block_line(&mut exports, inline);
                } else {
                    block_kind = Some(ExportBlockKind::Runtime);
                }
            }
        }

        Ok(exports)
    }

    fn collect_kotlin_ffi_functions(path: &Utf8PathBuf) -> Result<BTreeSet<String>> {
        let contents = read_required_text_file(path)?;
        let mut functions = BTreeSet::new();
        for line in contents.lines() {
            let Some((_, tail)) = line.split_once("fun ") else {
                continue;
            };
            let tail = tail.trim_start();
            let tail = tail.strip_prefix('`').unwrap_or(tail);
            let Some((name, _)) = tail.split_once('(') else {
                continue;
            };
            functions.insert(name.trim_matches('`').trim().to_owned());
        }
        Ok(functions)
    }

    fn collect_swift_public_functions(path: &Utf8PathBuf) -> Result<BTreeSet<String>> {
        let contents = read_required_text_file(path)?;
        let mut functions = BTreeSet::new();
        for line in contents.lines() {
            let trimmed = line.trim();
            let Some(rest) = trimmed.strip_prefix("public func ") else {
                continue;
            };
            let Some((name, _)) = rest.split_once('(') else {
                continue;
            };
            functions.insert(name.trim().to_owned());
        }
        Ok(functions)
    }

    fn collect_enum_variants(path: &Utf8PathBuf, enum_name: &str) -> Result<BTreeSet<String>> {
        let source = read_required_text_file(path)?;
        let file = parse_file(&source).with_context(|| format!("failed to parse {path}"))?;
        let mut collector = ErrorEnumCollector {
            target_name: enum_name,
            variants: Vec::new(),
        };
        collector.visit_file(&file);
        ensure!(
            !collector.variants.is_empty(),
            "enum {enum_name} not found in {path}"
        );
        Ok(collector.variants.into_iter().collect())
    }

    fn push_surface_mismatches(
        findings: &mut Vec<String>,
        left_name: &str,
        left: &BTreeSet<String>,
        left_allowlist: &BTreeSet<String>,
        right_name: &str,
        right: &BTreeSet<String>,
        right_allowlist: &BTreeSet<String>,
    ) {
        let left_only: Vec<_> = left
            .difference(right)
            .filter(|name| !left_allowlist.contains(*name))
            .cloned()
            .collect();
        if !left_only.is_empty() {
            findings.push(format!(
                "{left_name} exports not present in {right_name}: {}",
                left_only.join(", ")
            ));
        }

        let right_only: Vec<_> = right
            .difference(left)
            .filter(|name| !right_allowlist.contains(*name))
            .cloned()
            .collect();
        if !right_only.is_empty() {
            findings.push(format!(
                "{right_name} exports not present in {left_name}: {}",
                right_only.join(", ")
            ));
        }
    }

    let workspace_root = workspace_root()?;
    let allowlist_path = workspace_root.join(".github/binding-parity-allowlist.toml");
    let allowlist: BindingParityAllowlist =
        toml::from_str(&read_required_text_file(&allowlist_path)?)
            .with_context(|| format!("failed to parse {}", allowlist_path))?;

    let browser_exports =
        collect_runtime_exports(&workspace_root.join("packages/sdk/src/browser/safe.mjs"))?;
    let node_exports =
        collect_runtime_exports(&workspace_root.join("packages/sdk/src/node/safe.mjs"))?;
    let mut dts_exports =
        collect_runtime_exports(&workspace_root.join("packages/sdk/src/safe.d.ts"))?;
    dts_exports.extend(collect_runtime_exports(
        &workspace_root.join("packages/sdk/src/types.d.ts"),
    )?);
    let react_native_exports =
        collect_runtime_exports(&workspace_root.join("packages/react-native/src/safe.ts"))?;
    let kotlin_exports = collect_kotlin_ffi_functions(
        &workspace_root.join(
            "bindings/android/generated/src/main/java/io/oxbow/privacypoolssdk/privacy_pools_sdk_ffi.kt",
        ),
    )?;
    let swift_exports = collect_swift_public_functions(
        &workspace_root.join("bindings/ios/generated/PrivacyPoolsSdk.swift"),
    )?;

    let mut findings = Vec::new();
    push_surface_mismatches(
        &mut findings,
        "browser safe.mjs",
        &browser_exports,
        &as_set(&allowlist.safe_exports.browser),
        "node safe.mjs",
        &node_exports,
        &as_set(&allowlist.safe_exports.node),
    );
    push_surface_mismatches(
        &mut findings,
        "browser safe.mjs",
        &browser_exports,
        &as_set(&allowlist.safe_exports.browser),
        "safe.d.ts",
        &dts_exports,
        &as_set(&allowlist.safe_exports.dts),
    );
    push_surface_mismatches(
        &mut findings,
        "node safe.mjs",
        &node_exports,
        &as_set(&allowlist.safe_exports.node),
        "safe.d.ts",
        &dts_exports,
        &as_set(&allowlist.safe_exports.dts),
    );

    let react_native_required: BTreeSet<_> = react_native_exports
        .difference(&as_set(&allowlist.safe_exports.react_native))
        .cloned()
        .collect();
    let missing_from_kotlin: Vec<_> = react_native_required
        .difference(&kotlin_exports)
        .cloned()
        .collect();
    if !missing_from_kotlin.is_empty() {
        findings.push(format!(
            "react-native safe exports missing in generated Android bindings: {}",
            missing_from_kotlin.join(", ")
        ));
    }
    let missing_from_swift: Vec<_> = react_native_required
        .difference(&swift_exports)
        .cloned()
        .collect();
    if !missing_from_swift.is_empty() {
        findings.push(format!(
            "react-native safe exports missing in generated iOS bindings: {}",
            missing_from_swift.join(", ")
        ));
    }

    let core_error_variants = collect_enum_variants(
        &workspace_root.join("crates/privacy-pools-sdk-bindings-core/src/error.rs"),
        "BindingCoreError",
    )?;
    let web_error_variants = collect_enum_variants(
        &workspace_root.join("crates/privacy-pools-sdk-web/src/error.rs"),
        "WebError",
    )?;
    let node_error_variants = collect_enum_variants(
        &workspace_root.join("crates/privacy-pools-sdk-node/src/lib.rs"),
        "NodeError",
    )?;
    let missing_from_web: Vec<_> = core_error_variants
        .difference(&web_error_variants)
        .cloned()
        .collect();
    if !missing_from_web.is_empty() {
        findings.push(format!(
            "WebError is missing BindingCoreError variants: {}",
            missing_from_web.join(", ")
        ));
    }
    let unexpected_web: Vec<_> = web_error_variants
        .difference(&core_error_variants)
        .filter(|variant| !allowlist.error_variants.web.contains(*variant))
        .cloned()
        .collect();
    if !unexpected_web.is_empty() {
        findings.push(format!(
            "WebError has unallowlisted extra variants: {}",
            unexpected_web.join(", ")
        ));
    }

    let missing_from_node: Vec<_> = core_error_variants
        .difference(&node_error_variants)
        .cloned()
        .collect();
    if !missing_from_node.is_empty() {
        findings.push(format!(
            "NodeError is missing BindingCoreError variants: {}",
            missing_from_node.join(", ")
        ));
    }
    let unexpected_node: Vec<_> = node_error_variants
        .difference(&core_error_variants)
        .filter(|variant| !allowlist.error_variants.node.contains(*variant))
        .cloned()
        .collect();
    if !unexpected_node.is_empty() {
        findings.push(format!(
            "NodeError has unallowlisted extra variants: {}",
            unexpected_node.join(", ")
        ));
    }

    ensure!(
        findings.is_empty(),
        "binding parity drift detected:\n{}",
        findings.join("\n")
    );
    println!("check-binding-parity ok");
    Ok(())
}

fn ffi_input_bound_lint() -> Result<()> {
    const ACCEPTED_MARKERS: &[&str] = &[
        "validate_json_boundary",
        "parse_json",
        "parse_json_with_limit",
        "parse_manifest(",
        "artifact_statuses_json(",
        "resolve_verified_artifact_bundle_json(",
        "parse_wire_withdrawal_witness_request_json(",
        "parse_wire_commitment_witness_request_json(",
        "parse_execution_policy_json(",
        "parse_recovery_policy_json(",
    ];

    fn is_candidate_signature(signature: &str) -> bool {
        signature.contains("_json: String") || signature.contains("json: String")
    }

    fn is_exempt(signature: &str, body: &str) -> bool {
        signature.contains("ffi-bound-exempt:") || body.contains("ffi-bound-exempt:")
    }

    fn has_marker(body: &str) -> bool {
        ACCEPTED_MARKERS.iter().any(|marker| body.contains(marker))
    }

    fn collect_candidate_findings(path: &Utf8PathBuf) -> Result<Vec<String>> {
        let source = read_required_text_file(path)?;
        let mut findings = Vec::new();
        let mut scan_from = 0usize;

        while let Some(relative_start) = source[scan_from..].find("pub fn ") {
            let start = scan_from + relative_start;
            let Some(relative_body_start) = source[start..].find('{') else {
                break;
            };
            let body_start = start + relative_body_start;
            let signature = &source[start..body_start];

            let mut depth = 0usize;
            let mut body_end = None;
            for (offset, ch) in source[body_start..].char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            body_end = Some(body_start + offset + 1);
                            break;
                        }
                    }
                    _ => {}
                }
            }
            let Some(body_end) = body_end else {
                bail!("failed to find the end of function starting at byte {start} in {path}");
            };
            let body = &source[body_start..body_end];

            if is_candidate_signature(signature) && !is_exempt(signature, body) && !has_marker(body)
            {
                let name = signature["pub fn ".len()..]
                    .split_once('(')
                    .map(|(name, _)| name.trim())
                    .unwrap_or("<unknown>");
                findings.push(format!(
                    "{path}: `{name}` is missing bounded JSON/byte parsing"
                ));
            }

            scan_from = body_end;
        }

        Ok(findings)
    }

    let workspace_root = workspace_root()?;
    let mut findings = Vec::new();
    for path in [
        workspace_root.join("crates/privacy-pools-sdk-ffi/src/lib.rs"),
        workspace_root.join("crates/privacy-pools-sdk-node/src/lib.rs"),
        workspace_root.join("crates/privacy-pools-sdk-web/src/lib.rs"),
    ] {
        findings.extend(collect_candidate_findings(&path)?);
    }

    ensure!(
        findings.is_empty(),
        "ffi input bound lint failures:\n{}",
        findings.join("\n")
    );
    println!("ffi-input-bound-lint ok");
    Ok(())
}

fn write_cargo_audit_config() -> Result<()> {
    let workspace_root = workspace_root()?;
    let policy = read_advisory_policy(&workspace_root)?;
    let cargo_home = env::var("CARGO_HOME")
        .map(Utf8PathBuf::from)
        .or_else(|_| env::var("HOME").map(|home| Utf8PathBuf::from(home).join(".cargo")))
        .context("failed to determine CARGO_HOME or HOME for cargo-audit config output")?;
    fs::create_dir_all(&cargo_home).with_context(|| format!("failed to create {}", cargo_home))?;

    let config_path = cargo_home.join("audit.toml");
    let ignored = policy
        .cargo_audit_ignore
        .iter()
        .map(|id| format!("\"{id}\""))
        .collect::<Vec<_>>()
        .join(", ");
    let contents = format!("[advisories]\nignore = [{ignored}]\n");
    fs::write(&config_path, contents)
        .with_context(|| format!("failed to write {}", config_path))?;

    println!("cargo-audit config written {}", config_path);
    Ok(())
}

fn artifact_fingerprints(args: Vec<String>) -> Result<()> {
    let workspace_root = workspace_root()?;
    let snapshot_path = workspace_root.join("fixtures/artifacts/fingerprints.lock.json");
    let snapshot = artifact_fingerprint_snapshot(&workspace_root)?;
    let rendered = serde_json::to_string_pretty(&snapshot)
        .context("failed to serialize artifact fingerprint snapshot")?;

    let mode = match args.as_slice() {
        [flag] if flag == "--check" => "check",
        [flag] if flag == "--update" => "update",
        [] => bail!("artifact-fingerprints requires --check or --update"),
        _ => bail!("artifact-fingerprints accepts only --check or --update"),
    };

    if mode == "update" {
        if let Some(parent) = snapshot_path.parent() {
            fs::create_dir_all(parent).with_context(|| format!("failed to create {}", parent))?;
        }
        fs::write(&snapshot_path, format!("{rendered}\n"))
            .with_context(|| format!("failed to write {}", snapshot_path))?;
        println!("artifact-fingerprints updated {}", snapshot_path);
        return Ok(());
    }

    let existing = read_required_json(&snapshot_path)?;
    ensure!(
        existing == snapshot,
        "artifact fingerprint snapshot is out of date: run `cargo run -p xtask -- artifact-fingerprints --update`"
    );
    println!("artifact-fingerprints ok");
    Ok(())
}

fn geiger_delta_check() -> Result<()> {
    let workspace_root = workspace_root()?;
    let allowlist_path = workspace_root.join("security/unsafe-allowlist.json");
    let allowlist: UnsafeAllowlist =
        serde_json::from_value(read_required_json(&allowlist_path)?)
            .with_context(|| format!("failed to parse {}", allowlist_path))?;
    let findings = workspace_unsafe_matches(&workspace_root)?;
    let allowlist_set: BTreeSet<_> = allowlist.allowed_matches.into_iter().collect();
    let findings_set: BTreeSet<_> = findings.iter().cloned().collect();
    let unexpected: Vec<_> = findings_set.difference(&allowlist_set).cloned().collect();
    ensure!(
        unexpected.is_empty(),
        "unexpected unsafe matches detected outside allowlist: {:?}",
        unexpected
    );
    println!("geiger-delta-check ok");
    println!("tracked matches: {}", findings.len());
    Ok(())
}

fn signed_manifest_sample_check() -> Result<()> {
    let workspace_root = workspace_root()?;
    let fixture_dir = workspace_root.join("fixtures/artifacts/signed-manifest");
    let public_key = env::var("PRIVACY_POOLS_SIGNED_MANIFEST_PUBLIC_KEY")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or(read_required_text_file(
            &fixture_dir.join("public-key.hex"),
        )?);
    let validated = validate_signed_manifest_directory(&fixture_dir, &public_key)?;
    println!("signed-manifest-sample-check ok");
    println!(
        "version: {}",
        validated["version"].as_str().unwrap_or("unknown")
    );
    println!(
        "artifacts: {}",
        validated["artifactCount"].as_u64().unwrap_or(0)
    );
    Ok(())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CommandSpec {
    program: &'static str,
    args: &'static [&'static str],
    error_context: &'static str,
}

fn required_example_names() -> &'static [&'static str] {
    &[
        "basic",
        "npm_migration",
        "client_builder",
        "withdrawal_paths",
        "recovery_fixture",
    ]
}

fn discover_example_names(examples_dir: &Utf8PathBuf) -> Result<Vec<String>> {
    let mut examples = Vec::new();
    for entry in fs::read_dir(examples_dir)
        .with_context(|| format!("failed to read examples directory {}", examples_dir))?
    {
        let entry = entry.with_context(|| format!("failed to read entry in {}", examples_dir))?;
        let entry_path = Utf8PathBuf::from_path_buf(entry.path())
            .map_err(|raw| anyhow::anyhow!("example path is not valid UTF-8: {:?}", raw))?;

        if !entry
            .file_type()
            .with_context(|| format!("failed to inspect {}", entry_path))?
            .is_file()
        {
            continue;
        }

        if entry_path.extension() == Some("rs") {
            examples.push(
                entry_path
                    .file_stem()
                    .context("example file path has no stem")?
                    .to_owned(),
            );
        }
    }

    examples.sort_unstable();
    Ok(examples)
}

fn validate_required_examples(examples: &[String]) -> Result<()> {
    for required in required_example_names() {
        ensure!(
            examples.iter().any(|example| example == required),
            "missing required Rust SDK example `{required}`"
        );
    }

    Ok(())
}

fn feature_check_commands() -> &'static [CommandSpec] {
    &[
        CommandSpec {
            program: "cargo",
            args: &[
                "hack",
                "check",
                "--locked",
                "-p",
                "privacy-pools-sdk-prover",
                "--each-feature",
            ],
            error_context: "privacy-pools-sdk-prover cargo-hack feature check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "--locked",
                "-p",
                "privacy-pools-sdk-prover",
                "--no-default-features",
            ],
            error_context: "privacy-pools-sdk-prover no-default-features check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "--locked",
                "-p",
                "privacy-pools-sdk-prover",
                "--all-features",
            ],
            error_context: "privacy-pools-sdk-prover all-features check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "--locked",
                "-p",
                "privacy-pools-sdk-web",
                "--target",
                "wasm32-unknown-unknown",
            ],
            error_context: "privacy-pools-sdk-web wasm32 check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "--locked",
                "-p",
                "privacy-pools-sdk-web",
                "--no-default-features",
                "--features",
                "dangerous-exports",
                "--target",
                "wasm32-unknown-unknown",
            ],
            error_context: "privacy-pools-sdk-web dangerous-exports gate check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "--locked",
                "-p",
                "privacy-pools-sdk-signer",
                "--no-default-features",
            ],
            error_context: "privacy-pools-sdk-signer default gate check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "--locked",
                "-p",
                "privacy-pools-sdk-signer",
                "--no-default-features",
                "--features",
                "local-mnemonic",
            ],
            error_context: "privacy-pools-sdk-signer local-mnemonic gate check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "--locked",
                "-p",
                "privacy-pools-sdk-signer",
                "--no-default-features",
                "--features",
                "dangerous-key-export",
            ],
            error_context: "privacy-pools-sdk-signer dangerous-key-export gate check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "--locked",
                "-p",
                "privacy-pools-sdk-chain",
                "--no-default-features",
                "--features",
                "local-signer-client",
            ],
            error_context: "privacy-pools-sdk-chain local-signer-client gate check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "--locked",
                "-p",
                "privacy-pools-sdk-node",
                "--no-default-features",
            ],
            error_context: "privacy-pools-sdk-node default feature gate check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "--locked",
                "-p",
                "privacy-pools-sdk-node",
                "--no-default-features",
                "--features",
                "dangerous-exports",
            ],
            error_context: "privacy-pools-sdk-node dangerous-exports gate check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "--locked",
                "-p",
                "privacy-pools-sdk-ffi",
                "--no-default-features",
            ],
            error_context: "privacy-pools-sdk-ffi default feature gate check failed",
        },
        CommandSpec {
            program: "cargo",
            args: &[
                "check",
                "--locked",
                "-p",
                "privacy-pools-sdk-ffi",
                "--no-default-features",
                "--features",
                "dangerous-exports",
            ],
            error_context: "privacy-pools-sdk-ffi dangerous-exports gate check failed",
        },
    ]
}

fn package_check_args(packages: &[String]) -> Vec<String> {
    let mut args = vec![
        "package".to_owned(),
        "--allow-dirty".to_owned(),
        "--no-verify".to_owned(),
        "--locked".to_owned(),
    ];
    for package in packages {
        args.push("-p".to_owned());
        args.push(package.clone());
    }
    args
}
