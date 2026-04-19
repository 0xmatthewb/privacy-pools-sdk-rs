fn assurance(args: Vec<String>) -> Result<()> {
    let workspace_root = workspace_root()?;
    let options = AssuranceOptions::parse(args, &workspace_root)?;
    run_assurance(&workspace_root, &options)
}

fn assurance_merge(args: Vec<String>) -> Result<()> {
    let workspace_root = workspace_root()?;
    let options = AssuranceMergeOptions::parse(args)?;
    merge_assurance_outputs(&workspace_root, &options)
}

fn audit_pack(args: Vec<String>) -> Result<()> {
    let workspace_root = workspace_root()?;
    let options =
        AssuranceOptions::from_audit_pack(AuditPackOptions::parse(args, &workspace_root)?);
    run_assurance(&workspace_root, &options)
}

fn external_evidence_assemble(args: Vec<String>) -> Result<()> {
    let workspace_root = workspace_root()?;
    let options = ExternalEvidenceAssembleOptions::parse(args, &workspace_root)?;
    let commit = current_git_commit(&workspace_root)?;
    let manifest = assemble_external_evidence_dir(&workspace_root, &options, &commit)
        .with_context(|| {
            format!(
                "failed to assemble {} external evidence at {}",
                options.mode.as_str(),
                options.out_dir
            )
        })?;

    println!("external-evidence-assemble ok");
    println!("mode: {}", options.mode.as_str());
    println!("commit: {commit}");
    println!("output directory: {}", options.out_dir);
    println!(
        "reference performance: {}",
        manifest["referencePerformance"]["status"]
            .as_str()
            .unwrap_or("unknown")
    );
    Ok(())
}
