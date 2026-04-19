fn current_git_commit(workspace_root: &Utf8PathBuf) -> Result<String> {
    Ok(command_stdout(
        "git",
        &["rev-parse", "HEAD"],
        workspace_root,
        "git rev-parse HEAD failed",
    )?
    .trim()
    .to_owned())
}

fn current_git_branch(workspace_root: &Utf8PathBuf) -> Result<String> {
    Ok(command_stdout(
        "git",
        &["branch", "--show-current"],
        workspace_root,
        "git branch --show-current failed",
    )?
    .trim()
    .to_owned())
}

fn current_github_repository_slug(workspace_root: &Utf8PathBuf) -> Result<String> {
    let remote = command_stdout(
        "git",
        &["config", "--get", "remote.origin.url"],
        workspace_root,
        "git config --get remote.origin.url failed",
    )?;
    parse_github_repository_slug(remote.trim()).with_context(|| {
        format!(
            "failed to parse GitHub repository slug from remote origin URL `{}`",
            remote.trim()
        )
    })
}

fn parse_github_repository_slug(remote: &str) -> Result<String> {
    let trimmed = remote.trim().trim_end_matches(".git");
    if let Some(rest) = trimmed.strip_prefix("https://github.com/") {
        return Ok(rest.trim_start_matches('/').to_owned());
    }
    if let Some(rest) = trimmed.strip_prefix("ssh://git@github.com/") {
        return Ok(rest.trim_start_matches('/').to_owned());
    }
    if let Some(rest) = trimmed.strip_prefix("git@github.com:") {
        return Ok(rest.trim_start_matches('/').to_owned());
    }
    bail!("unsupported remote origin URL: {trimmed}")
}

