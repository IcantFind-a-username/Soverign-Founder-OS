# Repository conventions for AI-assisted sessions

## Git

- Branch names use conventional prefixes only: `feature/`, `hotfix/`, `fix/`,
  `chore/`, `docs/`, `refactor/`. Never use `claude/`, `ai/`, or any tool-named
  branch prefix.
- Do not add AI attribution to commits: no `Co-Authored-By: Claude` (or
  similar) trailers, no AI names or emails as author or committer, no session
  links. Author and committer are the repository owner's identity.
- Use conventional commit messages (`feat(scope): …`, `fix(scope): …`).
- Do not create pull requests unless explicitly asked.

## Validation before any commit

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace
```

## Source of truth

Current implementation plus RFCs under `rfcs/` take precedence over other
docs. Keep maturity labels honest: current vs. target vs. simulated. Never
claim absolute security.
