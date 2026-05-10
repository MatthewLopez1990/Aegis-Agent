# Install

Aegis Agent installs as a Python command-line app. Linux and macOS users should only need one command.

## From This Checkout

Run from the repository root:

```bash
./install.sh
```

That creates:

- Preferred install: `~/.aegis-agent/venv`
- Fallback install when `python3-venv`/`ensurepip` is unavailable: `~/.aegis-agent/source`
- Command shim: `~/.local/bin/aegis`

## From a Published Archive

Once the project is published, use one command like this:

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/aegis-agent/main/install.sh | sh -s -- --archive https://github.com/YOUR_ORG/aegis-agent/archive/refs/heads/main.tar.gz
```

## From a Git Repo

```bash
curl -fsSL https://raw.githubusercontent.com/YOUR_ORG/aegis-agent/main/install.sh | sh -s -- --repo https://github.com/YOUR_ORG/aegis-agent.git
```

Use `--archive` if the target machine does not have `git`.

## Custom Location

```bash
./install.sh --install-dir "$HOME/Applications/aegis-agent" --bin-dir "$HOME/bin"
```

## Verify

```bash
aegis --help
aegis tui
aegis serve --host 127.0.0.1 --port 8765
```

No `sudo`, npm, pnpm, yarn, or system package install is required by the current MVP. If Python virtual environments are unavailable, the installer automatically falls back to a source-copy launcher because Aegis currently has no third-party runtime dependencies.
