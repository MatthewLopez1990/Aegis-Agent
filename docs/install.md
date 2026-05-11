# Install

Aegis Agent installs as a Python command-line app. Linux and macOS users should only need one command.

## From This Checkout

Run from the repository root:

```bash
./install.sh
```

## One Command From GitHub

For a user-local install from the main branch:

```bash
curl -fsSL https://raw.githubusercontent.com/MatthewLopez1990/Aegis-Agent/main/install.sh | sh
```

That creates:

- Preferred install: `~/.aegis-agent/venv`
- Fallback install when `python3-venv`/`ensurepip` is unavailable: `~/.aegis-agent/source`
- Command shim: `~/.local/bin/aegis`

## From a Specific Archive

Use an explicit archive URL when you want to pin a branch, tag, or fork:

```bash
curl -fsSL https://raw.githubusercontent.com/MatthewLopez1990/Aegis-Agent/main/install.sh | sh -s -- --archive https://github.com/MatthewLopez1990/Aegis-Agent/archive/refs/heads/main.tar.gz
```

## From a Git Repo

```bash
curl -fsSL https://raw.githubusercontent.com/MatthewLopez1990/Aegis-Agent/main/install.sh | sh -s -- --repo https://github.com/MatthewLopez1990/Aegis-Agent.git
```

Use `--archive` if the target machine does not have `git`.

## Custom Location

```bash
./install.sh --install-dir "$HOME/Applications/aegis-agent" --bin-dir "$HOME/bin"
```

## Verify

```bash
aegis --help
aegis dashboard
aegis tui
aegis serve --host 127.0.0.1 --port 8765
```

No `sudo`, npm, pnpm, yarn, or system package install is required by the current runtime. If Python virtual environments are unavailable, the installer automatically falls back to a source-copy launcher because Aegis currently has no third-party runtime dependencies.
