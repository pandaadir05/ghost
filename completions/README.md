# Shell Completions

Ghost supports tab completion for Bash, Zsh, Fish, PowerShell, and Elvish.

## Generate Completions

```bash
# Bash
ghost completions bash > ghost.bash

# Zsh
ghost completions zsh > _ghost

# Fish
ghost completions fish > ghost.fish

# PowerShell
ghost completions powershell > _ghost.ps1

# Elvish
ghost completions elvish > ghost.elv
```

## Installation

### Bash

```bash
# Linux
ghost completions bash > /etc/bash_completion.d/ghost

# macOS (with Homebrew)
ghost completions bash > $(brew --prefix)/etc/bash_completion.d/ghost
```

### Zsh

```bash
# Using Oh My Zsh
ghost completions zsh > ~/.oh-my-zsh/completions/_ghost

# Or add to fpath
ghost completions zsh > ~/.zfunc/_ghost
# Then add to ~/.zshrc: fpath+=~/.zfunc
```

### Fish

```bash
ghost completions fish > ~/.config/fish/completions/ghost.fish
```

### PowerShell

Add to your PowerShell profile (`$PROFILE`):

```powershell
ghost completions powershell | Out-String | Invoke-Expression
```

## Quick Install (Unix)

```bash
# Detect shell and install
./completions/install.sh
```
