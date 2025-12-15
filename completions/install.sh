#!/bin/bash
# Install shell completions for ghost

set -e

GHOST_BIN="${GHOST_BIN:-ghost}"

# Check if ghost is available
if ! command -v "$GHOST_BIN" &> /dev/null; then
    echo "ghost not found in PATH. Set GHOST_BIN to the path of the ghost binary."
    exit 1
fi

install_bash() {
    local dest
    if [[ "$OSTYPE" == "darwin"* ]] && command -v brew &> /dev/null; then
        dest="$(brew --prefix)/etc/bash_completion.d/ghost"
    elif [[ -d /etc/bash_completion.d ]]; then
        dest="/etc/bash_completion.d/ghost"
    else
        dest="$HOME/.local/share/bash-completion/completions/ghost"
        mkdir -p "$(dirname "$dest")"
    fi
    
    "$GHOST_BIN" completions bash > "$dest"
    echo "Bash completions installed to $dest"
}

install_zsh() {
    local dest
    if [[ -d "$HOME/.oh-my-zsh/completions" ]]; then
        dest="$HOME/.oh-my-zsh/completions/_ghost"
    elif [[ -d "$HOME/.zfunc" ]]; then
        dest="$HOME/.zfunc/_ghost"
    else
        dest="$HOME/.zfunc/_ghost"
        mkdir -p "$HOME/.zfunc"
        echo "Add 'fpath+=~/.zfunc' to your ~/.zshrc if not already present"
    fi
    
    "$GHOST_BIN" completions zsh > "$dest"
    echo "Zsh completions installed to $dest"
}

install_fish() {
    local dest="$HOME/.config/fish/completions/ghost.fish"
    mkdir -p "$(dirname "$dest")"
    "$GHOST_BIN" completions fish > "$dest"
    echo "Fish completions installed to $dest"
}

# Detect current shell
detect_shell() {
    local shell_name
    shell_name=$(basename "$SHELL")
    echo "$shell_name"
}

main() {
    local target_shell="${1:-$(detect_shell)}"
    
    case "$target_shell" in
        bash)
            install_bash
            ;;
        zsh)
            install_zsh
            ;;
        fish)
            install_fish
            ;;
        *)
            echo "Unsupported shell: $target_shell"
            echo "Supported: bash, zsh, fish"
            exit 1
            ;;
    esac
    
    echo ""
    echo "Restart your shell or run 'source ~/.${target_shell}rc' to enable completions"
}

main "$@"
