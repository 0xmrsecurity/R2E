#!/bin/bash
# gitcheck2enum.sh
#
# Usage:-
# ./gitcheck2enum.sh
# ./gitcheck2enum.sh -h  |  --help
# ./gitcheck2enum.sh -u https://git.example.com/app.git
# ./gitcheck2enum.sh -p ./Already-cloned-Repo
set -u
set -o pipefail

export GIT_PAGER=cat
export PAGER=cat

# ---- Colors ----
DRED='\033[38;5;9m'
DGREEN='\033[38;5;46m'
DYELLOW='\033[38;5;226m'
DBLUE='\033[38;5;39m'
NC='\033[0m'

export GREP_COLORS='mt=01;38;5;196'

banner()  { printf '%b\n' "${DRED}[*] $1${NC}"; }
section() { printf '\n%b\n' "${DGREEN}[+] $1${NC}"; }
info()    { printf '%b\n' "${DBLUE}[i] $1${NC}"; }
warn()    { printf '%b\n' "${DYELLOW}[!] $1${NC}"; }

show_help() {
    cat << EOF
gitcheck2enum.sh - Clone + Enumerate a Git repository.

USAGE:
    ./gitcheck2enum.sh [-u URL | -p PATH] [-h|--help]

OPTIONS:
    -u, --url <URL>     Git remote URL to clone (https/ssh/git)
    -p, --path <PATH>   Path to an already-cloned local repo (skips cloning)
    -h, --help          Show this help message and exit

    If neither is supplied you'll be prompted interactively.

EXAMPLES:
    ./gitcheck2enum.sh -u https://10.129.60.23/app.git
    ./gitcheck2enum.sh -p ./Already-cloned-Repo

REQUIRED TOOLS:
    git
    curl
    git-dumper
    trufflehog, gitleaks
EOF
}

URL=""
LOCAL_PATH=""

# ---- Argument parsing ----
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -u|--url)
            [[ -n "${2:-}" ]] || { warn "-u/--url requires a value. Use -h for help."; exit 1; }
            URL="$2"
            shift 2
            ;;
        -p|--path)
            [[ -n "${2:-}" ]] || { warn "-p/--path requires a value. Use -h for help."; exit 1; }
            LOCAL_PATH="$2"
            shift 2
            ;;
        *)
            warn "Unknown argument: $1 (use -h for help)"
            shift
            ;;
    esac
done

if [[ -z "$URL" && -z "$LOCAL_PATH" ]]; then
    read -rp "Enter Target URL (or press Enter to give a local path instead):- " URL
    if [[ -z "$URL" ]]; then
        read -rp "Enter path to local repo:- " LOCAL_PATH
    fi
fi

command -v git &>/dev/null || { warn "git is required. Install it and re-run. Exiting."; exit 1; }

if [[ -n "$URL" ]]; then
    SAFE_NAME=$(basename "$URL" .git | tr -c '[:alnum:]_-' '_')
else
    SAFE_NAME=$(basename "$(realpath "$LOCAL_PATH")" | tr -c '[:alnum:]_-' '_')
fi

banner "GitCheck2Enum - Git Recon Pipeline"
banner "Target: ${URL:-$LOCAL_PATH}"

if [[ -n "$URL" && "$URL" =~ ^https?:// ]] && command -v curl &>/dev/null; then
    section "Web Exposure Check"
    PROBE_URL="${URL%/}"
    [[ "$PROBE_URL" != *".git"* ]] && PROBE_URL="${PROBE_URL}/.git"
    HEAD_CONTENT=$(curl -sk --max-time 8 "${PROBE_URL}/HEAD" 2>/dev/null)
    if [[ "$HEAD_CONTENT" == ref:* ]]; then
        warn "Exposed .git/HEAD found at ${PROBE_URL}/HEAD -> $HEAD_CONTENT"
        warn "Misconfigured web root exposing raw git internals - reconstructing"
        warn "it needs a dumper tool."
        if command -v git-dumper &>/dev/null; then
            read -rp "git-dumper is installed - run it against ${PROBE_URL}/ now? [y/N] " DODUMP
            if [[ "$DODUMP" =~ ^[Yy]$ ]]; then
                DUMPDIR="${SAFE_NAME}-git-dump"
                git-dumper "${PROBE_URL}/" "$DUMPDIR"
                info "Loot (if any) saved to: $DUMPDIR"
            fi
        else
            warn "git-dumper not found. Install it (pip install git-dumper) or use GitTools' gitdumper.sh, then point -p at the reconstructed repo."
        fi
    else
        info "No exposed .git/HEAD detected. Continuing with standard clone flow."
    fi
fi

REPO_DIR="$SAFE_NAME"

if [[ -n "$LOCAL_PATH" ]]; then
    section "Local Repository Access"
    info "Using existing local repo: $LOCAL_PATH"
    if [[ ! -d "$LOCAL_PATH/.git" ]]; then
        warn "'$LOCAL_PATH' does not look like a git repo (.git missing). Exiting."
        exit 1
    fi
    REPO_DIR="$LOCAL_PATH"
else
    section "Repository Clone"
    info "Cloning: $URL"
    git clone "$URL" "$REPO_DIR"

    if [[ ! -d "$REPO_DIR/.git" ]]; then
        warn "SSL clone failed or produced no repo."
        read -rp "Retry with SSL verification DISABLED (-c http.sslVerify=false)? [y/N] " NOSSL
        if [[ "$NOSSL" =~ ^[Yy]$ ]]; then
            warn "Disabling SSL verification skips certificate validation - only do this against targets you trust."
            section "Clone with SSL verification OFF"
            if [[ -n "$REPO_DIR" && "$REPO_DIR" != "/" && "$REPO_DIR" != "." && -d "$REPO_DIR" ]]; then
                rm -rf -- "$REPO_DIR"
            fi
            GIT_SSL_NO_VERIFY=true git -c http.sslVerify=false clone "$URL" "$REPO_DIR"
        fi
    fi
fi

if [[ ! -d "$REPO_DIR/.git" ]]; then
    warn "Could not obtain a valid git repo. Exiting."
    exit 1
fi

cd "$REPO_DIR" || { warn "Failed to cd into $REPO_DIR. Exiting."; exit 1; }
section "Repository Context"
info "Working inside: $(pwd)"

# ---- Loot directory ----
OUTDIR="git_loot_${SAFE_NAME}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"
chmod 700 "$OUTDIR"

section "Repository Overview"
info "Loot directory: $OUTDIR"

echo "--- Authors ---"
git log --all | grep -i 'author'
info "Unique authors (name <email>)"
git log --all --format='%aN <%aE>' | sort -u

echo "--- Deleted files ---"
git log --all --diff-filter=D --summary | grep delete || echo "No deleted files found."

echo "--- git status ---"
git status

echo "--- Branches (local + remote) ---"
git branch -a

echo "--- Tags ---"
git tag

section "Commit History"
mapfile -t COMMITS < <(git log --oneline --all | cut -d ' ' -f1)
info "Found ${#COMMITS[@]} commits. Full per-commit diff saved to: $OUTDIR/full-history.diff"
: > "$OUTDIR/full-history.diff"
for c in "${COMMITS[@]}"; do
    {
        echo "===== commit $c ====="
        git show "$c"
    } >> "$OUTDIR/full-history.diff" 2>&1
done

echo "--- Commit graph (all branches) ---"
git log --oneline --graph --all

section "Dangling / Unreachable Objects"
mapfile -t DANGLING < <(git fsck --no-reflog 2>/dev/null | awk '/dangling commit/ {print $3}')
if [[ ${#DANGLING[@]} -gt 0 ]]; then
    warn "${#DANGLING[@]} dangling commit(s) found - not reachable from any branch/tag."
    warn "Diffs saved to: $OUTDIR/dangling.diff"
    : > "$OUTDIR/dangling.diff"
    for dc in "${DANGLING[@]}"; do
        {
            echo "===== dangling commit $dc ====="
            git show -s --format="%H %ai %s" "$dc"
            git show "$dc"
        } >> "$OUTDIR/dangling.diff" 2>&1
    done
else
    info "No dangling commits found."
fi

section "Reflog and Local Recovery Data"
REFLOG_OUT=$(git reflog show --all 2>/dev/null)
if [[ -n "$REFLOG_OUT" ]]; then
    echo "$REFLOG_OUT"
else
    warn "No reflog entries present. This is expected for a fresh clone; reflog is local-only and is not transferred by git clone."
fi

echo "--- Stash list ---"
git stash list

echo "--- Dropped stashes (recovered via fsck) ---"
git fsck --no-reflog 2>/dev/null | awk '/dangling commit/ {print $3}' \
    | xargs -r -I{} git show -s --format="%H %ai %s" {} 2>/dev/null \
    | grep -i "^.* WIP on \|^.* On " || echo "None found."

section "Repository Metadata"
info "Remotes"
git remote -v
info "Submodules (.gitmodules)"
if [[ -f ".gitmodules" ]]; then
    cat ".gitmodules"
else
    echo "No .gitmodules file present."
fi

echo "--- git config (local) ---"
git config -l

echo "--- .git/hooks ---"
ls -la .git/hooks/ 2>/dev/null

section "CI/CD Files"
CI_FILES=$(find . -path ./.git -prune -o \( -path '*/.github/workflows/*.yml' -o -path '*/.github/workflows/*.yaml' -o -name '.gitlab-ci.yml' -o -name 'Jenkinsfile' \) -print 2>/dev/null)
if [[ -n "$CI_FILES" ]]; then
    echo "$CI_FILES"
    echo "--- content ---"
    while IFS= read -r f; do
        echo "===== $f ====="
        cat "$f" 2>/dev/null
    done <<< "$CI_FILES"
else
    info "No CI/CD workflow files found."
fi

section "Large Objects"
info "Largest objects in git history (top 15)"
git rev-list --objects --all 2>/dev/null \
    | git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' 2>/dev/null \
    | awk '/^blob/ {print $3, $4}' | sort -rn | head -15

section "Secret / Sensitive Pattern Scan"
SECRETS_RE="(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{16,}|pk_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}|-----BEGIN [A-Z ]*PRIVATE KEY-----|https?://[^[:space:]]+:[^[:space:]]+@|[A-Za-z0-9_]+=+[A-Za-z0-9_]{20,})"
git log -p --all --full-history 2>/dev/null | grep -inE "$SECRETS_RE" > "$OUTDIR/secrets-grep.txt" || true
if [[ -s "$OUTDIR/secrets-grep.txt" ]]; then
    info "Matches saved to: $OUTDIR/secrets-grep.txt"
    head -50 "$OUTDIR/secrets-grep.txt"
else
    info "No high-signal secret patterns matched."
fi

section "Scanner Results"
if command -v trufflehog &>/dev/null; then
    info "Running TruffleHog"
    if trufflehog --help 2>&1 | grep -q "git_url"; then
        warn "Detected TruffleHog v2 (legacy Python). This mode is regex/entropy based rather than a strict verified-secret scan."
        trufflehog --regex --entropy=True "file://$(pwd)" 2>&1 | tee "$OUTDIR/trufflehog.txt"
    else
        trufflehog git "file://$(pwd)" --only-verified 2>&1 | tee "$OUTDIR/trufflehog.txt"
    fi
else
    warn "trufflehog not installed - skipping. (pipx install trufflehog for verified-secret detection)"
fi

if command -v gitleaks &>/dev/null; then
    info "Running Gitleaks"
    gitleaks detect -v --source . 2>&1 | tee "$OUTDIR/gitleaks.txt"
else
    warn "gitleaks not installed - skipping. (apt install gitleaks for a second-opinion secrets scan)"
fi

cd - > /dev/null

section "Final Summary"
info "Repository left on disk at: $REPO_DIR"
info "Bulk dump directory: $OUTDIR"
info "Artifacts include: full-history.diff, dangling.diff, secrets-grep.txt, trufflehog.txt, gitleaks.txt"

echo "Done."
exit 0
