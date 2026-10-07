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
NC='\033[0m'
 
export GREP_COLORS='mt=01;38;5;196'

banner()  { echo -e "${DRED}[*] $1${NC}"; }
section() { echo -e "\n${DGREEN}[+] $1${NC}"; }
warn()    { echo -e "${DYELLOW}[!] $1${NC}"; }

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
            URL="$2"; shift 2 ;;
        -p|--path)
            [[ -n "${2:-}" ]] || { warn "-p/--path requires a value. Use -h for help."; exit 1; }
            LOCAL_PATH="$2"; shift 2 ;;
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
    section "Checking for an exposed .git/ directory on the web server"
    PROBE_URL="${URL%/}"
    [[ "$PROBE_URL" != *".git"* ]] && PROBE_URL="${PROBE_URL}/.git"
    HEAD_CONTENT=$(curl -sk --max-time 8 "${PROBE_URL}/HEAD" 2>/dev/null)
    if [[ "$HEAD_CONTENT" == ref:* ]]; then
        warn "Exposed .git/HEAD found at ${PROBE_URL}/HEAD -> $HEAD_CONTENT"
        warn "Misconfigured web root exposing raw git internals - reconstructing"
        warn "it needs a dumper tool:"
        if command -v git-dumper &>/dev/null; then
            read -rp "git-dumper is installed - run it against ${PROBE_URL}/ now? [y/N] " DODUMP
            if [[ "$DODUMP" =~ ^[Yy]$ ]]; then
                DUMPDIR="${SAFE_NAME}-git-dump"
                git-dumper "${PROBE_URL}/" "$DUMPDIR"
                echo "Loot (if any) saved to: $DUMPDIR"
            fi
        else
            warn "git-dumper not found. Install it (pip install git-dumper) or use"
            warn "GitTools' gitdumper.sh, then point -p at the reconstructed repo."
        fi
    else
        echo "No exposed .git/HEAD detected (normal clone path continues below)."
    fi
fi

 
REPO_DIR="$SAFE_NAME"

if [[ -n "$LOCAL_PATH" ]]; then
    section "Using existing local repo: $LOCAL_PATH"
    if [[ ! -d "$LOCAL_PATH/.git" ]]; then
        warn "'$LOCAL_PATH' does not look like a git repo (.git missing). Exiting."
        exit 1
    fi
    REPO_DIR="$LOCAL_PATH"
else
    section "Cloning (SSL verification ON): $URL"
    git clone "$URL" "$REPO_DIR"

    if [[ ! -d "$REPO_DIR/.git" ]]; then
        warn "SSL clone failed or produced no repo."
        read -rp "Retry with SSL verification DISABLED (-c http.sslVerify=false)? [y/N] " NOSSL
        if [[ "$NOSSL" =~ ^[Yy]$ ]]; then
            warn "Disabling SSL verification skips certificate validation - only do this"
            warn "against targets you trust (e.g. lab/internal environments)."
            section "Cloning (SSL verification OFF): $URL"
            # Guard before recursive delete: never rm -rf an empty, dot,
            # or root path in case SAFE_NAME ever came out odd.
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
section "Working inside: $(pwd)"

# ---- Loot directory: bulk dumps go to files, console stays readable ----
OUTDIR="git_loot_${SAFE_NAME}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"
chmod 700 "$OUTDIR"

# ---- Authors ----
section "Authors"
git log --all | grep -i 'author'
echo "--- Unique authors (name <email>) ---"
git log --all --format='%aN <%aE>' | sort -u

# ---- Deleted files ----
section "Deleted files"
git log --all --diff-filter=D --summary | grep delete

# ---- git status ----
section "git status"
git status

# ---- Branches and tags ----
section "Branches (local + remote)"
git branch -a
section "Tags"
git tag

# ---- Commit list + full per-commit diff dump ----
section "Commit list"
mapfile -t COMMITS < <(git log --oneline --all | cut -d ' ' -f1)
echo "Found ${#COMMITS[@]} commits. Full per-commit diff saved to: $OUTDIR/full-history.diff"
: > "$OUTDIR/full-history.diff"
for c in "${COMMITS[@]}"; do
    {
        echo "===== commit $c ====="
        git show "$c"
    } >> "$OUTDIR/full-history.diff" 2>&1
done

# ---- Commit graph across all branches ----
section "Commit graph (all branches)"
git log --oneline --graph --all

# ---- Dangling commits / unreachable objects ----
section "Dangling commits / unreachable objects (git fsck)"
mapfile -t DANGLING < <(git fsck --no-reflog 2>/dev/null | awk '/dangling commit/ {print $3}')
if [[ ${#DANGLING[@]} -gt 0 ]]; then
    warn "${#DANGLING[@]} dangling commit(s) found - not reachable from any"
    warn "branch/tag but not yet garbage-collected. Diffs saved to: $OUTDIR/dangling.diff"
    : > "$OUTDIR/dangling.diff"
    for dc in "${DANGLING[@]}"; do
        {
            echo "===== dangling commit $dc ====="
            git show -s --format="%H %ai %s" "$dc"
            git show "$dc"
        } >> "$OUTDIR/dangling.diff" 2>&1
    done
else
    echo "No dangling commits found."
fi

# ---- Reflog across all refs ----
section "Reflog - all refs (recovers force-pushed/reset-away history)"
REFLOG_OUT=$(git reflog show --all 2>/dev/null)
if [[ -n "$REFLOG_OUT" ]]; then
    echo "$REFLOG_OUT"
else
    echo "No reflog entries (expected for a fresh clone - reflog is local-only and"
    echo "isn't transferred by 'git clone'; only relevant with the dev's actual"
    echo "working copy, e.g. from an exposed .git/ or a backup)."
fi

# ---- Stash list + dropped-stash recovery ----
section "Stash list"
git stash list
section "Dropped stashes (recovered via fsck, not in normal reflog)"
git fsck --no-reflog 2>/dev/null | awk '/dangling commit/ {print $3}' \
    | xargs -r -I{} git show -s --format="%H %ai %s" {} 2>/dev/null \
    | grep -i "^.* WIP on \|^.* On " || echo "None found."

# ---- Remotes, submodules, config, hooks ----
section "Remotes"
git remote -v

section "Submodules (.gitmodules) - often reveal internal/private repo URLs"
if [[ -f ".gitmodules" ]]; then
    cat ".gitmodules"
else
    echo "No .gitmodules file present."
fi

section "git config (local)"
git config -l

section "Hooks present in .git/hooks (check for anything non-default/suspicious)"
ls -la .git/hooks/ 2>/dev/null

# ---- CI/CD workflow files ----
section "CI/CD workflow files (.github/workflows, .gitlab-ci.yml, Jenkinsfile)"
CI_FILES=$(find . -path ./.git -prune -o \( -path '*/.github/workflows/*.yml' -o -path '*/.github/workflows/*.yaml' -o -name '.gitlab-ci.yml' -o -name 'Jenkinsfile' \) -print 2>/dev/null)
if [[ -n "$CI_FILES" ]]; then
    echo "$CI_FILES"
    echo "--- content ---"
    # while-read, not xargs: filenames containing whitespace break 'xargs cat'.
    while IFS= read -r f; do
        echo "===== $f ====="
        cat "$f" 2>/dev/null
    done <<< "$CI_FILES"
else
    echo "No CI/CD workflow files found in the working tree."
fi

# ---- Largest objects in history ----
section "Largest objects in git history (top 15 - check for leaked dumps/binaries)"
git rev-list --objects --all 2>/dev/null \
    | git cat-file --batch-check='%(objecttype) %(objectname) %(objectsize) %(rest)' 2>/dev/null \
    | awk '/^blob/ {print $3, $4}' | sort -rn | head -15

# ---- Secrets / automation check (with matched keywords highlighted inline) ----
section "Secrets / automation check (matches highlighted)"
# High-signal only. The old pattern listed bare words (http|host|port|user|
# db|secret|token|...) which matched almost EVERY diff line - zero triage
# value at volume. This version matches concrete credential shapes instead:
# known token/key prefixes, URIs with embedded user:pass, PEM blocks, and
# key=value assignment forms with a minimum secret length.
SECRETS_RE="(AKIA[0-9A-Z]{16}|ASIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|sk_live_[A-Za-z0-9]{16,}|pk_live_[A-Za-z0-9]{16,}|AIza[0-9A-Za-z_-]{35}|-----BEGIN [A-Z ]*PRIVATE KEY-----|(postgres(ql)?|mysql|mongodb(\+srv)?|redis|amqp)://[^ :/]+:[^@]+@|jdbc:[a-zA-Z]+://[^ ]*:[^ ]*@|(password|passwd|pwd|secret|api[_-]?key|apikey|access[_-]?token|refresh[_-]?token|client[_-]?secret|jwt[_-]?secret)[\"' ]*[:=][ \"']*[A-Za-z0-9/+_=.,:@-]{8,})"
git log -p --all --full-history 2>/dev/null | grep -inE "$SECRETS_RE" > "$OUTDIR/secrets-grep.txt" || true
if [[ -s "$OUTDIR/secrets-grep.txt" ]]; then
    echo "Matches saved to: $OUTDIR/secrets-grep.txt - first 50:"
    head -50 "$OUTDIR/secrets-grep.txt"
else
    echo "No high-signal secret patterns matched."
fi

# ---- TruffleHog (verified secrets, if installed) ----
section "TruffleHog scan (verified secrets, if installed)"
if command -v trufflehog &>/dev/null; then
    # v2 (Python, dxa4481/trufflesecurity legacy) uses a plain positional
    # git_url argument and has no --only-verified flag. v3 (Go rewrite) uses
    # subcommands (git/github/filesystem/...) and supports --only-verified.
    # Detect which one is installed from its own --help output and call it
    # with the matching syntax instead of assuming v3.
    if trufflehog --help 2>&1 | grep -q "git_url"; then
        warn "Detected TruffleHog v2 (legacy Python) - it has no verified-secret"
        warn "mode, so results here are regex+entropy based, same signal class"
        warn "as the grep check above, not a strictly higher-confidence pass."
        trufflehog --regex --entropy=True "file://$(pwd)" 2>&1 | tee "$OUTDIR/trufflehog.txt"
    else
        trufflehog git "file://$(pwd)" --only-verified 2>&1 | tee "$OUTDIR/trufflehog.txt"
    fi
else
    warn "trufflehog not installed - skipping. (pipx install trufflehog for verified-secret detection)"
fi

# ---- Gitleaks (if installed) ----
section "Gitleaks scan (if installed)"
if command -v gitleaks &>/dev/null; then
    gitleaks detect -v --source . 2>&1 | tee "$OUTDIR/gitleaks.txt"
else
    warn "gitleaks not installed - skipping. (apt install gitleaks for a second-opinion secrets scan)"
fi

cd - > /dev/null

section "Done"
echo "Repo left on disk at: $REPO_DIR"
echo "Bulk dumps (history, dangling, secrets, scanner logs) in: $OUTDIR"
exit 0
