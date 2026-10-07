#!/bin/bash
# crawlurl2enum.sh - Crawl (katana + gospider) and categorize discovered endpoints
#
# Usage:-
# ./crawlurl2enum.sh
# ./crawlurl2enum.sh -h | --help
# ./crawlurl2enum.sh -u https://target.com
# ./crawlurl2enum.sh -l urls.txt
set -u
set -o pipefail

# ---- Colors ----
DRED='\033[38;5;9m'
DGREEN='\033[38;5;46m'
DYELLOW='\033[38;5;226m'
DCYAN='\033[38;5;51m'
NC='\033[0m'

banner()  { echo -e "${DRED}[*] $1${NC}"; }
section() { echo -e "\n${DGREEN}[+] $1${NC}"; }
warn()    { echo -e "${DYELLOW}[!] $1${NC}"; }
cat_head(){ echo -e "${DCYAN}--- $1 ($2 unique) ---${NC}"; }


COMMON_PATHS=(
    "robots.txt" "sitemap.xml" "favicon.ico" "humans.txt"
    ".well-known/security.txt" "manifest.json" "site.webmanifest"
    "ads.txt" "app-ads.txt"
    ".git/" ".git/config" ".git/HEAD" ".svn/" ".hg/" ".bzr/"
    ".env" ".env.local" ".env.production" ".env.bak" ".env.old" ".env.save"
    "config.json" "config.php" "config.yml" "secrets.yml" "credentials.json"
    "wp-config.php" "settings.py" ".htpasswd" ".htaccess"
    "package.json" "package-lock.json" "composer.json" "composer.lock"
    "requirements.txt" "Gemfile" "Gemfile.lock" "yarn.lock"
    "backup.zip" "backup.sql" "site.tar.gz" "index.php.bak" "index.html~"
    "database.sql" "dump.sql"
    "wp-admin/" "wp-login.php" "administrator/" "user/login" "phpmyadmin/"
    "admin/" "manager/html" ".well-known/"
    "web.config" "server-status" "server-info"
    ".DS_Store" "Thumbs.db" "crossdomain.xml" "clientaccesspolicy.xml"
    "api/swagger.json" "api-docs" "graphql" "debug" "console" "actuator"
    ".well-known/openid-configuration"
    "Dockerfile" "docker-compose.yml" ".dockerenv"
    ".aws/credentials" "id_rsa" "id_rsa.pub"
)

show_help() {
    cat << EOF
crawlurl2enum.sh - Crawl a target (katana + gospider) and categorize endpoints

USAGE:
    ./crawlurl2enum.sh [-u URL | -l URLLIST] [OPTIONS]

OPTIONS:
    -u, --url <URL>         Single target URL to crawl
    -l, --list <FILE>       File containing one URL per line to crawl
    --keep-raw              Keep raw katana/gospider output (default: deleted
                             after categorization, only the summary is kept)
    --no-path-probe         Skip the common web-root path/file probe step
    --path-concurrency <N>  Parallel requests for the path probe (default: 15)
    --path-timeout <N>      Per-request timeout in seconds (default: 8)
    -h, --help               Show this help message and exit
 

EXAMPLES:
    ./crawlurl2enum.sh -u https://target.com
    ./crawlurl2enum.sh -l urls.txt
    ./crawlurl2enum.sh -u https://target.com --keep-raw

REQUIRED TOOLS:
    katana, gospider, curl
EOF
}

URL=""
URLLIST=""
KEEP_RAW=0
NO_PATH_PROBE=0
PATH_CONCURRENCY=15
PATH_TIMEOUT=8

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
        -l|--list)
            [[ -n "${2:-}" ]] || { warn "-l/--list requires a value. Use -h for help."; exit 1; }
            URLLIST="$2"; shift 2 ;;
        --keep-raw)
            KEEP_RAW=1; shift ;;
        --no-path-probe)
            NO_PATH_PROBE=1; shift ;;
        --path-concurrency)
            [[ -n "${2:-}" ]] || { warn "--path-concurrency requires a value."; exit 1; }
            PATH_CONCURRENCY="$2"; shift 2 ;;
        --path-timeout)
            [[ -n "${2:-}" ]] || { warn "--path-timeout requires a value."; exit 1; }
            PATH_TIMEOUT="$2"; shift 2 ;;
        *)
            warn "Unknown argument: $1 (use -h for help)"
            shift ;;
    esac
done

if [[ -z "$URL" && -z "$URLLIST" ]]; then
    read -rp "Enter target URL (or press Enter to give a list file instead):- " URL
    if [[ -z "$URL" ]]; then
        read -rp "Enter path to URL list file:- " URLLIST
    fi
fi

# ---- Build the list of targets to crawl ----
TARGETS=()
if [[ -n "$URLLIST" ]]; then
    [[ -f "$URLLIST" ]] || { warn "'$URLLIST' not found. Exiting."; exit 1; }
    mapfile -t TARGETS < <(grep -v '^\s*$' "$URLLIST")
else
    TARGETS=("$URL")
fi

if [[ ${#TARGETS[@]} -eq 0 ]]; then
    warn "No targets to crawl. Exiting."
    exit 1
fi

# ---- Tool availability ----
HAVE_KATANA=1;   command -v katana   &>/dev/null || { warn "'katana' not found - skipping katana crawl."; HAVE_KATANA=0; }
HAVE_GOSPIDER=1; command -v gospider &>/dev/null || { warn "'gospider' not found - skipping gospider crawl."; HAVE_GOSPIDER=0; }
HAVE_CURL=1;     command -v curl     &>/dev/null || { warn "'curl' not found - skipping common path probe."; HAVE_CURL=0; NO_PATH_PROBE=1; }

if [[ "$HAVE_KATANA" -eq 0 && "$HAVE_GOSPIDER" -eq 0 && "$NO_PATH_PROBE" -eq 1 ]]; then
    warn "Nothing available to run (no katana, gospider, or curl). Exiting."
    exit 1
fi

WORKDIR=$(mktemp -d /tmp/crawlurl2enum.XXXXXX)
REPORT="crawl_report_$(date +%Y%m%d_%H%M%S).txt"
exec > >(tee "$REPORT") 2>&1
cleanup() {
    if [[ "$KEEP_RAW" -eq 1 ]]; then
        echo "Raw crawl data kept at: $WORKDIR"
    else
        rm -rf "$WORKDIR"
    fi
    echo "Report saved to: $REPORT"
}
trap cleanup EXIT

banner "CrawlURL2Enum - Endpoint Discovery Pipeline"
banner "Targets: ${#TARGETS[@]}"

RAW_ALL="$WORKDIR/raw-all.txt"
> "$RAW_ALL"

probe_common_paths() {
    local base="${1%/}"
    local resultfile="$WORKDIR/pathprobe-results.txt"
    > "$resultfile"

    # Establish a baseline against a random path that should NOT exist, so we
    # can tell a genuine 200 apart from a soft-404 (SPA fallback / custom
    # catch-all page that returns 200 with identical content for everything).
    local randstr baseline base_code base_size
    randstr=$(od -An -N8 -tx1 /dev/urandom 2>/dev/null | tr -d ' \n' || echo "a1b2c3d4e5f6")
    baseline=$(curl -o /dev/null -s -w "%{http_code} %{size_download}" -m "$PATH_TIMEOUT" -k \
        -A "Mozilla/5.0" "${base}/nonexistent-${randstr}-check" 2>/dev/null)
    base_code="${baseline%% *}"
    base_size="${baseline##* }"
    echo "Baseline (random nonexistent path): status=$base_code size=${base_size}b"

    export PROBE_BASE="$base"
    export PROBE_TIMEOUT="$PATH_TIMEOUT"
    export PROBE_BASE_CODE="$base_code"
    export PROBE_BASE_SIZE="$base_size"

    printf '%s\n' "${COMMON_PATHS[@]}" | xargs -P "$PATH_CONCURRENCY" -I{} bash -c '
        url="${PROBE_BASE}/{}"
        read -r code size < <(curl -o /dev/null -s -w "%{http_code} %{size_download}" -m "$PROBE_TIMEOUT" -k -A "Mozilla/5.0" "$url" 2>/dev/null)
        case "$code" in
            2??)
                if [[ "$code" == "$PROBE_BASE_CODE" && "$size" == "$PROBE_BASE_SIZE" ]]; then
                    : # matches baseline signature - soft-404 / SPA fallback, not a real hit
                else
                    echo "FOUND      $code  $url  (${size}b)"
                fi
                ;;
            401|403) echo "RESTRICTED $code  $url  (${size}b)" ;;
            3??) echo "REDIRECT   $code  $url  (${size}b)" ;;
        esac
    ' >> "$resultfile"

    unset PROBE_BASE PROBE_TIMEOUT PROBE_BASE_CODE PROBE_BASE_SIZE

    local found restricted redirect
    found=$(grep '^FOUND' "$resultfile" | sort -u)
    restricted=$(grep '^RESTRICTED' "$resultfile" | sort -u)
    redirect=$(grep '^REDIRECT' "$resultfile" | sort -u)

    if [[ -n "$found" ]]; then
        echo -e "${DGREEN}Found (2xx, differs from baseline):${NC}"
        echo "$found" | awk '{printf "  [%s] %s %s\n", $2, $3, $4}'
    fi
    if [[ -n "$restricted" ]]; then
        echo -e "${DYELLOW}Exists but restricted (401/403):${NC}"
        echo "$restricted" | awk '{printf "  [%s] %s %s\n", $2, $3, $4}'
    fi
    if [[ -n "$redirect" ]]; then
        echo -e "${DCYAN}Redirect (3xx - path/directory likely exists):${NC}"
        echo "$redirect" | awk '{printf "  [%s] %s %s\n", $2, $3, $4}'
    fi
    if [[ -z "$found$restricted$redirect" ]]; then
        echo "None of the ${#COMMON_PATHS[@]} probed paths returned an interesting status."
    fi
}

for TARGET in "${TARGETS[@]}"; do
    section "Crawling: $TARGET"

    if [[ "$NO_PATH_PROBE" -eq 0 ]]; then
        echo "-> common path/file probe (${#COMMON_PATHS[@]} paths, concurrency $PATH_CONCURRENCY)"
        probe_common_paths "$TARGET"
    fi

    if [[ "$HAVE_KATANA" -eq 1 ]]; then
        echo "-> katana"
        katana -u "$TARGET" -js-crawl -known-files all -silent \
            -o "$WORKDIR/katana-$(echo "$TARGET" | tr -c '[:alnum:]' '_').txt" 2>&1 | tail -n +1
    fi

    if [[ "$HAVE_GOSPIDER" -eq 1 ]]; then
        echo "-> gospider"
        gospider -s "$TARGET" -u "Mozilla/5.0" -t 5 --sitemap -c 5 -d 3 \
            -o "$WORKDIR/gospider-$(echo "$TARGET" | tr -c '[:alnum:]' '_')" 2>&1 | tail -n +1
    fi
done

# ---- Normalize + merge all discovered URLs from both tools ----
section "Merging and deduplicating results"
grep -rohE 'https?://[^[:space:]"'"'"'<>]+' "$WORKDIR" 2>/dev/null | sort -u > "$RAW_ALL"
TOTAL=$(wc -l < "$RAW_ALL")
echo "Total unique URLs discovered: $TOTAL"

if [[ "$TOTAL" -eq 0 ]]; then
    warn "No URLs discovered. Nothing to categorize."
    exit 0
fi

# ---- Categorization (mutually exclusive buckets, matched in priority order) ----
IMG_REGEX='\.(png|jpe?g|gif|bmp|svg|ico|webp|tiff?)([?#]|$)'
JS_REGEX='\.js([?#]|$)'
EXT_REGEX='\.(xml|zip|json|config|env|bak|sql|tar|gz|7z|yml|yaml|log|pem|key|crt|conf|ini|old|swp)([?#]|$)|/\.git(/|$)|/\.env(/|$)'
API_REGEX='(/api(/|$|[?#])|/v[0-9]+(/|$|[?#]))'
PARAM_REGEX='\?[A-Za-z0-9_.%-]+='

REMAINING="$WORKDIR/remaining.txt"
cp "$RAW_ALL" "$REMAINING"

extract_category() {
    local label="$1" pattern="$2" outvar_count
    local matches
    matches=$(grep -iE "$pattern" "$REMAINING" | sort -u)
    outvar_count=$(echo -n "$matches" | grep -c . || true)
    section "$label"
    if [[ -n "$matches" ]]; then
        cat_head "$label" "$outvar_count"
        echo "$matches"
        # Remove matched lines so buckets stay exclusive. NB: the old
        # 'grep ... && mv' was a bug - when the pattern matched EVERY
        # remaining line, grep -iv exits 1 (no output), mv never ran, and
        # the stale pool was re-reported by every later bucket.
        grep -ivE "$pattern" "$REMAINING" > "$REMAINING.tmp" || true
        mv "$REMAINING.tmp" "$REMAINING"
    else
        echo "None found."
    fi
}

extract_category "Parameter Endpoints"          "$PARAM_REGEX"
extract_category "Image Endpoints"              "$IMG_REGEX"
extract_category "JavaScript Endpoints"         "$JS_REGEX"
extract_category "Interesting File Extensions"  "$EXT_REGEX"
extract_category "API Endpoints"                "$API_REGEX"

section "Other URL Endpoints"
REMAINING_COUNT=$(wc -l < "$REMAINING")
if [[ "$REMAINING_COUNT" -gt 0 ]]; then
    cat_head "Other URL Endpoints" "$REMAINING_COUNT"
    cat "$REMAINING"
else
    echo "None found."
fi

section "Done"
echo "Total unique endpoints processed: $TOTAL"
