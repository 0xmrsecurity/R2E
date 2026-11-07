#!/bin/bash
# bloodhound2enum.sh -> AD Enum + Multi-collector BloodHound loot script
#
# Usage:-
# ./bloodhound2enum.sh
# ./bloodhound2enum.sh -h | --help
# ./bloodhound2enum.sh -f FQDN -d DOMAIN -i IP -u USER -p PASS
#
# Env var overrides
#   BH_FQDN, BH_DOMAIN, BH_IP, BH_USER, BH_PASS
set -u
set -o pipefail

# Colors
DRED='\033[38;5;9m'
DGREEN='\033[38;5;46m'
DYELLOW='\033[38;5;226m'
DBLUE='\033[38;5;39m'
NC='\033[0m'

banner()  { printf '%b\n' "${DRED}[*] $1${NC}"; }
section() { printf '\n%b\n' "${DGREEN}[+] $1${NC}"; }
info()    { printf '%b\n' "${DBLUE}[i] $1${NC}"; }
warn()    { printf '%b\n' "${DYELLOW}[!] $1${NC}"; }

show_help() {
    cat << EOF
bloodhound2enum.sh - AD enumeration + BloodHound collection wrapper

USAGE:
    ./bloodhound2enum.sh [OPTIONS]

OPTIONS:
    -f, --fqdn <FQDN>       Domain FQDN of the DC (e.g. dc01.garfield.htb)
    -d, --domain <DOMAIN>   Domain name (e.g. garfield.htb)
    -i, --ip <IP>           Domain Controller IP address
    -u, --user <USER>       Valid domain username
    -p, --pass <PASS>       Password for the above user
    -h, --help              Show this help message and exit

    Any value not supplied via flag or env var will be prompted for interactively.

ENVIRONMENT VARIABLE OVERRIDES:
    BH_FQDN, BH_DOMAIN, BH_IP, BH_USER, BH_PASS

EXAMPLES:
    ./bloodhound2enum.sh
    ./bloodhound2enum.sh -f dc.example.htb -d example.htb -i IP -u user -p 'pass'
    BH_USER='user' BH_PASS='pass' ./bloodhound2enum.sh -f dc.example.htb -d example.htb -i IP

WHAT IT RUNS:
    1. net rpc group members 'Domain Users'  -> users.txt
    2. bloodyAD get search (computers)       -> computers.txt
    3. bloodyAD get bloodhound --transitive
    4. bloodhound-python -c All --zip
    5. rusthound --zip

    All loot is collected into a timestamped output directory (chmod 700).

SECURITY NOTE:
    The collector tools take the password as a command-line argument, so
    it is briefly visible in 'ps' output. On a shared or multi-user box,
    run this script on a dedicated host you control.
EOF
}

resolve_fqdn() {
    # getent is glibc-only; fall back to dig/host elsewhere.
    if command -v getent &>/dev/null; then
        getent hosts "$1" &>/dev/null
    elif command -v dig &>/dev/null; then
        dig +short "$1" | grep -q .
    elif command -v host &>/dev/null; then
        host "$1" &>/dev/null
    else
        return 1
    fi
}

check_tool() {
    if ! command -v "$1" &>/dev/null; then
        warn "'$1' not found in PATH - skipping steps that need it."
        return 1
    fi
    return 0
}

prompt_yes_no() {
    local prompt="$1"
    local response
    read -rp "$prompt [y/N] " response
    [[ "$response" =~ ^[Yy]$ ]]
}

run_capture() {
    local label="$1"
    local out_file="$2"
    shift 2

    section "$label"
    echo "Output file: $out_file"
    "$@" 2>&1 | tee "$out_file"
}

count_lines() {
    local file="$1"
    if [[ -f "$file" ]]; then
        wc -l < "$file" | tr -d ' '
    else
        echo "0"
    fi
}

# ---- User-supplied values ----
FQDN="${BH_FQDN:-}"
DOMAIN="${BH_DOMAIN:-}"
IP="${BH_IP:-}"
BH_USERNAME="${BH_USER:-}"
BHPASS="${BH_PASS:-}"

# ---- Argument parsing ----
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -f|--fqdn)
            FQDN="$2"
            shift 2
            ;;
        -d|--domain)
            DOMAIN="$2"
            shift 2
            ;;
        -i|--ip)
            IP="$2"
            shift 2
            ;;
        -u|--user)
            BH_USERNAME="$2"
            shift 2
            ;;
        -p|--pass)
            BHPASS="$2"
            shift 2
            ;;
        *)
            warn "Unknown argument: $1 (use -h for help)"
            shift
            ;;
    esac
done

[[ -z "$FQDN" ]] && read -rp "Enter Domain FQDN (dc.example.local):- " FQDN
[[ -z "$DOMAIN" ]] && read -rp "Enter Domain Name (example.local):- " DOMAIN
[[ -z "$IP" ]] && read -rp "Enter Domain IP Address:- " IP
[[ -z "$BH_USERNAME" ]] && read -rp "Enter valid username:- " BH_USERNAME
[[ -z "$BHPASS" ]] && read -rsp "Enter password for $BH_USERNAME:- " BHPASS && echo

check_tool net || HAVE_NET=0
check_tool bloodyAD || HAVE_BLOODYAD=0
check_tool bloodhound-python || HAVE_BHPY=0
check_tool rusthound || HAVE_RUSTHOUND=0

# Default behavior: treat all as available unless check_tool says otherwise
HAVE_NET=1
HAVE_BLOODYAD=1
HAVE_BHPY=1
HAVE_RUSTHOUND=1

check_tool net || HAVE_NET=0
check_tool bloodyAD || HAVE_BLOODYAD=0
check_tool bloodhound-python || HAVE_BHPY=0
check_tool rusthound || HAVE_RUSTHOUND=0

OUTDIR="bh_loot_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"
chmod 700 "$OUTDIR"

banner "BloodHound Enumeration"
banner "Target: $DOMAIN | FQDN: $FQDN | DC IP: $IP | User: $BH_USERNAME"
banner "Loot dir: $OUTDIR"

section "Target Validation"
info "Checking FQDN resolution for $FQDN"
if ! resolve_fqdn "$FQDN"; then
    warn "'$FQDN' does not resolve. Kerberos auth (used by bloodhound-python/rusthound)"
    warn "needs this to resolve, or it may silently fall back to weaker NTLM auth."

    FQDN_UPPER=$(echo "$FQDN" | tr '[:lower:]' '[:upper:]')
    SHORT_NAME=$(echo "$FQDN" | cut -d'.' -f1 | tr '[:lower:]' '[:upper:]')
    DOMAIN_UPPER=$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')
    HOSTS_LINE="$IP    $FQDN_UPPER $SHORT_NAME $DOMAIN_UPPER"

    if prompt_yes_no "Add '$HOSTS_LINE' to /etc/hosts now?"; then
        if echo "$HOSTS_LINE" | sudo tee -a /etc/hosts &>/dev/null; then
            info "Added: $HOSTS_LINE -> /etc/hosts"
        else
            warn "Failed to write /etc/hosts (need sudo?). Continuing without it."
        fi
    else
        warn "Skipping. Collectors may fall back to NTLM instead of Kerberos."
    fi
else
    info "'$FQDN' resolves successfully."
fi

section "Clock Skew Check"
warn "Kerberos usually fails (KRB_AP_ERR_SKEW) if your clock differs from the DC by more than 5 minutes."
if prompt_yes_no "Sync system clock to the DC's time now via ntpdate/rdate?"; then
    if command -v ntpdate &>/dev/null; then
        sudo ntpdate -u "$IP" && info "Clock synced to $IP." || warn "ntpdate failed - sync manually if Kerberos errors persist."
    elif command -v rdate &>/dev/null; then
        sudo rdate -n "$IP" && info "Clock synced to $IP." || warn "rdate failed - sync manually if Kerberos errors persist."
    else
        warn "Neither ntpdate nor rdate found. Install one or sync manually."
    fi
else
    warn "Skipping clock sync. If bloodhound-python/rusthound report skew, re-run with sync enabled."
fi

# ---- 1. Domain Users via net rpc ----
if [[ "$HAVE_NET" -eq 1 ]]; then
    USERS_FILE="$OUTDIR/users.txt"
    section "Domain User Enumeration"
    info "Command: net rpc group members 'Domain Users'"
    if net rpc group members 'Domain Users' -W "$DOMAIN" -S "$IP" -U "${BH_USERNAME}%${BHPASS}" 2>&1 | cut -d '\' -f2 | tee "$USERS_FILE"; then
        info "Saved to $USERS_FILE"
        info "Count: $(count_lines "$USERS_FILE") user(s)"
    else
        warn "Domain user enumeration failed or returned no data."
    fi
    sleep 1
fi

# ---- 2. Domain Computers via bloodyAD ----
if [[ "$HAVE_BLOODYAD" -eq 1 ]]; then
    COMPUTERS_FILE="$OUTDIR/computers.txt"
    section "Domain Computer Enumeration"
    info "Command: bloodyAD get search --filter '(objectClass=computer)'"
    if bloodyAD --host "$IP" -d "$DOMAIN" -u "$BH_USERNAME" -p "$BHPASS" get search --filter "(objectClass=computer)" --attr sAMAccountName,dNSHostName,operatingSystem 2>&1 | tee "$COMPUTERS_FILE"; then
        info "Saved to $COMPUTERS_FILE"
        info "Count: $(count_lines "$COMPUTERS_FILE") record(s)"
    else
        warn "Computer enumeration failed or returned no data."
    fi
    sleep 1
fi

# ---- 3. bloodyAD ----
if [[ "$HAVE_BLOODYAD" -eq 1 ]]; then
    section "BloodyAD Collection"
    info "Running: bloodyAD get bloodhound --transitive"
    (
        cd "$OUTDIR" && \
        bloodyAD --host "$IP" -d "$DOMAIN" -u "$BH_USERNAME" -p "$BHPASS" get bloodhound --transitive --path .
    )
    sleep 1
fi

# ---- 4. bloodhound-python ----
if [[ "$HAVE_BHPY" -eq 1 ]]; then
    section "BloodHound.py Collection"
    info "Running: bloodhound-python -c All --zip"
    (
        cd "$OUTDIR" && \
        bloodhound-python -d "$DOMAIN" -u "$BH_USERNAME" -p "$BHPASS" -ns "$IP" -dc "$FQDN" -c All --zip
    )
    sleep 1
fi

# ---- 5. rusthound (BloodHound CE) ----
if [[ "$HAVE_RUSTHOUND" -eq 1 ]]; then
    section "RustHound Collection"
    info "Running: rusthound --domain ... --zip"
    (
        cd "$OUTDIR" && \
        rusthound --domain "$DOMAIN" -f "$FQDN" -i "$IP" -u "$BH_USERNAME" -p "$BHPASS" --zip
    )
    sleep 1
fi

section "Loot Summary"
info "Output directory: $OUTDIR"
if [[ -f "$OUTDIR/users.txt" ]]; then
    info "Users file: $OUTDIR/users.txt ($(count_lines "$OUTDIR/users.txt") lines)"
fi
if [[ -f "$OUTDIR/computers.txt" ]]; then
    info "Computers file: $OUTDIR/computers.txt ($(count_lines "$OUTDIR/computers.txt") lines)"
fi

# Print available BloodHound output files if they exist
for artifact in "$OUTDIR"/*.zip "$OUTDIR"/*.json "$OUTDIR"/*.bson; do
    if [[ -e "$artifact" ]]; then
        info "Generated artifact: $artifact"
    fi
done

section "Done"
echo "All loot saved under: $OUTDIR"
echo "Next steps:"
echo "  - Import the .zip file(s) into BloodHound / BloodHound CE"
echo "  - Review ${OUTDIR}/users.txt for account names to spray or cross-check"
echo "  - Review ${OUTDIR}/computers.txt for hostnames/OS versions to target"
