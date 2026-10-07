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

DRED='\033[38;5;9m'
DGREEN='\033[38;5;46m'
DYELLOW='\033[38;5;226m'
NC='\033[0m'

banner()  { echo -e "${DRED}[*] $1${NC}"; }
section() { echo -e "\n${DGREEN}[+] $1${NC}"; }
warn()    { echo -e "${DYELLOW}[!] $1${NC}"; }

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
    3. bloodyAD             (get bloodhound --transitive)
    4. bloodhound-python    (-c All --zip)
    5. rusthound            (--zip)

    All loot is collected into a timestamped output directory (chmod 700).

SECURITY NOTE:
    The collector tools take the password as a command-line argument, so
    it is briefly visible in 'ps' output. On a shared or multi-user box,
    run this script on a dedicated host you control.

EOF
}

 
FQDN="${BH_FQDN:-}"
DOMAIN="${BH_DOMAIN:-}"
IP="${BH_IP:-}"
# Distinct local names: assigning to plain USER/PASS clobbers the
# environment variables every child process inherits.
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
            FQDN="$2"; shift 2 ;;
        -d|--domain)
            DOMAIN="$2"; shift 2 ;;
        -i|--ip)
            IP="$2"; shift 2 ;;
        -u|--user)
            BH_USERNAME="$2"; shift 2 ;;
        -p|--pass)
            BHPASS="$2"; shift 2 ;;
        *)
            warn "Unknown argument: $1 (use -h for help)"
            shift
            ;;
    esac
done

 
[[ -z "$FQDN"   ]] && read -rp   "Enter Domain FQDN (dc.example.local):- " FQDN
[[ -z "$DOMAIN" ]] && read -rp   "Enter Domain Name (example.local):- " DOMAIN
[[ -z "$IP"     ]] && read -rp   "Enter Domain IP Address:- " IP
[[ -z "$BH_USERNAME" ]] && read -rp   "Put Valid Username :- " BH_USERNAME
[[ -z "$BHPASS"      ]] && read -rsp  "Put valid Password for above user:- " BHPASS && echo

 
check_tool() {
    if ! command -v "$1" &>/dev/null; then
        warn "'$1' not found in PATH - skipping steps that need it."
        return 1
    fi
    return 0
}

HAVE_NET=1;        check_tool net        || HAVE_NET=0
HAVE_BLOODYAD=1;   check_tool bloodyAD   || HAVE_BLOODYAD=0
HAVE_BHPY=1;       check_tool bloodhound-python || HAVE_BHPY=0
HAVE_RUSTHOUND=1;  check_tool rusthound  || HAVE_RUSTHOUND=0

 
OUTDIR="bh_loot_${DOMAIN}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"
chmod 700 "$OUTDIR"

banner "BloodHound Enumeration script.."
banner "Domain: $DOMAIN  FQDN: $FQDN  DC IP: $IP  User: $BH_USERNAME"
banner "Loot directory: $OUTDIR"

section "Checking FQDN resolution ($FQDN)"
resolve_fqdn() {
    # getent is glibc-only; fall back to dig/host elsewhere.
    if command -v getent &>/dev/null; then getent hosts "$1" &>/dev/null
    elif command -v dig &>/dev/null; then dig +short "$1" | grep -q .
    elif command -v host &>/dev/null; then host "$1" &>/dev/null
    else return 1
    fi
}
if ! resolve_fqdn "$FQDN"; then
    warn "'$FQDN' does not resolve. Kerberos auth (used by bloodhound-python/rusthound)"
    warn "needs this to resolve, or it silently falls back to weaker NTLM auth."

    # Build hosts line in the format: IP  FQDN  SHORTNAME  DOMAIN  (all uppercase)
    FQDN_UPPER=$(echo "$FQDN" | tr '[:lower:]' '[:upper:]')
    SHORT_NAME=$(echo "$FQDN" | cut -d'.' -f1 | tr '[:lower:]' '[:upper:]')
    DOMAIN_UPPER=$(echo "$DOMAIN" | tr '[:lower:]' '[:upper:]')
    HOSTS_LINE="$IP    $FQDN_UPPER $SHORT_NAME $DOMAIN_UPPER"

    read -rp "Add '$HOSTS_LINE' to /etc/hosts now? [y/N] " ADD_HOSTS
    if [[ "$ADD_HOSTS" =~ ^[Yy]$ ]]; then
        if echo "$HOSTS_LINE" | sudo tee -a /etc/hosts &>/dev/null; then
            echo "Added: $HOSTS_LINE -> /etc/hosts"
        else
            warn "Failed to write /etc/hosts (need sudo?). Continuing without it."
        fi
    else
        warn "Skipping. Collectors may fall back to NTLM instead of Kerberos."
    fi
else
    echo "'$FQDN' resolves fine."
fi

 
section "Checking clock skew against DC ($IP)"
warn "Kerberos typically fails (KRB_AP_ERR_SKEW) if your clock differs from the DC by more than 5 minutes."
read -rp "Sync system clock to the DC's time now via ntpdate? [y/N] " SYNC_TIME
if [[ "$SYNC_TIME" =~ ^[Yy]$ ]]; then
    if command -v ntpdate &>/dev/null; then
        sudo ntpdate -u "$IP" && echo "Clock synced to $IP." || warn "ntpdate failed - sync manually if Kerberos errors persist."
    elif command -v rdate &>/dev/null; then
        sudo rdate -n "$IP" && echo "Clock synced to $IP." || warn "rdate failed - sync manually if Kerberos errors persist."
    else
        warn "Neither ntpdate nor rdate found. Install one (apt install ntpdate) or sync manually."
    fi
else
    warn "Skipping. If bloodhound-python/rusthound report clock skew, re-run with sync enabled."
fi

# ---- 1. Domain Users via net rpc ----
if [[ "$HAVE_NET" -eq 1 ]]; then
    section "AD Users Enumeration (saved ${OUTDIR}/users.txt)"
    net rpc group members 'Domain Users' -W "$DOMAIN" -S "$IP" -U "${BH_USERNAME}%${BHPASS}" \
        | cut -d '\' -f2 | tee "$OUTDIR/users.txt"
    sleep 1
fi

# ---- 2. Domain Computers via bloodyAD ----
if [[ "$HAVE_BLOODYAD" -eq 1 ]]; then
    section "AD Computers Enumeration (saved ${OUTDIR}/computers.txt)"
    bloodyAD --host "$IP" -d "$DOMAIN" -u "$BH_USERNAME" -p "$BHPASS" get search --filter "(objectClass=computer)" --attr sAMAccountName,dNSHostName,operatingSystem \
        | tee "$OUTDIR/computers.txt"
    sleep 1
fi

# ---- 3. bloodyAD ----
if [[ "$HAVE_BLOODYAD" -eq 1 ]]; then
    section "BloodyAD Collection (transitive)"
    ( cd "$OUTDIR" && bloodyAD --host "$IP" -d "$DOMAIN" -u "$BH_USERNAME" -p "$BHPASS" get bloodhound --transitive --path . )
    sleep 1
fi

# ---- 4. bloodhound-python ----
if [[ "$HAVE_BHPY" -eq 1 ]]; then
    section "BloodHound.py Collection (Legacy collector, -c All --zip)"
    ( cd "$OUTDIR" && bloodhound-python -d "$DOMAIN" -u "$BH_USERNAME" -p "$BHPASS" -ns "$IP" -dc "$FQDN" -c All --zip )
    sleep 1
fi

# ---- 5. rusthound (BloodHound CE) ----
if [[ "$HAVE_RUSTHOUND" -eq 1 ]]; then
    section "RustHound-CE Collection (--zip)"
    ( cd "$OUTDIR" && rusthound --domain "$DOMAIN" -f "$FQDN" -i "$IP" -u "$BH_USERNAME" -p "$BHPASS" --zip )
    sleep 1
fi

section "Done"
echo "All loot saved under: $OUTDIR"
echo "Next steps:"
echo "  - Import the .zip file(s) into BloodHound / BloodHound CE"
echo "  - Review ${OUTDIR}/users.txt for account names to spray or cross-check"
echo "  - Review ${OUTDIR}/computers.txt for hostnames/OS versions to target"
