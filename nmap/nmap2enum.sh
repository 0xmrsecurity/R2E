#!/bin/bash
# nmap2enum.sh
#
# Usage:-
# ./nmap2enum.sh
# ./nmap2enum.sh -h | --help
# ./nmap2enum.sh -t 10.129.60.23
# ./nmap2enum.sh -t 10.129.60.0/24
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
nmap2enum.sh - Automated IP/range recon pipeline

USAGE:
    ./nmap2enum.sh [-t TARGET] [-h|--help]

OPTIONS:
    -t, --target <TARGET>    Any of fscan's native -h formats:
                                single IP:   10.129.60.23
                                dash-range:  10.129.60.1-255
                                comma-list:  10.129.60.1,10.129.60.2
                              Or a true CIDR range: 10.129.60.0/24
                              (CIDR is the only format that triggers the
                              fping live-host discovery step below - the
                              other three are passed straight to fscan -h)
    -r, --rate <N>           nmap --min-rate for the TCP/UDP deep-scan stages
                              (default: 1000; lower on VPN/HTB-style labs)
    -s, --scan <1-5>         Pick the deep scan without the interactive menu
                              (1=tcp 2=udp 3=both 4=poc-cve 5=everything)
                              Required for non-TTY use (piped/automation).
    -h, --help               Show this help message and exit

EXAMPLES:
    ./nmap2enum.sh -t 10.129.60.23
    ./nmap2enum.sh -t 10.129.60.0/24
    ./nmap2enum.sh -t 10.129.60.23 -r 300      # slower/safer rate for VPN labs

REQUIRED TOOLS:
    fping, fscan, nmap
EOF
}

TARGET=""
RATE=1000
SCAN_PRESET=""
# ---- Argument parsing ----
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)
            show_help
            exit 0
            ;;
        -t|--target)
            TARGET="$2"; shift 2 ;;
        -r|--rate)
            [[ "${2:-}" =~ ^[0-9]+$ ]] || { warn "--rate needs a number."; exit 1; }
            RATE="$2"; shift 2 ;;
        -s|--scan)
            [[ "${2:-}" =~ ^[1-5]$ ]] || { warn "--scan needs a value 1-5."; exit 1; }
            SCAN_PRESET="$2"; shift 2 ;;
        *)
            warn "Unknown argument: $1 (use -h for help)"
            shift
            ;;
    esac
done

[[ -z "$TARGET" ]] && read -rp "Enter the Target IP/Range:- " TARGET

# ---- Tool checks ----
check_tool() {
    if ! command -v "$1" &>/dev/null; then
        warn "'$1' not found in PATH: $PATH"
        warn "If it IS installed, try: hash -r   (clears stale zsh/bash command cache)"
        warn "or confirm its location with: find / -iname '$1' -type f 2>/dev/null"
        return 1
    fi
    return 0
}

check_tool nmap  || { warn "nmap is required. Install it and re-run. Exiting."; exit 1; }
check_tool fscan || { warn "fscan is required for the discovery scan. Install it and re-run. Exiting."; exit 1; }

# ---- Detect CIDR range vs any other fscan-native target format ----
IS_RANGE=0
if [[ "$TARGET" =~ /[0-9]{1,2}$ ]]; then
    IS_RANGE=1
fi

# ---- Output directory ----
SAFE_NAME=$(echo "$TARGET" | tr '/.' '__')
OUTDIR="scan_${SAFE_NAME}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"

banner "Nmap2Enum - Automated Scanning Pipeline"
banner "Target: $TARGET   Type: $([[ $IS_RANGE -eq 1 ]] && echo 'CIDR range' || echo 'Single host')"
banner "Output directory: $OUTDIR"

# ---- Step 1: Live host discovery (range only) ----
LIVE_HOSTS_FILE="$OUTDIR/live-hosts.txt"
if [[ "$IS_RANGE" -eq 1 ]]; then
    section "Live Host Discovery (fping)"
    if check_tool fping; then
        fping -asgq "$TARGET" 2>/dev/null | tee "$LIVE_HOSTS_FILE"
        HOST_COUNT=$(wc -l < "$LIVE_HOSTS_FILE")
        echo "Found $HOST_COUNT live host(s)."
        if [[ "$HOST_COUNT" -eq 0 ]]; then
            warn "No live hosts found. Exiting."
            exit 1
        fi
    else
        warn "fping missing - falling back to nmap ping sweep."
        nmap -sn "$TARGET" -oG - 2>/dev/null | awk '/Up$/{print $2}' | tee "$LIVE_HOSTS_FILE"
    fi
else
    echo "$TARGET" > "$LIVE_HOSTS_FILE"
fi

# ---- Determine target argument style for fscan/nmap ----
if [[ "$IS_RANGE" -eq 1 ]]; then
    FSCAN_TARGET_ARGS=(-hf "$LIVE_HOSTS_FILE")
else
    FSCAN_TARGET_ARGS=(-h "$TARGET")
fi
NMAP_TARGETS_ARG=(-iL "$LIVE_HOSTS_FILE")

# ---- Step 2: Full port + service discovery scan via fscan (output shown live) ----
section "Full Discovery Scan (fscan -p 1-65535 -nobr)"
RESULT_FILE="$OUTDIR/result.txt"
FSCAN_CONSOLE="$OUTDIR/fscan-console.txt"
fscan "${FSCAN_TARGET_ARGS[@]}" -p 1-65535 -nobr -o "$RESULT_FILE" 2>&1 | tee "$FSCAN_CONSOLE"

# ---- Step 3: Parse open ports into a file named 'ports' ----
section "Parsing open ports"
PORTS_FILE="$OUTDIR/ports"
# NOTE: the '[0-9]' pattern MUST stay quoted - unquoted, the shell globs it
# against the current directory (a stray file named 0-9 corrupts the list).
cat "$RESULT_FILE" | grep ':' | grep -v 'http' | cut -d ':' -f2 | grep -iE '[0-9]' | cut -d ' ' -f1 | sort -un | tr '\n' ',' | sed 's/,$//' | tee "$PORTS_FILE"
OPEN_PORTS=$(cat "$PORTS_FILE")

if [[ -z "$OPEN_PORTS" ]]; then
    warn "No open ports parsed from fscan output. Showing raw result.txt for debugging:"
    echo "---------------------------------------------"
    cat "$RESULT_FILE" 2>/dev/null
    echo "---------------------------------------------"
    exit 1
fi
echo "Open ports found: $OPEN_PORTS"
echo "Saved to: $PORTS_FILE"

# ---- Step 4: Menu for deep scan type ----
section "Choose deep scan type"
echo "  1) TCP deep scan only                   "
echo "  2) UDP top-ports scan                   "
echo "  3) Both TCP and UDP                     "
echo "  4) POC-CVE scan                         "
echo "  5) Everything (TCP + UDP + vuln scripts)"
if [[ -n "$SCAN_PRESET" ]]; then
    SCAN_CHOICE="$SCAN_PRESET"
    echo "Non-interactive: using --scan $SCAN_CHOICE"
elif [[ -t 0 ]]; then
    read -rp "Select an option [1-5]: " SCAN_CHOICE
else
    SCAN_CHOICE=1
    warn "No TTY and no --scan given - defaulting to 1 (TCP deep scan)."
fi

run_tcp_deep() {
    section "TCP Deep Scan (-sC -sV --reason) on ports: $OPEN_PORTS"
    mkdir -p "$OUTDIR/nmap"
    # sudo only when not already root and sudo exists - a TCP connect
    # scan (-sC -sV without -sS) works unprivileged on modern kernels.
    local SUDO=""
    [[ $EUID -ne 0 ]] && command -v sudo &>/dev/null && SUDO="sudo"
    $SUDO nmap -p "$OPEN_PORTS" -sC -sV --reason -Pn -vv "${NMAP_TARGETS_ARG[@]}" -oA "$OUTDIR/nmap/${SAFE_NAME}-nmap"
}

run_udp() {
    section "UDP Top-Ports Scan (--min-rate $RATE)"
    nmap -sUCV -T4 --min-rate "$RATE" "${NMAP_TARGETS_ARG[@]}" -vv -oA "$OUTDIR/nmap-udp"
}

run_poc_cve() {
    section "POC-CVE Scan (fscan -nobr -full)"
    fscan "${FSCAN_TARGET_ARGS[@]}" -nobr -full -o "$OUTDIR/fscan-poc-cve.txt" 2>&1 \
        | tee "$OUTDIR/fscan-poc-cve-console.txt"
}

run_fscan_everything() {
    section "Full Vulnerability Sweep (fscan -full, all modules)"
    fscan "${FSCAN_TARGET_ARGS[@]}" -full -o "$OUTDIR/fscan-everything.txt" 2>&1 \
        | tee "$OUTDIR/fscan-everything-console.txt"
}

case "$SCAN_CHOICE" in
    1) run_tcp_deep ;;
    2) run_udp ;;
    3) run_tcp_deep; run_udp ;;
    4) run_poc_cve ;;
    5) run_tcp_deep; run_udp; run_fscan_everything ;;
    *) warn "Invalid choice, defaulting to TCP deep scan only."; run_tcp_deep ;;
esac

section "Done"
echo "All results saved under: $OUTDIR"
echo "  - $LIVE_HOSTS_FILE"
echo "  - $FSCAN_CONSOLE  "
echo "  - $PORTS_FILE     "
echo "  - $OUTDIR/nmap-*.nmap / .gnmap / .xml"
echo "  - $OUTDIR/fscan-*-console.txt"
