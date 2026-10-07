#!/bin/bash
# Usage:-
# ./rpc2enum.sh
# ./rpc2enum.sh [TARGET_IP]
# ./rpc2enum.sh -h | --help
# RPC_USER='USER' RPC_PASS='PASSWORD' ./rpc2enum.sh
# RPC_USER='USER' RPC_PASS='PASSWORD' ./rpc2enum.sh [TARGET_IP]
set -u
set -o pipefail

# Colors (dark red for [*], dark green for [+])
DRED='\033[38;5;9m'
DGREEN='\033[38;5;46m'
DYELLOW='\033[38;5;226m'
NC='\033[0m'

banner()  { echo -e "${DRED}[*] $1${NC}"; }
section() { echo -e "\n${DGREEN}[+] $1${NC}"; }
warn()    { echo -e "${DYELLOW}[!] $1${NC}"; }

show_help() {
    cat << EOF
rpc2enum.sh - Anonymous/authenticated RPC enumeration wrapper for rpcclient

USAGE:
    ./rpc2enum.sh [-h|--help] [TARGET_IP]

OPTIONS:
    -h, --help      Show this help message and exit

ARGUMENTS:
    TARGET_IP       IP address of the target (DC/SMB host). If omitted,
                    you will be prompted interactively.

AUTHENTICATION (environment variables, optional):
    RPC_USER        Username for authenticated session (default: anonymous)
    RPC_PASS        Password for authenticated session

EXAMPLES:
    ./rpc2enum.sh
    ./rpc2enum.sh 10.129.60.23
    RPC_USER='j.arbuckle' RPC_PASS='P@ssw0rd' ./rpc2enum.sh
    RPC_USER='j.arbuckle' RPC_PASS='P@ssw0rd' ./rpc2enum.sh 10.129.60.23

WHAT IT RUNS:
    Port check (139/445), srvinfo, lsaquery, querydominfo, enumdomusers,
    enumdomgroups, enumalsgroups, querydispinfo, per-user queryuser,
    lookupnames, RID cycling (lookupsids, configurable range), getdompwinfo,
    netshareenumall, enumprivs, enumprinters.

ENVIRONMENT VARIABLES:
    RPC_USER / RPC_PASS     Credentials (anonymous session when unset)
    RPC_RID_START           RID cycle start (default: 500)
    RPC_RID_END             RID cycle end   (default: 1100)

All console output is also saved to a timestamped loot directory.
EOF
}

# ---- Argument parsing (while loop: options and positional target in any order)
IP=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        -h|--help)   show_help; exit 0 ;;
        -t|--target) [[ -n "${2:-}" ]] || { warn "-t/--target needs a value."; exit 1; }
                     IP="$2"; shift 2 ;;
        -*)          warn "Unknown option: $1 (use -h for help)"; shift ;;
        *)           IP="$1"; shift ;;
    esac
done

if [[ -z "$IP" ]]; then
    read -rp "Provide the Target IP address:- " IP
fi
[[ -n "$IP" ]] || { warn "No target given. Exiting."; exit 1; }

# NB: never assign to plain USER/PASS - clobbering $USER leaks the target
# username into every child process environment.
RC_USER="${RPC_USER:-}"
RC_PASS="${RPC_PASS:-}"
RID_START="${RPC_RID_START:-500}"
RID_END="${RPC_RID_END:-1100}"
[[ "$RID_START" =~ ^[0-9]+$ && "$RID_END" =~ ^[0-9]+$ ]] || { warn "RPC_RID_START/END must be integers."; exit 1; }

# ---- Tool checks ----
command -v rpcclient &>/dev/null || { warn "rpcclient not found (apt install samba-common-bin). Exiting."; exit 1; }
HAVE_NC=1; command -v nc &>/dev/null || { warn "nc not found - skipping port check."; HAVE_NC=0; }

# ---- Loot directory: everything printed is also saved ----
OUTDIR="rpc_loot_${IP//./_}_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$OUTDIR"
chmod 700 "$OUTDIR"
exec > >(tee "$OUTDIR/rpc2enum-console.txt") 2>&1

if [[ -n "$RC_USER" ]]; then
    # Real credentials supplied -> authenticate properly, no -N
    AUTH=(-U "${RC_USER}%${RC_PASS}")
else
    # No credentials -> fall back to null/anonymous session
    AUTH=(-U "" -N)
fi

run() {
    # run "description" "rpcclient command"
    rpcclient "${AUTH[@]}" "$IP" -c "$2" 2>&1
}

banner "Rpc-client Enumeration script.."
banner "Target: $IP  (auth: '${RC_USER:-anonymous}')  loot: $OUTDIR"

section "Checking if RPC/SMB port is open (139/445)"
if [[ "$HAVE_NC" -eq 1 ]]; then
    nc -zv -w3 "$IP" 139 2>&1 || true
    nc -zv -w3 "$IP" 445 2>&1 || true
else
    echo "skipped (nc missing)."
fi

section "Server Info (srvinfo)"
run "srvinfo" "srvinfo"

section "Domain / LSA Info (lsaquery)"
run "lsaquery" "lsaquery"

section "Domain Information (querydominfo)"
run "querydominfo" "querydominfo"

section "User Enumeration (enumdomusers)"
USERS_RAW=$(run "enumdomusers" "enumdomusers")
echo "$USERS_RAW"

section "Group Enumeration (enumdomgroups)"
run "enumdomgroups" "enumdomgroups"

section "Alias / Local Group Enumeration (builtin + domain)"
run "enumalsgroups builtin" "enumalsgroups builtin"
run "enumalsgroups domain" "enumalsgroups domain"

section "Display Information (querydispinfo)"
run "querydispinfo" "querydispinfo"

section "Per-user detail (queryuser) for each RID found"
# pull rid:[0x...] out of enumdomusers output and query each one
# sed, not grep -oP: PCRE (-P) is GNU-only and absent on BSD/macOS grep.
echo "$USERS_RAW" | sed -n 's/.*rid:\[\(0x[0-9a-fA-F]*\)\].*/\1/p' | while read -r rid; do
    echo "--- RID $rid ---"
    run "queryuser $rid" "queryuser $rid"
done

section "SID Lookup for known usernames (lookupnames)"
echo "$USERS_RAW" | sed -n 's/user:\[\([^]]*\)\].*/\1/p' | while read -r uname; do
    run "lookupnames $uname" "lookupnames $uname"
done

section "RID Cycling / SID brute force (lookupsids, $RID_START-$RID_END)"
DOMSID=$(run "lsaquery" "lsaquery" | grep -oE 'S-1-5-21-[0-9-]+' | head -n1)
if [[ -n "$DOMSID" ]]; then
    echo "Domain SID: $DOMSID"
    for rid in $(seq "$RID_START" "$RID_END"); do
        run "lookupsids $DOMSID-$rid" "lookupsids $DOMSID-$rid" | grep -v -E "NT_STATUS_NONE_MAPPED|\*unknown\*\\\\\*unknown\*" || true
    done
else
    echo "Could not resolve domain SID, skipping RID cycle."
fi

section "Password Policy Enumeration (getdompwinfo)"
run "getdompwinfo" "getdompwinfo"

section "Shares Enumeration (netshareenumall)"
run "netshareenumall" "netshareenumall"

section "Privileges Enumeration (enumprivs)"
run "enumprivs" "enumprivs"

section "Printer Enumeration (enumprinters)"
run "enumprinters" "enumprinters"

section "Done"
echo "Console log saved to: $OUTDIR/rpc2enum-console.txt"
