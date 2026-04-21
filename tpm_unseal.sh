#!/bin/sh

if [ "$1" = "" ]; then
  echo "\n  Gebruik:"
  echo "  $0 <bestand>"
  echo ""
  exit 2
fi

if [ -e "$1.tpmpub" ] && [ -e "$1.tpmpriv" ]; then
  true
else
  echo "\n  Bestanden \"$1.tpmpub\" en \"$1.tpmpriv\" bestaat niet"
  echo ""
  exit 1
fi

PRIMARY=$(mktemp --suffix=.ctx)
SESSION=$(mktemp --suffix=.ctx)
POLICY=$(mktemp --suffix=.pcr)
SECRET=$(mktemp --suffix=.ctx)

trap 'rm -f "$PRIMARY" "$SESSION" "$POLICY" "$SECRET"' EXIT

# Create primary
tpm2_createprimary -C o -G ecc -g sha256 -c "$PRIMARY" -Q

# Start policy session
tpm2_startauthsession --policy-session -c "$PRIMARY" -S "$SESSION" -Q

# Maak de policy
tpm2_policypcr -S "$SESSION" -l sha256:0,1,2,3,5,7,14 -L "$POLICY" -Q


# Load objects
tpm2_load -C "$PRIMARY" -u "$1.tpmpub" -r "$1.tpmpriv" -c "$SECRET" -Q

# Unseal
tpm2_unseal -c "$SECRET" -p session:"$SESSION"

# Flush context
tpm2_flushcontext "$SESSION" -Q
