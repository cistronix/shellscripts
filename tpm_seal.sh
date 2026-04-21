#!/bin/sh

if [ "$1" = "" ]; then
  echo "\n  Gebruik:"
  echo "  $0 <bestand>"
  echo ""
  exit 2
fi

if [ -e "$1" ]; then
  if [ -e "$1.tpmpub" ] || [ -e "$1.tpmpriv" ]; then
    echo "\n  Fout: uitvoerbestand (\"$1.tpmpub\" / \"$1.tpmpriv\") bestaat al"
    echo ""
    exit 1
  fi
else
  echo "\n  Bestand \"$1\" bestaat niet"
  echo ""
  exit 1
fi

size=$(stat -c %s -- "$1") || {
    echo "\n  Fout: kan bestand niet lezen\n" >&2
    exit 1
}

if [ "$size" -ge 1 ] && [ "$size" -le 128 ]; then
    true
else
    echo "\n  Fout: bestand is $size bytes (moet 1–128 zijn)\n" >&2
    exit 1
fi


PRIMARY=$(mktemp --suffix=.ctx)
SESSION=$(mktemp --suffix=.ctx)
POLICY=$(mktemp --suffix=.pcr)

trap 'rm -f "$PRIMARY" "$SESSION" "$POLICY"' EXIT

# Create primary
tpm2_createprimary -C o -G ecc -g sha256 -c "$PRIMARY" -Q

# Start policy session
tpm2_startauthsession --policy-session -c "$PRIMARY" -S "$SESSION" -Q

# Maak de policy
tpm2_policypcr -S "$SESSION" -l sha256:0,1,2,3,5,7,14 -L "$POLICY" -Q


# Seal object "secret"
tpm2_create -C "$PRIMARY" -u "$1.tpmpub" -r "$1.tpmpriv" -i "$1" -L "$POLICY" -Q

# Save public.pub and private.key, they contain the encrypted secret

# Flush context
tpm2_flushcontext "$SESSION" -Q
