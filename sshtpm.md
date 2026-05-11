# Using a TPM 2.0 Protected SSH Key on Linux with PKCS#11

This guide explains how to generate and use an SSH key stored securely inside a TPM 2.0 chip using `tpm2-pkcs11` on Linux.

The private key never leaves the TPM. SSH authentication happens through a PKCS#11 provider, which allows OpenSSH to use TPM-backed keys transparently.

This setup is useful for:

- Hardware-protected SSH authentication
- Preventing private key extraction
- Portable system administration setups
- Servers and workstations with integrated TPM 2.0 hardware
- Using SSH keys without storing plaintext private keys on disk

The examples below are intentionally anonymized and suitable for publication.

---

# Requirements

## Hardware

- A system with a TPM 2.0 chip
- TPM enabled in UEFI/BIOS

## Software

On Debian-based systems:

```bash
sudo apt update

sudo apt install \
    tpm2-tools \
    libtpm2-pkcs11-1 \
    tpm2-pkcs11-tools \
    openssh-client
```

---

# TPM Access Permissions

Add your user to the `tss` group so it can access TPM resources:

```bash
sudo usermod -aG tss $USER
```

Then log out and log back in.

You can verify group membership with:

```bash
id
```

You should see:

```text
groups=...,tss
```

---

# TPM2 PKCS#11 Storage Setup

`tpm2-pkcs11` stores metadata in a local database.

Create a directory for the PKCS#11 store:

```bash
mkdir -p ~/.tpm2-pkcs11
```

Set the environment variable:

```bash
export TPM2_PKCS11_STORE=$HOME/.tpm2-pkcs11
```

To make this persistent:

```bash
echo 'export TPM2_PKCS11_STORE=$HOME/.tpm2-pkcs11' >> ~/.bashrc
```

Reload your shell:

```bash
source ~/.bashrc
```

---

# Initialize the PKCS#11 Store

Initialize the store database:

```bash
tpm2_ptool init
```

This creates the SQLite database used by `tpm2-pkcs11`.

---

# Create a TPM Token

Create a token inside the TPM-backed store:

```bash
tpm2_ptool addtoken \
    --pid=1 \
    --label="ssh-token" \
    --userpin=USER_PIN \
    --sopin=ADMIN_PIN
```

## Explanation

### `--label`

Human-readable token name.

### `--userpin`

PIN required when using the SSH key.

### `--sopin`

Security Officer PIN used for administrative operations.

### `--pid=1`

References the primary object created during initialization.

---

# Generate the TPM-Protected SSH Key

Generate an ECC P-256 key:

```bash
tpm2_ptool addkey \
    --label="ssh-token" \
    --userpin=USER_PIN \
    --algorithm=ecc256
```

This creates a private key inside the TPM.

The private portion is non-exportable.

---

# Export the Public SSH Key

OpenSSH can retrieve the public key from the PKCS#11 provider.

Run:

```bash
ssh-keygen -D /usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so
```

Example output:

```text
ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBB...
```

Save this to a public key file:

```bash
ssh-keygen -D /usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so \
    > ~/.ssh/id_tpm.pub
```

---

# Install the Public Key on the Server

Copy the public key to the target server:

```bash
ssh-copy-id -i ~/.ssh/id_tpm.pub user@server
```

Or manually append it to:

```text
~/.ssh/authorized_keys
```

on the remote system.

---

# Connecting with the TPM Key

Use the PKCS#11 provider directly:

```bash
ssh -I /usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so user@server
```

You will usually be prompted for the TPM user PIN.

---

# Persistent SSH Configuration

You can configure SSH to automatically use the TPM-backed key.

Edit:

```text
~/.ssh/config
```

Example:

```sshconfig
Host example-server
    HostName server.example.com
    User username

    PKCS11Provider /usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so

    IdentityFile ~/.ssh/id_tpm.pub
    IdentitiesOnly yes
```

Now simply connect using:

```bash
ssh example-server
```

---

# Security Notes

## Advantages

- The private key never leaves the TPM
- Resistant against filesystem theft
- PIN-protected usage
- Better isolation than regular SSH keys

## Important Limitations

- TPMs are slower than dedicated HSMs
- TPM reset may destroy access to keys
- Keys are tied to the local hardware

---

# Optional Improvements

## Use `ssh-agent`

```bash
ssh-add -s /usr/lib/x86_64-linux-gnu/pkcs11/libtpm2_pkcs11.so
```

## Use systemd environment configuration

Create:

```text
~/.config/environment.d/tpm2-pkcs11.conf
```

Contents:

```text
TPM2_PKCS11_STORE=%h/.tpm2-pkcs11
```

---

# Conclusion

Using a TPM-backed SSH key with `tpm2-pkcs11` provides strong protection against private key extraction while remaining compatible with standard OpenSSH workflows.

---

# Server config

sshd must allow ecdsa-sha2-nistp256 keys.

```text
PubkeyAcceptedAlgorithms ecdsa-sha2-nistp256,sk-ssh-ed25519@openssh.com
```
