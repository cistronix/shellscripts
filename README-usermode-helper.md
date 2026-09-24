# usermode-helper — Privileged Helper Dispatcher

## Overview

A restrictive allowlist-based dispatcher for kernel usermode helpers, intended for use with:
```
CONFIG_STATIC_USERMODEHELPER=y
CONFIG_STATIC_USERMODEHELPER_PATH="/sbin/usermode-helper"
```

This tool acts as a gatekeeper between the Linux kernel and privileged helper binaries. It reads a configuration file, validates that the requested helper matches a rule, and then safely executes it.

## How it Works

1. **Load config**: Read `/etc/usermode-helper.conf` and validate it is root-owned, not writable, and a regular file.
2. **Parse rules**: Tokenize each configuration line, supporting quotes and backslash escapes.
3. **Match rules**: Check whether the kernel-provided helper path and arguments match one of three directive types:
   - `allow-path /path/to/helper` — allows the helper with any arguments
   - `allow-exact /path/to/helper arg1 arg2 ...` — requires exact argument count and values
   - `allow-prefix /path/to/helper arg1` — requires the helper and prefix arguments, then allows additional trailing arguments
4. **Validate executable**: Ensure the helper is root-owned, regular, executable, not writable by others, and not the dispatcher itself.
5. **Log decision**: Write allow/deny/error to kernel log (`/dev/kmsg`) with process IDs, UIDs, arguments (escaped).
6. **Execute or deny**: Run the helper via `execve()` or exit with status 1.

## Build

```bash
gcc -o usermode-helper usermode-helper.c -Wall -Wextra -O2
sudo cp usermode-helper /sbin/
sudo chmod 755 /sbin/usermode-helper
```

## Configuration

Create `/etc/usermode-helper.conf`:

```bash
sudo touch /etc/usermode-helper.conf
sudo chmod 600 /etc/usermode-helper.conf
sudo chown root:root /etc/usermode-helper.conf
```

## Configuration Format

```
# Comments start with #

# allow-path: Allow a helper with any arguments
allow-path /sbin/modprobe

# allow-exact: Require exact arguments
allow-exact /usr/sbin/firmware-loader /load /fw.bin

# allow-prefix: Require helper and prefix arguments; allow additional trailing args
allow-prefix /usr/libexec/my-helper --mode=strict

# Quotes and escaping are supported
allow-exact "/sbin/helper with spaces" "arg 1" "arg 2"
allow-path "/sbin/another-helper"
```

## Example Configuration

```bash
# Default kernel helpers that are usually safe:
allow-path /sbin/modprobe

# If you use firmware loading, uncomment only what you need:
# allow-path /usr/lib/firmware/load-firmware

# Custom helpers with strict arguments:
# allow-exact /usr/local/sbin/custom-handler --config=/etc/custom.conf
```

## ⚠️  Security Warnings

### Critical Issues

1. **Time-of-check/time-of-use (TOCTOU) race**
   - The dispatcher validates the helper with `stat(path)` and then executes it with `execve(path)`.
   - Between those calls, an attacker with write access to a parent directory can replace the file or symlink.
   - **Mitigation**: Keep `/sbin/` and all parent directories on a read-only mount or otherwise protected filesystem. Verify that only root can write.
   - **Better fix**: Use `open(..., O_PATH | O_NOFOLLOW)` to open the helper first, then use `execveat(fd, "", ..., AT_EMPTY_PATH)` to execute the already-validated descriptor.

2. **Parent directory symlink/replacement attacks**
   - The code does not verify that every parent directory is root-owned and not writable.
   - A writable `/sbin/` or any ancestor directory allows an attacker to inject a malicious symlink or subdirectory.
   - **Mitigation**: Ensure all ancestor directories from `/` to `/sbin/` are root-owned and not writable except by root.

3. **Inherited environment**
   - The dispatcher passes the entire kernel environment to the helper:
     ```c
     execve(argv[0], argv, environ);
     ```
   - Kernel-controlled variables in the environment may influence library loading, privilege escalation, or unsafe parsing in the helper.
   - **Mitigation**: Sanitize the environment or pass a minimal allowlist: `PATH`, `LANG=C`.

4. **Overly broad allow rules**
   - `allow-path /sbin/modprobe` allows any modprobe invocation, regardless of arguments.
   - A malicious kernel caller can pass arbitrary arguments to modprobe, potentially loading untrusted modules.
   - **Recommendation**: Use `allow-exact` or `allow-prefix` with the minimal argument set your kernel actually needs.

### Medium Issues

5. **Usermode-helper is a global kernel feature**
   - With `CONFIG_STATIC_USERMODEHELPER=y`, all kernel subsystems that invoke usermode helpers are routed through this dispatcher.
   - Firewalling or denying a common helper (e.g., modprobe) can break kernel features like module loading, firmware loading, or udev events.
   - **Mitigation**: Test your deny rules in a development environment. A config error can render a system unbootable.

6. **Limited logging**
   - Logs are sent to `/dev/kmsg` with truncation at ~3800 characters, so very long arguments are lost.
   - The kernel may generate high call volume, filling the log and potentially masking other messages.
   - **Mitigation**: Monitor kernel logs carefully. Add rate-limiting or disable logging in production if it causes excessive I/O.

7. **No capability dropping**
   - The dispatcher runs with the full ambient capabilities and privilege set it inherits from the kernel.
   - **Mitigation**: Consider running helpers with reduced capabilities if they support it (e.g., libcap, seccomp).

## Usage Example

After building and configuring, ensure the kernel is booted with:
```
CONFIG_STATIC_USERMODEHELPER=y
CONFIG_STATIC_USERMODEHELPER_PATH="/sbin/usermode-helper"
```

Then reboot or verify that `/sbin/usermode-helper` is the dispatcher. Monitor kernel logs:
```bash
sudo dmesg | grep usermode-helper-logger
sudo journalctl -u kernel | grep usermode-helper-logger
```

## Monitoring Decisions

All decisions are logged to `/dev/kmsg` with the prefix `usermode-helper-logger`. Each log entry includes:

- **Decision**: `ALLOW`, `DENY`, or `EXECFAIL`
- **PID/PPID**: Process ID and parent ID
- **UID/GID**: Real and effective user/group IDs
- **Rule line**: Line number in config if matched
- **Reason**: Why the request was denied (escaped)
- **Helper path and arguments**: Fully escaped (escaped)

Example:
```
[    0.123456] <12>usermode-helper-logger: ALLOW helper_pid=123 helper_ppid=1 uid=0 euid=0 gid=0 egid=0 argc=2 rule_line=5 helper="/sbin/modprobe" argv[1]="module_name"
[    0.234567] <12>usermode-helper-logger: DENY helper_pid=456 helper_ppid=1 uid=0 euid=0 gid=0 egid=0 argc=1 reason="no matching allow rule" helper="/some/unknown/helper"
```

## Testing

1. Build the dispatcher and place it at `/sbin/usermode-helper`.
2. Create a minimal config at `/etc/usermode-helper.conf`.
3. Verify the config is owned by root and not world-writable:
   ```bash
   ls -la /etc/usermode-helper.conf
   # Should show: -rw------- 1 root root
   ```
4. Reboot into a kernel with `CONFIG_STATIC_USERMODEHELPER=y`.
5. Monitor logs to ensure expected helpers are being allowed.

## Comparison: Dynamic vs Static Helper Mode

| Aspect | `CONFIG_STATIC_USERMODEHELPER=n` | `CONFIG_STATIC_USERMODEHELPER=y` + dispatcher |
|--------|-----------------------------------|----------------------------------------------|
| Helper path | Runtime-configurable (mutable) | Hardcoded, then dispatched | 
| Risk of path injection | Higher | Lower (fixed kernel config) |
| Gatekeeper enforced | No | Yes (this program) |
| Log audit trail | Limited | Detailed |
| Complexity | Lower | Higher |
| Security boundary strength | Weak | Medium (with caveats) |

## Recommended Security Posture

- ✅ Use `CONFIG_STATIC_USERMODEHELPER=y` to lock the kernel's helper path.
- ✅ Use only `allow-exact` rules with explicit arguments.
- ✅ Ensure `/sbin/` and ancestors are read-only or tightly protected.
- ✅ Regularly audit `/etc/usermode-helper.conf` for unnecessary rules.
- ✅ Monitor `/dev/kmsg` for DENY decisions and unexpected patterns.
- ⚠️ If possible, run helpers in a constrained environment (seccomp, namespace, reduced capabilities).
- ⚠️ Do not rely on this dispatcher alone as a security boundary; use defense-in-depth.

## Exit Codes

- `0` — Helper executed (control passed to helper; exit code reflects helper's exit)
- `1` — Config error, no matching rule, invalid helper, or security check failed
- `127` — `execve()` failed

## License

See the repository for license information.
