# How to SSH into images

SSH support is enabled on the `debug/ssh` branch. Public keys are fetched at
build time from `https://github.com/<actor>.keys` — no secrets required.

## Windows client setup

### One-time (requires Administrator)

```powershell
.\modules\ssh-support\scripts\setup-ssh-agent.ps1
```

Configures the Windows SSH agent to start automatically on every boot.

### Per-boot (no Administrator required)

```powershell
.\modules\ssh-support\scripts\add-ssh-key.ps1
```

Loads your SSH private key into the agent. Run once after each reboot.

## Connecting

### Host

```
ssh root@<bare-metal-host>
```

### Guest (via jump host)

The guest's SSH port (22) is forwarded to port 2222 on the host:

```
ssh -J root@<bare-metal-host> root@localhost -p 2222
```

### Optional: ~/.ssh/config entry

```
Host sev-guest
    HostName localhost
    Port 2222
    User root
    ProxyJump root@<bare-metal-host>
```

Then simply:

```
ssh sev-guest
```

## Notes

- Password auth is enabled (`PermitRootLogin yes`, password: `root`) to ease
  initial testing. Once key auth is confirmed working, tighten to
  `PermitRootLogin prohibit-password` and `PasswordAuthentication no`.
- After a rebuild, SSH will warn that the host key has changed (images
  generate fresh keys each build). Clear the old entry:
  `ssh-keygen -R <bare-metal-host>`
