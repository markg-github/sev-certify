# add-ssh-key.ps1
# Run after each reboot to load your SSH key into the agent.
# No administrator privileges required.
# Prerequisite: run setup-ssh-agent.ps1 once first.

$key = Get-ChildItem "$env:USERPROFILE\.ssh\" |
    Where-Object { $_.Name -match '^id_' -and $_.Extension -ne '.pub' } |
    Select-Object -First 1

if (-not $key) {
    Write-Error "No SSH private key found in $env:USERPROFILE\.ssh\"
    exit 1
}

ssh-add $key.FullName
Write-Host "Key loaded: $($key.Name). Ready to connect."
