# setup-ssh-agent.ps1
# Run ONCE as Administrator to configure the Windows SSH agent service.
# After this, the agent starts automatically on every boot.

#Requires -RunAsAdministrator

Set-Service -Name ssh-agent -StartupType Automatic
Start-Service ssh-agent
Write-Host "SSH agent configured for automatic startup and started."
