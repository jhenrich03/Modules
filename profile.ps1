# Remove the progress bar/warning 
$ProgressPreference= "SilentlyContinue"
$WarningPreference = "SilentlyContinue"

# Set SMTP server
# $PSEmailServer = ""

. "$env:ExchangeInstallPath\bin\RemoteExchange.ps1"; Connect-ExchangeServer $PSEmailServer

# Set console colors
Set-PSReadlineOption -TokenKind Command -ForegroundColor White
Set-PSReadlineOption -TokenKind String -ForegroundColor Yellow
Set-PSReadlineOption -TokenKind Variable -ForegroundColor Red
Set-PSReadlineOption -BellStyle None

# Change the working directory
cd C:\

# Add back the progress bar
$ProgressPreference=’Continue’
$WarningPreference = "Continue"

# Import certain modules

import-module activedirectory
import-module customfunctions
import-module sqlps
import-module WindowsUpdate
get-module -ListAvailable vm* | import-module

# Connect to vCenter Server
$vcenter = ""

connect-viserver $vcenter

# Create aliases

new-alias -name mem -value Get-MemoryUsage
new-alias -name gadg -value Get-GroupMembership
new-alias -name gui -value Get-UserInfo
new-alias -name cpu -value Get-CPU
new-alias -name module -value Load-Module
new-alias -name gcomp -value Get-Computer
new-alias -name touch -value New-Item

# Clear the host
cls
