#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Reverts every machine-level change made by enable-proxy.ps1.

.DESCRIPTION
    Restores the state this machine was in before the AMP local proxy was set up:

      1. Turns ARR proxying back off (nothing else on this machine used it).
      2. Removes HTTP_X_SSL_ENABLED from the URL Rewrite allow-list.
      3. Removes the SNI certificate binding and restores the plain
         *:443:amp.mindmatrix.net binding, leaving the catch-all 0.0.0.0:443
         certificate untouched.
      4. Deletes the self-signed certificate this setup issued, from both
         LocalMachine\My and LocalMachine\Root. Pass -KeepCertificate to leave it.

    The site-level rewrite rules in .local-dev/iis/web.config are left alone;
    delete that file or the IIS site itself to remove them.
#>
[CmdletBinding()]
param(
    [string] $SiteName   = 'amp.mindmatrix.net',
    [string] $HostHeader = 'amp.mindmatrix.net',
    [int]    $HttpsPort  = 443,
    [switch] $KeepCertificate
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AppHost      = 'MACHINE/WEBROOT/APPHOST'
$CertFriendly = 'AMP local dev (amp.mindmatrix.net)'

function Write-Step { param([string] $Message) Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Done { param([string] $Message) Write-Host "    [changed] $Message" -ForegroundColor Green }
function Write-Skip { param([string] $Message) Write-Host "    [already] $Message" -ForegroundColor DarkGray }

Import-Module WebAdministration -ErrorAction Stop

# --- 1. Restore the plain HTTPS binding -------------------------------------
Write-Step "Restoring the https binding on $SiteName"
if (Get-Website -Name $SiteName -ErrorAction SilentlyContinue) {
    $wanted = "*:${HttpsPort}:${HostHeader}"
    Get-WebBinding -Name $SiteName -Protocol https -ErrorAction SilentlyContinue | Remove-WebBinding
    New-WebBinding -Name $SiteName -Protocol https -Port $HttpsPort -HostHeader $HostHeader
    Write-Done "https binding reset to $wanted (no SNI, no certificate mapping)"

    $hostnamePort = "${HostHeader}:${HttpsPort}"
    $existing = netsh http show sslcert hostnameport=$hostnamePort 2>&1 | Out-String
    if ($existing -match [regex]::Escape($hostnamePort)) {
        netsh http delete sslcert hostnameport=$hostnamePort | Out-Null
        Write-Done "removed the http.sys SNI certificate binding for $hostnamePort"
    }
    else {
        Write-Skip "no SNI certificate binding for $hostnamePort"
    }
}
else {
    Write-Skip "site '$SiteName' not present"
}

# --- 2. Remove the allow-listed server variable -----------------------------
Write-Step 'Removing HTTP_X_SSL_ENABLED from the URL Rewrite allow-list'
$varFilter = 'system.webServer/rewrite/allowedServerVariables'
$allowed   = @(Get-WebConfigurationProperty -PSPath $AppHost -Filter $varFilter -Name 'Collection')
if ($allowed | Where-Object { $_.name -eq 'HTTP_X_SSL_ENABLED' }) {
    Remove-WebConfigurationProperty -PSPath $AppHost -Filter $varFilter -Name '.' -AtElement @{ name = 'HTTP_X_SSL_ENABLED' }
    Write-Done 'HTTP_X_SSL_ENABLED removed'
}
else {
    Write-Skip 'HTTP_X_SSL_ENABLED not present'
}

# --- 3. Disable ARR proxying -------------------------------------------------
Write-Step 'Disabling ARR reverse proxy'
$current = (Get-WebConfigurationProperty -PSPath $AppHost -Filter 'system.webServer/proxy' -Name 'enabled').Value
if ($current) {
    Set-WebConfigurationProperty -PSPath $AppHost -Filter 'system.webServer/proxy' -Name 'enabled' -Value $false
    Write-Done 'proxy/enabled = False'
}
else {
    Write-Skip 'proxy/enabled = False'
}

# --- 4. Remove the development certificate -----------------------------------
Write-Step 'Removing the development certificate'
if ($KeepCertificate) {
    Write-Skip '-KeepCertificate specified; leaving the certificate in place'
}
else {
    $removed = 0
    foreach ($storeName in @('My', 'Root')) {
        $store = New-Object System.Security.Cryptography.X509Certificates.X509Store $storeName, 'LocalMachine'
        $store.Open('ReadWrite')
        try {
            foreach ($candidate in @($store.Certificates)) {
                if ($candidate.FriendlyName -eq $CertFriendly) {
                    $store.Remove($candidate)
                    Write-Done "removed $($candidate.Thumbprint) from LocalMachine\$storeName"
                    $removed++
                }
            }
        }
        finally {
            $store.Close()
        }
    }
    if ($removed -eq 0) {
        Write-Skip 'no certificate issued by this setup was found'
    }
}

Write-Host "`nDone.`n" -ForegroundColor Cyan
