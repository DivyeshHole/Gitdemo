#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Prepares IIS to reverse-proxy https://amp.mindmatrix.net to the local App host.

.DESCRIPTION
    Applies the machine-level pieces that a site web.config is not allowed to set.
    Everything here is idempotent: re-running it makes no further changes.

      1. Enables ARR proxying with preserveHostHeader, so the rewrite rule in
         .local-dev/iis/web.config can forward to http://127.0.0.1:8111 and AMP
         still sees Host: amp.mindmatrix.net.
      2. Allow-lists the HTTP_X_SSL_ENABLED server variable. The rewrite rule sets
         it so InstallSslPolicy knows TLS was already terminated upstream.
      3. Issues (once) a self-signed certificate for amp.mindmatrix.net and
         *.amp.mindmatrix.net, trusts it in LocalMachine\Root, and binds it to the
         site 443 binding using SNI. SNI keeps the existing catch-all
         0.0.0.0:443 certificate in place for every other site on this machine.

    Run disable-proxy.ps1 to revert.

.NOTES
    Site-level rewrite rules live in .local-dev/iis/web.config and need no elevation.
#>
[CmdletBinding()]
param(
    [string] $SiteName   = 'amp.mindmatrix.net',
    [string] $HostHeader = 'amp.mindmatrix.net',
    [int]    $HttpsPort  = 443,
    [int]    $AppPort    = 8111
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$AppHost      = 'MACHINE/WEBROOT/APPHOST'
$CertFriendly = 'AMP local dev (amp.mindmatrix.net)'
$CertDnsNames = @('amp.mindmatrix.net', '*.amp.mindmatrix.net')

function Write-Step { param([string] $Message) Write-Host "`n==> $Message" -ForegroundColor Cyan }
function Write-Done { param([string] $Message) Write-Host "    [changed] $Message" -ForegroundColor Green }
function Write-Skip { param([string] $Message) Write-Host "    [already] $Message" -ForegroundColor DarkGray }

Import-Module WebAdministration -ErrorAction Stop

# --- 1. ARR reverse proxy --------------------------------------------------
Write-Step 'Enabling ARR reverse proxy (system.webServer/proxy)'
$proxySettings = [ordered]@{
    enabled                             = $true
    preserveHostHeader                  = $true
    reverseRewriteHostInResponseHeaders = $false
}
foreach ($name in $proxySettings.Keys) {
    $want    = $proxySettings[$name]
    $current = (Get-WebConfigurationProperty -PSPath $AppHost -Filter 'system.webServer/proxy' -Name $name).Value
    if ($current -ne $want) {
        Set-WebConfigurationProperty -PSPath $AppHost -Filter 'system.webServer/proxy' -Name $name -Value $want
        Write-Done "proxy/$name = $want (was $current)"
    }
    else {
        Write-Skip "proxy/$name = $want"
    }
}

# --- 2. Allow the SSL-offload server variable ------------------------------
Write-Step 'Allow-listing HTTP_X_SSL_ENABLED for URL Rewrite'
$varFilter = 'system.webServer/rewrite/allowedServerVariables'
$allowed   = @(Get-WebConfigurationProperty -PSPath $AppHost -Filter $varFilter -Name 'Collection')
if ($allowed | Where-Object { $_.name -eq 'HTTP_X_SSL_ENABLED' }) {
    Write-Skip 'HTTP_X_SSL_ENABLED is allowed'
}
else {
    Add-WebConfigurationProperty -PSPath $AppHost -Filter $varFilter -Name '.' -Value @{ name = 'HTTP_X_SSL_ENABLED' }
    Write-Done 'HTTP_X_SSL_ENABLED added to allowedServerVariables'
}

# --- 3. Development certificate --------------------------------------------
Write-Step 'Ensuring the development certificate'
$cert = Get-ChildItem Cert:\LocalMachine\My |
    Where-Object { $_.FriendlyName -eq $CertFriendly -and $_.NotAfter -gt (Get-Date) } |
    Sort-Object NotAfter -Descending |
    Select-Object -First 1

if ($cert) {
    Write-Skip "certificate $($cert.Thumbprint) valid until $($cert.NotAfter)"
}
else {
    $cert = New-SelfSignedCertificate -DnsName $CertDnsNames -CertStoreLocation 'Cert:\LocalMachine\My' -FriendlyName $CertFriendly -NotAfter (Get-Date).AddYears(5) -KeyLength 2048 -KeyExportPolicy Exportable -TextExtension @('2.5.29.37={text}1.3.6.1.5.5.7.3.1')
    Write-Done "issued certificate $($cert.Thumbprint) for $($CertDnsNames -join ', ')"
}

Write-Step 'Trusting the certificate (LocalMachine\Root)'
$root = New-Object System.Security.Cryptography.X509Certificates.X509Store 'Root', 'LocalMachine'
$root.Open('ReadWrite')
try {
    if ($root.Certificates.Find('FindByThumbprint', $cert.Thumbprint, $false).Count -gt 0) {
        Write-Skip 'certificate already trusted'
    }
    else {
        $root.Add($cert)
        Write-Done 'certificate added to the trusted root store'
    }
}
finally {
    $root.Close()
}

# --- 4. HTTPS binding with SNI ---------------------------------------------
Write-Step "Binding the certificate to $SiteName on $HttpsPort (SNI)"
if (-not (Get-Website -Name $SiteName -ErrorAction SilentlyContinue)) {
    throw "IIS site '$SiteName' was not found. Create it against .local-dev/iis before running this script."
}

$hostnamePort = "${HostHeader}:${HttpsPort}"
$sniBound = (netsh http show sslcert hostnameport=$hostnamePort 2>&1 | Out-String) -match [regex]::Escape($cert.Thumbprint)
$wanted   = "*:${HttpsPort}:${HostHeader}"
$binding  = Get-WebBinding -Name $SiteName -Protocol https -ErrorAction SilentlyContinue |
    Where-Object { $_.bindingInformation -eq $wanted -and $_.sslFlags -eq 1 }

if ($binding -and $sniBound) {
    Write-Skip "https binding $wanted already uses this certificate"
}
else {
    Get-WebBinding -Name $SiteName -Protocol https -ErrorAction SilentlyContinue | Remove-WebBinding
    New-WebBinding -Name $SiteName -Protocol https -Port $HttpsPort -HostHeader $HostHeader -SslFlags 1
    $binding = Get-WebBinding -Name $SiteName -Protocol https |
        Where-Object { $_.bindingInformation -eq $wanted }
    $binding.AddSslCertificate($cert.Thumbprint, 'My')
    Write-Done "https binding $wanted -> $($cert.Thumbprint)"
}

# --- 5. Make sure the site and its pool are running -------------------------
Write-Step 'Starting the site and its application pool'
$site = Get-Website -Name $SiteName
$pool = $site.applicationPool
if ((Get-WebAppPoolState -Name $pool).Value -ne 'Started') {
    Start-WebAppPool -Name $pool
    Write-Done "app pool '$pool' started"
}
else {
    Write-Skip "app pool '$pool' running"
}
if ($site.State -ne 'Started') {
    Start-Website -Name $SiteName
    Write-Done "site '$SiteName' started"
}
else {
    Write-Skip "site '$SiteName' running"
}

# --- 6. Verify --------------------------------------------------------------
Write-Step 'Verifying'
$listening = @(Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | Where-Object { $_.LocalPort -eq $AppPort })
if ($listening) {
    Write-Host "    App on 127.0.0.1:${AppPort} : listening"
}
else {
    Write-Host "    App on 127.0.0.1:${AppPort} : NOT running (start it with: dotnet run)" -ForegroundColor Yellow
}

$code = & curl.exe -sS -o NUL -w '%{http_code}' -m 25 "https://${HostHeader}/" 2>&1
Write-Host "    GET https://${HostHeader}/ -> $code"
switch -Regex ("$code") {
    '^(200|30[0-9])$' { Write-Host '    Proxy chain is working.' -ForegroundColor Green }
    '^50[234]$'       { Write-Host "    ARR reached an upstream that is down - start App on ${AppPort}." -ForegroundColor Yellow }
    '^500$'           { Write-Host '    Still a rewrite/config error - inspect the response body.' -ForegroundColor Red }
    default           { Write-Host '    Unexpected result; inspect manually.' -ForegroundColor Yellow }
}

Write-Host "`nDone. Revert with disable-proxy.ps1`n" -ForegroundColor Cyan
