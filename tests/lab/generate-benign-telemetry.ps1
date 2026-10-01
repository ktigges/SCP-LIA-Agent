[CmdletBinding()]
param(
    [ValidateRange(1, 500)]
    [int]$Iterations = 50,

    [ValidateRange(50, 60000)]
    [int]$DelayMilliseconds = 250,

    [uri]$TargetUri,

    [ValidatePattern('^[A-Za-z0-9_-]{1,40}$')]
    [string]$Marker = "LIA_TEST_MARKER"
)

$ErrorActionPreference = "Stop"

function Test-PrivateOrLoopbackAddress {
    param([System.Net.IPAddress]$Address)

    if ([System.Net.IPAddress]::IsLoopback($Address)) {
        return $true
    }

    $bytes = $Address.GetAddressBytes()
    if ($Address.AddressFamily -eq [System.Net.Sockets.AddressFamily]::InterNetwork) {
        return $bytes[0] -eq 10 `
            -or ($bytes[0] -eq 172 -and $bytes[1] -ge 16 -and $bytes[1] -le 31) `
            -or ($bytes[0] -eq 192 -and $bytes[1] -eq 168) `
            -or ($bytes[0] -eq 169 -and $bytes[1] -eq 254)
    }

    return $Address.IsIPv6LinkLocal -or (($bytes[0] -band 0xfe) -eq 0xfc)
}

if ($TargetUri) {
    if ($TargetUri.Scheme -notin @("http", "https")) {
        throw "TargetUri must use HTTP or HTTPS."
    }

    $targetAddress = $null
    if (-not [System.Net.IPAddress]::TryParse($TargetUri.Host, [ref]$targetAddress)) {
        throw "TargetUri must use a literal loopback or private lab IP address, not a DNS name."
    }
    if (-not (Test-PrivateOrLoopbackAddress -Address $targetAddress)) {
        throw "TargetUri must resolve directly to a loopback or RFC1918/link-local lab address."
    }

    try {
        Invoke-WebRequest -Uri $TargetUri -Method Head -TimeoutSec 3 -UseBasicParsing | Out-Null
    }
    catch {
        throw "TargetUri preflight failed. Verify the listener, private IP, port, and firewall rule: $($_.Exception.Message)"
    }
}

$runId = [guid]::NewGuid().ToString("N")
$workDirectory = Join-Path $env:TEMP "lia-lab-$runId"
$registryPath = "HKCU:\Software\LIA-Lab"
$networkFailures = 0

New-Item -ItemType Directory -Path $workDirectory | Out-Null
New-Item -Path $registryPath -Force | Out-Null

Write-Host "Generating $Iterations bounded telemetry iterations. RunId=$runId"

try {
    for ($index = 1; $index -le $Iterations; $index++) {
        $token = "${Marker}_${runId}_$index"
        $filePath = Join-Path $workDirectory "$token.txt"

        & "$env:ComSpec" /d /c "echo $token" | Out-Null
        Set-Content -Path $filePath -Value $token -Encoding ascii
        Get-Content -Path $filePath | Out-Null
        Set-ItemProperty -Path $registryPath -Name "LastMarker" -Value $token

        if ($TargetUri) {
            $separator = if ($TargetUri.Query) { "&" } else { "?" }
            $requestUri = "$($TargetUri.AbsoluteUri)$separator" + "liaMarker=$token"
            try {
                Invoke-WebRequest -Uri $requestUri -Method Get -TimeoutSec 5 -UseBasicParsing | Out-Null
            }
            catch {
                $networkFailures++
                if ($networkFailures -le 5) {
                    Write-Warning "Request $index failed: $($_.Exception.Message)"
                }
            }
        }

        Remove-Item -Path $filePath
        Start-Sleep -Milliseconds $DelayMilliseconds
    }
}
finally {
    Remove-Item -Path $registryPath -Recurse -Force -ErrorAction SilentlyContinue
    Remove-Item -Path $workDirectory -Recurse -Force -ErrorAction SilentlyContinue
}

if ($networkFailures -gt 0) {
    throw "$networkFailures network requests failed. Verify that the private lab sink is reachable."
}

Write-Host "Telemetry generation completed. RunId=$runId"
