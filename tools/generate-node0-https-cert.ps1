[CmdletBinding()]
param(
    [string]$OutDir = "",
    [string]$IpAddress = "192.168.1.50",
    [string]$DnsName = "node0.local",
    [int]$Years = 10
)

$ErrorActionPreference = "Stop"

if ([string]::IsNullOrWhiteSpace($OutDir)) {
    $OutDir = Join-Path $PSScriptRoot "..\main\certs"
}
$OutDir = [System.IO.Path]::GetFullPath($OutDir)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null

$rsa = [System.Security.Cryptography.RSACng]::new(2048)
$hash = [System.Security.Cryptography.HashAlgorithmName]::SHA256
$padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
$subject = "CN=$DnsName, O=KeeMASH"
$req = [System.Security.Cryptography.X509Certificates.CertificateRequest]::new($subject, $rsa, $hash, $padding)

$san = [System.Security.Cryptography.X509Certificates.SubjectAlternativeNameBuilder]::new()
$san.AddDnsName($DnsName)
$san.AddIpAddress([System.Net.IPAddress]::Parse($IpAddress))
$req.CertificateExtensions.Add($san.Build())
$req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509BasicConstraintsExtension]::new($false, $false, 0, $true))
$keyUsage = [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::DigitalSignature -bor
            [System.Security.Cryptography.X509Certificates.X509KeyUsageFlags]::KeyEncipherment
$req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509KeyUsageExtension]::new($keyUsage, $true))

$oids = [System.Security.Cryptography.OidCollection]::new()
[void]$oids.Add([System.Security.Cryptography.Oid]::new("1.3.6.1.5.5.7.3.1"))
$req.CertificateExtensions.Add([System.Security.Cryptography.X509Certificates.X509EnhancedKeyUsageExtension]::new($oids, $true))

$notBefore = [System.DateTimeOffset]::UtcNow.AddDays(-1)
$notAfter = $notBefore.AddYears($Years)
$cert = $req.CreateSelfSigned($notBefore, $notAfter)

function Convert-ToPem([string]$Label, [byte[]]$Bytes) {
    $b64 = [Convert]::ToBase64String($Bytes)
    $lines = [System.Collections.Generic.List[string]]::new()
    $lines.Add("-----BEGIN $Label-----")
    for ($i = 0; $i -lt $b64.Length; $i += 64) {
        $len = [Math]::Min(64, $b64.Length - $i)
        $lines.Add($b64.Substring($i, $len))
    }
    $lines.Add("-----END $Label-----")
    return ($lines -join "`n") + "`n"
}

$certPem = Convert-ToPem "CERTIFICATE" ($cert.Export([System.Security.Cryptography.X509Certificates.X509ContentType]::Cert))
$keyPem = Convert-ToPem "PRIVATE KEY" ($rsa.Key.Export([System.Security.Cryptography.CngKeyBlobFormat]::Pkcs8PrivateBlob))

Set-Content -LiteralPath (Join-Path $OutDir "node0_https_servercert.pem") -Value $certPem -Encoding ascii
Set-Content -LiteralPath (Join-Path $OutDir "node0_https_prvtkey.pem") -Value $keyPem -Encoding ascii

Write-Host "Generated node0 HTTPS cert/key in $OutDir for https://$IpAddress/"
