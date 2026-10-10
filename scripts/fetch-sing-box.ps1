# Скачивает зафиксированную версию sing-box в bin\ и проверяет SHA256.
$ErrorActionPreference = 'Stop'
$Version = '1.14.3'
$Hashes = @{
    'windows-amd64' = 'd8b86ef58936dba9230ec6a57ffa4243933f3c14ef4809828b6c553440ed1518'
    'windows-arm64' = '195b35424c6e3f5913954c7f08c5d8ba2d2199f6d18eb27a3972a5a29cdaa78c'
}
$Arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'windows-arm64' } else { 'windows-amd64' }
$Name = "sing-box-$Version-$Arch"
$Root = Split-Path $PSScriptRoot -Parent
$Bin = Join-Path $Root 'bin'
$Tmp = Join-Path ([IO.Path]::GetTempPath()) "cproxy-$([guid]::NewGuid())"
New-Item -ItemType Directory -Force $Bin, $Tmp | Out-Null
try {
    $Zip = Join-Path $Tmp "$Name.zip"
    Invoke-WebRequest "https://github.com/SagerNet/sing-box/releases/download/v$Version/$Name.zip" -OutFile $Zip
    $Hash = (Get-FileHash $Zip -Algorithm SHA256).Hash.ToLower()
    if ($Hash -ne $Hashes[$Arch]) { throw "SHA256 mismatch for $Name.zip: $Hash" }
    Expand-Archive $Zip -DestinationPath $Tmp
    Copy-Item (Join-Path $Tmp "$Name\sing-box.exe") (Join-Path $Bin 'sing-box.exe') -Force
    Write-Host "sing-box $Version ($Arch) -> $Bin\sing-box.exe"
} finally {
    Remove-Item -Recurse -Force $Tmp
}
