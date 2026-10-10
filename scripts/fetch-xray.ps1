# Скачивает зафиксированную версию Xray-core в bin\ и проверяет SHA256.
# Xray нужен только для узлов с транспортом xhttp (его нет в sing-box): ARCHITECTURE.md §11.
$ErrorActionPreference = 'Stop'
$Version = '26.3.27'
$Hashes = @{
    'windows-64'        = 'd004c39288ce9ada487c6f398c7c545f7d749e44bdfdd59dbc9f865afba4e1ad'
    'windows-arm64-v8a' = '35d4ed6ec21224fb22b07c2c3f672e2350cd536f2c74d309150175a76365ea88'
}
$Arch = if ($env:PROCESSOR_ARCHITECTURE -eq 'ARM64') { 'windows-arm64-v8a' } else { 'windows-64' }
$Name = "Xray-$Arch"
$Root = Split-Path $PSScriptRoot -Parent
$Bin = Join-Path $Root 'bin'
$Tmp = Join-Path ([IO.Path]::GetTempPath()) "cproxy-$([guid]::NewGuid())"
New-Item -ItemType Directory -Force $Bin, $Tmp | Out-Null
try {
    $Zip = Join-Path $Tmp "$Name.zip"
    Invoke-WebRequest "https://github.com/XTLS/Xray-core/releases/download/v$Version/$Name.zip" -OutFile $Zip
    $Hash = (Get-FileHash $Zip -Algorithm SHA256).Hash.ToLower()
    if ($Hash -ne $Hashes[$Arch]) { throw "SHA256 mismatch for $Name.zip: $Hash" }
    Expand-Archive $Zip -DestinationPath (Join-Path $Tmp 'x')
    Copy-Item (Join-Path $Tmp 'x\xray.exe') (Join-Path $Bin 'xray.exe') -Force
    Write-Host "xray $Version ($Arch) -> $Bin\xray.exe"
} finally {
    Remove-Item -Recurse -Force $Tmp
}
