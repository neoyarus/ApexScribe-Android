$ErrorActionPreference = 'Stop'
$artifacts = @(
    @{
        Name = 'libv2ray.aar'
        Url = 'https://github.com/2dust/AndroidLibXrayLite/releases/download/v26.10.17/libv2ray.aar'
        Sha256 = 'fd6cb61fed873e465c3064327dffbcb22dc3fd78260d162ec9e868db2582495f'
    },
    @{
        Name = 'hev-socks5-tunnel.aar'
        Url = 'https://github.com/heiher/hev-socks5-tunnel/releases/download/2.19.0/hev-socks5-tunnel.aar'
        Sha256 = 'fbbf014c1c4c6d1e0922db88542abd9dc726600473bdfdc8039ed157b4ba02b0'
    }
)
$destination = Join-Path $PSScriptRoot 'libs'
New-Item -ItemType Directory -Force -Path $destination | Out-Null
foreach ($artifact in $artifacts) {
    $target = Join-Path $destination $artifact.Name
    if ((Test-Path -LiteralPath $target) -and (Get-FileHash -LiteralPath $target -Algorithm SHA256).Hash -eq $artifact.Sha256) {
        Write-Host "$($artifact.Name): verified"
        continue
    }
    $temporary = "$target.download"
    try {
        Invoke-WebRequest -Uri $artifact.Url -OutFile $temporary
        if ((Get-FileHash -LiteralPath $temporary -Algorithm SHA256).Hash -ne $artifact.Sha256) {
            throw "SHA256 mismatch for $($artifact.Name)"
        }
        Move-Item -LiteralPath $temporary -Destination $target -Force
        Write-Host "$($artifact.Name): downloaded and verified"
    } finally {
        if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary }
    }
}
