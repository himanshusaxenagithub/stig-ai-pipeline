# Download a private CPython from python.org if this PC has none.
# Used by run-hidden.vbs. Nothing is added to PATH. Nothing needs admin.
$ErrorActionPreference = "Stop"
$dest = Join-Path $env:LOCALAPPDATA "STIG Checker\runtime"
$py = Join-Path $dest "python.exe"
if (Test-Path $py) {
    Write-Output $py
    exit 0
}

$url = "https://www.python.org/ftp/python/3.12.7/python-3.12.7-embed-amd64.zip"
$expect = "0d57bb6cb078b74d23dbfe91f77d6780d45bed328911609f1f7ee2ba1606bf44"
$zip = Join-Path $env:TEMP "stig-checker-python-embed.zip"

Write-Host "Downloading Python 3.12.7 (embeddable) from python.org…"
Invoke-WebRequest -Uri $url -OutFile $zip -UseBasicParsing
$got = (Get-FileHash $zip -Algorithm SHA256).Hash.ToLowerInvariant()
if ($got -ne $expect) {
    throw "Python download failed the SHA-256 check (`$got). Refusing to run it."
}

New-Item -ItemType Directory -Force -Path $dest | Out-Null
Expand-Archive -LiteralPath $zip -DestinationPath $dest -Force
Get-ChildItem -LiteralPath $dest -Filter "python*._pth" | ForEach-Object {
    $text = Get-Content -LiteralPath $_.FullName -Raw
    $text = $text -replace '#import site', 'import site'
    Set-Content -LiteralPath $_.FullName -Value $text -NoNewline
}
Remove-Item -LiteralPath $zip -Force -ErrorAction SilentlyContinue
Write-Output $py
