$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
New-Item -ItemType Directory -Path 'outputs' -Force | Out-Null

# Stamp the commit into the binary so a running server can be traced to its source.
$version = 'dev'
if (Get-Command git -ErrorAction SilentlyContinue) {
  $described = git describe --tags --always --dirty 2>$null
  if ($LASTEXITCODE -eq 0 -and $described) { $version = $described.Trim() }
}
$ldflags = "-X main.version=$version"

npm ci
if ($LASTEXITCODE -ne 0) { throw 'npm dependency installation failed' }
npm audit --omit=dev --audit-level=high
if ($LASTEXITCODE -ne 0) { throw 'npm audit found high or critical vulnerabilities' }
npm run build
if ($LASTEXITCODE -ne 0) { throw 'TypeScript / React build failed' }
go test -buildvcs=false ./...
if ($LASTEXITCODE -ne 0) { throw 'Go tests failed' }
if (Get-Command govulncheck -ErrorAction SilentlyContinue) {
  govulncheck ./...
  if ($LASTEXITCODE -ne 0) { throw 'govulncheck found vulnerable Go dependencies' }
} else {
  Write-Warning 'govulncheck is not installed; Go dependencies were not checked. Install: go install golang.org/x/vuln/cmd/govulncheck@latest'
}
go build -buildvcs=false -trimpath -ldflags $ldflags -o outputs/trinetra.exe ./cmd/trinetra
if ($LASTEXITCODE -ne 0) { throw 'Go server build failed' }
go build -buildvcs=false -trimpath -ldflags $ldflags -o outputs/collector.exe ./cmd/collector
if ($LASTEXITCODE -ne 0) { throw 'Collector build failed' }
npm run test:api
if ($LASTEXITCODE -ne 0) { throw 'API integration tests failed' }
Get-FileHash outputs/trinetra.exe, outputs/collector.exe -Algorithm SHA256 |
  ForEach-Object { '{0}  {1}' -f $_.Hash.ToLower(), (Split-Path $_.Path -Leaf) } |
  Set-Content -Encoding ascii outputs/SHA256SUMS.txt
Write-Host "Build $version and checks passed. SHA-256 hashes: outputs/SHA256SUMS.txt"
Write-Host 'Run outputs/trinetra.exe -static dist from this folder.'
