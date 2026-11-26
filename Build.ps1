$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot
New-Item -ItemType Directory -Path 'outputs' -Force | Out-Null
npm ci
if ($LASTEXITCODE -ne 0) { throw 'npm dependency installation failed' }
npm run build
if ($LASTEXITCODE -ne 0) { throw 'TypeScript / React build failed' }
go test -buildvcs=false ./...
if ($LASTEXITCODE -ne 0) { throw 'Go tests failed' }
go build -buildvcs=false -o outputs/trinetra.exe ./cmd/trinetra
if ($LASTEXITCODE -ne 0) { throw 'Go server build failed' }
go build -buildvcs=false -o outputs/collector.exe ./cmd/collector
if ($LASTEXITCODE -ne 0) { throw 'Collector build failed' }
npm run test:api
if ($LASTEXITCODE -ne 0) { throw 'API integration tests failed' }
Write-Host 'Build and checks passed. Run outputs/trinetra.exe -static dist from this folder.'
