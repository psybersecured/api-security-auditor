$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
Set-Location $Root
$env:PYTHONPATH = "$Root\src"

$demo = Start-Process -FilePath "python" -ArgumentList "-m", "uvicorn", "demo_target.app:app", "--host", "127.0.0.1", "--port", "9000" -PassThru
Start-Sleep -Seconds 1
try {
  python -m auditor.cli scan demo_target/openapi.yaml `
    --base-url http://127.0.0.1:9000 `
    --bearer-token demo-user-a `
    --secondary-bearer-token demo-user-b `
    --alternate-id user_id=2 `
    --ack-authorized `
    --output reports/demo-report.json `
    --html reports/demo-report.html
  Write-Host "Demo complete. Open reports/demo-report.html"
}
finally {
  Stop-Process -Id $demo.Id -ErrorAction SilentlyContinue
}
