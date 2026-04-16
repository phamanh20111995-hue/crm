$ErrorActionPreference = 'Stop'
Set-Location (Join-Path $PSScriptRoot '..')

# Prefer py launcher if available
if (Get-Command py -ErrorAction SilentlyContinue) {
    py scripts/run_demo.py
} else {
    python scripts/run_demo.py
}
