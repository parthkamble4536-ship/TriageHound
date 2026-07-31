# build_exe.ps1
# ============================================================
# One-click build script for Digital Forensics Toolkit .exe
# Run from D:\Projects\DF_Toolkit directory:
#   .\build_exe.ps1
# ============================================================

Write-Host '======================================================' -ForegroundColor Cyan
Write-Host '  Digital Forensics Toolkit -- Build .exe' -ForegroundColor Cyan
Write-Host '======================================================' -ForegroundColor Cyan
Write-Host ''

# 1. Install PyInstaller if not present
Write-Host '[1/4] Checking PyInstaller...' -ForegroundColor Yellow
python -m pip install pyinstaller --quiet
if ($LASTEXITCODE -ne 0) {
    Write-Host 'ERROR: Failed to install PyInstaller.' -ForegroundColor Red
    exit 1
}
Write-Host '      PyInstaller ready.' -ForegroundColor Green

# 2. Clean previous build
Write-Host '[2/4] Cleaning previous build artifacts...' -ForegroundColor Yellow
if (Test-Path 'dist')  { Remove-Item -Recurse -Force 'dist' }
if (Test-Path 'build') { Remove-Item -Recurse -Force 'build' }
Write-Host '      Clean complete.' -ForegroundColor Green

# 3. Run PyInstaller
Write-Host '[3/4] Building DF_Toolkit.exe (this may take 1-2 minutes)...' -ForegroundColor Yellow
python -m PyInstaller DF_Toolkit.spec
if ($LASTEXITCODE -ne 0) {
    Write-Host 'ERROR: PyInstaller build failed.' -ForegroundColor Red
    exit 1
}

# 4. Confirm output
$exePath = 'dist\DF_Toolkit\DF_Toolkit.exe'
if (Test-Path $exePath) {
    $size = [math]::Round((Get-Item $exePath).Length / 1MB, 1)
    Write-Host ''
    Write-Host '======================================================' -ForegroundColor Green
    Write-Host '  BUILD SUCCESSFUL!' -ForegroundColor Green
    Write-Host "  Output : $exePath" -ForegroundColor Green
    Write-Host "  Size   : ${size} MB" -ForegroundColor Green
    Write-Host ''
    Write-Host '  To run from a USB drive:' -ForegroundColor Cyan
    Write-Host '    1. Copy the entire dist\DF_Toolkit folder to USB' -ForegroundColor Cyan
    Write-Host '    2. Run DF_Toolkit.exe on any Windows PC' -ForegroundColor Cyan
    Write-Host '       (no Python installation required)' -ForegroundColor Cyan
    Write-Host '======================================================' -ForegroundColor Green
} else {
    Write-Host 'ERROR: Output .exe not found. Check build logs above.' -ForegroundColor Red
}
