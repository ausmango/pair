$ErrorActionPreference = 'Stop'
$pairRoot = Split-Path $PSScriptRoot -Parent
try {
    Set-Location -LiteralPath $pairRoot
    $pairEnvironment = Join-Path $pairRoot '.tools\env.ps1'
    if (-not (Test-Path -LiteralPath $pairEnvironment)) {
        throw 'The local build environment is missing: .tools\env.ps1'
    }
    . $pairEnvironment
    $pairExecutable = Join-Path $pairRoot 'target\x86_64-pc-windows-gnu\debug\pair.exe'
    $pairRunning = Get-Process -Name pair -ErrorAction SilentlyContinue | Where-Object {
        $_.Path -eq $pairExecutable
    }
    if ($pairRunning) {
        Write-Host 'A developer preview is already open. Save your notes and close it to continue.'
        Write-Host 'This launcher will rebuild automatically after that window closes.'
        $pairRunning | Wait-Process -ErrorAction SilentlyContinue
    }
    Write-Host 'Building Pair from your current source...'
    & cargo build --target x86_64-pc-windows-gnu
    if ($LASTEXITCODE -ne 0) {
        throw 'Build failed. Pair was not launched; see the compiler message above.'
    }
    $pairBuild = Get-Item -LiteralPath $pairExecutable
    Write-Host "Opening current UI: $($pairBuild.FullName)"
    Write-Host "Executable updated: $($pairBuild.LastWriteTime)"
    Write-Host 'Keep this console open while using Pair; startup errors will appear here.'
    $pairErrorLog = Join-Path $pairRoot '.tools\dev-preview-stderr.txt'
    $pairPreview = Start-Process -FilePath $pairExecutable -WorkingDirectory $pairRoot -RedirectStandardError $pairErrorLog -PassThru -Wait
    if ($pairPreview.ExitCode -ne 0) {
        if (Test-Path -LiteralPath $pairErrorLog) {
            Get-Content -LiteralPath $pairErrorLog
        }
        throw "Pair exited with code $($pairPreview.ExitCode)."
    }
} catch {
    Write-Host $_.Exception.Message -ForegroundColor Red
    exit 1
}
