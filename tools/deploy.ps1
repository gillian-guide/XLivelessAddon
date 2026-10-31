# Copies a built XLivelessAddon.asi + INI into a game folder, after verifying that
# the binary is the right kind of module for GTA IV. The game must be closed.
param(
    [Parameter(Mandatory = $true)]
    [string] $GameDir,

    [string] $Configuration = "Release",

    [string] $BuildDir = ""
)

$ErrorActionPreference = 'Stop'

$repo = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
if ([string]::IsNullOrWhiteSpace($BuildDir)) {
    $BuildDir = Join-Path $repo "build\win-x86"
}

$asi = Join-Path $BuildDir "bin\XLivelessAddon.asi"
$ini = Join-Path $BuildDir "bin\XLivelessAddon.ini"
$sourceIni = Join-Path $repo "data\XLivelessAddon.ini"

if (-not (Test-Path -LiteralPath $asi)) {
    throw "No ASI at $asi. Build it first: cmake --build --preset $($Configuration.ToLower())"
}
if (-not (Test-Path -LiteralPath $GameDir)) {
    throw "Game directory not found: $GameDir"
}

$game = (Resolve-Path -LiteralPath $GameDir).Path
foreach ($exe in @("GTAIV.exe", "EFLC.exe", "PlayGTAIV.exe")) {
    $process = Get-Process -Name ([System.IO.Path]::GetFileNameWithoutExtension($exe)) -ErrorAction SilentlyContinue
    if ($process) {
        throw "$exe is running. Close the game before replacing the ASI."
    }
}
if (-not ((Test-Path -LiteralPath (Join-Path $game "GTAIV.exe")) -or
          (Test-Path -LiteralPath (Join-Path $game "EFLC.exe")))) {
    Write-Warning "$game does not look like a GTA IV folder (no GTAIV.exe/EFLC.exe)"
}

& (Join-Path $PSScriptRoot "verify_asi.ps1") -Path $asi

Copy-Item -LiteralPath $asi -Destination (Join-Path $game "XLivelessAddon.asi") -Force
if (Test-Path -LiteralPath $ini) {
    Copy-Item -LiteralPath $ini -Destination (Join-Path $game "XLivelessAddon.ini") -Force
}
else {
    Copy-Item -LiteralPath $sourceIni -Destination (Join-Path $game "XLivelessAddon.ini") -Force
}

Write-Host "Deployed XLivelessAddon to $game"
