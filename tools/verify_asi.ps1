# Verifies that the built artifact is the right kind of binary for a GTA IV ASI:
# a 32-bit Windows DLL, linked at the add-on's preferred base, with a GUI
# subsystem and a USER32 import. Run by CTest; exits non-zero on any mismatch.
param(
    [Parameter(Mandatory = $true)]
    [string] $Path
)

$ErrorActionPreference = 'Stop'
$resolved = (Resolve-Path -LiteralPath $Path).Path
$bytes = [System.IO.File]::ReadAllBytes($resolved)

function Read-U16([int] $offset) { [BitConverter]::ToUInt16($bytes, $offset) }
function Read-U32([int] $offset) { [BitConverter]::ToUInt32($bytes, $offset) }

$failures = New-Object System.Collections.Generic.List[string]

if ($bytes.Length -lt 0x40 -or $bytes[0] -ne 0x4D -or $bytes[1] -ne 0x5A) {
    $failures.Add('missing MZ header')
}
else {
    $pe = [int](Read-U32 0x3C)
    if ((Read-U32 $pe) -ne 0x00004550) {
        $failures.Add('missing PE signature')
    }
    else {
        $machine = Read-U16 ($pe + 4)
        $optional = $pe + 24
        $magic = Read-U16 $optional
        $imageBase = Read-U32 ($optional + 28)
        $sizeOfImage = Read-U32 ($optional + 56)
        $subsystem = Read-U16 ($optional + 68)
        $importRva = Read-U32 ($optional + 96 + (8 * 1))
        $importSize = Read-U32 ($optional + 96 + (8 * 1) + 4)

        if ($machine -ne 0x014C) { $failures.Add(("machine is 0x{0:X4}, expected 0x014C (i386)" -f $machine)) }
        if ($magic -ne 0x010B) { $failures.Add(("optional header magic is 0x{0:X4}, expected 0x010B (PE32)" -f $magic)) }
        if ($imageBase -ne 0x10000000) { $failures.Add(("image base is 0x{0:X8}, expected 0x10000000" -f $imageBase)) }
        if ($subsystem -ne 2) { $failures.Add(("subsystem is {0}, expected 2 (GUI)" -f $subsystem)) }
        if ($sizeOfImage -lt 0x1000) { $failures.Add('size of image looks empty') }
        if ($importRva -eq 0 -or $importSize -eq 0) { $failures.Add('no import directory') }

        # Walk the import descriptors and look for USER32.dll.
        $imports = @()
        if ($importRva -ne 0) {
            $sectionTable = $optional + (Read-U16 ($pe + 20))
            $sectionCount = Read-U16 ($pe + 6)
            $rvaToOffset = {
                param([uint32] $rva)
                for ($i = 0; $i -lt $sectionCount; $i++) {
                    $section = $sectionTable + ($i * 40)
                    $virtual = Read-U32 ($section + 12)
                    $virtualSize = Read-U32 ($section + 8)
                    $raw = Read-U32 ($section + 20)
                    if ($rva -ge $virtual -and $rva -lt ($virtual + [Math]::Max($virtualSize, 0x1000))) {
                        return [int]($raw + ($rva - $virtual))
                    }
                }
                return -1
            }
            $descriptor = & $rvaToOffset $importRva
            if ($descriptor -lt 0) {
                $failures.Add('import directory is not mapped')
            }
            else {
                for ($i = 0; $i -lt 64; $i++) {
                    $entry = $descriptor + ($i * 20)
                    $nameRva = Read-U32 ($entry + 12)
                    if ($nameRva -eq 0) { break }
                    $nameOffset = & $rvaToOffset $nameRva
                    if ($nameOffset -lt 0) { break }
                    $name = ''
                    while ($bytes[$nameOffset] -ne 0) {
                        $name += [char]$bytes[$nameOffset]
                        $nameOffset++
                    }
                    $imports += $name.ToLowerInvariant()
                }
            }
        }

        if ($imports -notcontains 'user32.dll') {
            $failures.Add('USER32.dll is not imported')
        }
    }
}

if ($failures.Count -gt 0) {
    Write-Error ("{0}: {1}" -f $resolved, ($failures -join '; '))
    exit 1
}

Write-Host ("{0}: PE32 i386, base 0x10000000, GUI subsystem, USER32 imported" -f $resolved)
exit 0
