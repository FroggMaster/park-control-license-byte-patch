<#
.SYNOPSIS
    ParkControl Bypass - Pattern Finder

.DESCRIPTION
    Verifies that all three byte patterns still match uniquely in a given
    ParkControl.exe. Run this before rebuilding after a ParkControl update.

.EXAMPLE
    .\find_patches.ps1 "C:\Program Files\Bitsum\ParkControl\ParkControl.exe"
#>

param(
    [Parameter(Mandatory)]
    [string]$ExePath
)

# ── Pattern definitions ────────────────────────────────────────────────────────
# Each entry: Name, Note, Pattern (hex string, ?? = wildcard), PatchOffsets
$patches = @(
    @{
        Name    = "Patch 1 - Inner HTTP result check"
        Note    = "NOP 'cmp eax,1' at +4, jz->jmp at +7, NOP 'cmp eax,0Dh'+jz at +13"
        Pattern = "41 8B 45 18 83 F8 01 0F 84 ?? ?? ?? ?? 83 F8 0D 0F 84 ?? ?? ?? ??"
    },
    @{
        Name    = "Patch 2 - DialogFunc format check gate"
        Note    = "NOP 'cmp al,1' + 'jnz failure' at +15 (8 bytes)"
        Pattern = "48 8B 5C 24 40 48 8B 4C 24 38 E8 ?? ?? ?? ?? 3C 01 0F 85 ?? ?? ?? ??"
    },
    @{
        Name    = "Patch 3 - DialogFunc result gate"
        Note    = "NOP 'cmp eax,1' at +15, jz->jmp at +18"
        Pattern = "4C 8B 44 24 38 48 8B D3 E8 ?? ?? ?? ?? 8B F0 83 F8 01 74 ??"
    }
)

# ── Helpers ────────────────────────────────────────────────────────────────────

function Parse-Pattern {
    param([string]$PatternStr)

    $tokens  = $PatternStr.Trim() -split '\s+'
    $bytes   = [System.Collections.Generic.List[byte]]::new()
    $mask    = [System.Collections.Generic.List[byte]]::new()

    foreach ($token in $tokens) {
        if ($token -eq '??') {
            $bytes.Add(0x00)
            $mask.Add(0x00)
        } else {
            $bytes.Add([Convert]::ToByte($token, 16))
            $mask.Add(0xFF)
        }
    }

    return $bytes.ToArray(), $mask.ToArray()
}

function Find-Pattern {
    param(
        [byte[]]$Data,
        [byte[]]$Pattern,
        [byte[]]$Mask
    )

    $results = [System.Collections.Generic.List[int]]::new()
    $plen    = $Pattern.Length
    $limit   = $Data.Length - $plen

    for ($i = 0; $i -le $limit; $i++) {
        $found = $true
        for ($j = 0; $j -lt $plen; $j++) {
            if ($Mask[$j] -eq 0xFF -and $Data[$i + $j] -ne $Pattern[$j]) {
                $found = $false
                break
            }
        }
        if ($found) { $results.Add($i) }
    }

    return $results
}

function Get-SectionRVA {
    param(
        [byte[]]$Data,
        [int]$FileOffset
    )

    # Parse PE headers to convert file offset -> RVA
    $peOffset    = [BitConverter]::ToInt32($Data, 0x3C)
    $sectionCount = [BitConverter]::ToInt16($Data, $peOffset + 6)
    $optHeaderSz = [BitConverter]::ToInt16($Data, $peOffset + 20)
    $sectionBase = $peOffset + 24 + $optHeaderSz
    $imageBase   = [BitConverter]::ToInt64($Data, $peOffset + 24 + 24)  # PE32+ optional header ImageBase

    for ($i = 0; $i -lt $sectionCount; $i++) {
        $off        = $sectionBase + ($i * 40)
        $virtAddr   = [BitConverter]::ToInt32($Data, $off + 12)
        $rawSize    = [BitConverter]::ToInt32($Data, $off + 16)
        $rawOffset  = [BitConverter]::ToInt32($Data, $off + 20)

        if ($FileOffset -ge $rawOffset -and $FileOffset -lt ($rawOffset + $rawSize)) {
            $rva = $FileOffset - $rawOffset + $virtAddr
            $va  = $imageBase + $rva
            return $rva, $va
        }
    }

    return $null, $null
}

# ── Main ───────────────────────────────────────────────────────────────────────

if (-not (Test-Path $ExePath)) {
    Write-Error "File not found: $ExePath"
    exit 1
}

Write-Host ""
Write-Host "Loading: $ExePath" -ForegroundColor Cyan
Write-Host ""

$data   = [System.IO.File]::ReadAllBytes($ExePath)
$allOk  = $true

foreach ($patch in $patches) {
    Write-Host ("-" * 60)
    Write-Host "  $($patch.Name)" -ForegroundColor White
    Write-Host "  $($patch.Note)" -ForegroundColor DarkGray
    Write-Host "  Pattern: $($patch.Pattern)" -ForegroundColor DarkGray

    $pattern, $mask = Parse-Pattern $patch.Pattern
    $matches         = Find-Pattern -Data $data -Pattern $pattern -Mask $mask

    if ($matches.Count -eq 0) {
        Write-Host "  [FAIL] NOT FOUND - pattern needs updating" -ForegroundColor Red
        $allOk = $false
    }
    elseif ($matches.Count -gt 1) {
        Write-Host "  [WARN] AMBIGUOUS - $($matches.Count) matches found (pattern too short)" -ForegroundColor Yellow
        foreach ($m in $matches) {
            $rva, $va = Get-SectionRVA -Data $data -FileOffset $m
            Write-Host "         file+0x$($m.ToString('X'))  RVA=0x$($rva.ToString('X'))  VA=0x$($va.ToString('X'))" -ForegroundColor Yellow
        }
        $allOk = $false
    }
    else {
        $rva, $va = Get-SectionRVA -Data $data -FileOffset $matches[0]
        Write-Host "  [OK]   UNIQUE match at file+0x$($matches[0].ToString('X'))  RVA=0x$($rva.ToString('X'))  VA=0x$($va.ToString('X'))" -ForegroundColor Green
    }

    Write-Host ""
}

Write-Host ("-" * 60)
if ($allOk) {
    Write-Host "All patterns matched uniquely. No update needed." -ForegroundColor Green
} else {
    Write-Host "One or more patterns need updating. See IDA_UPDATE_GUIDE.md." -ForegroundColor Red
}
Write-Host ""