# Find an existing codex binary on a Windows remote and emit "codex:<path>".
# Preserve command/PATH precedence, then check fixed trusted locations. Never
# invoke candidates, package managers, or installer paths during detection.
$ErrorActionPreference = 'SilentlyContinue'

$firstPath = $null
$seen = @{}

function Consider-CodexPath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) {
        return
    }
    try {
        $resolved = [System.IO.Path]::GetFullPath([Environment]::ExpandEnvironmentVariables($Path))
    } catch {
        return
    }
    if ($seen.ContainsKey($resolved)) {
        return
    }
    $seen[$resolved] = $true
    if (-not (Test-Path -LiteralPath $resolved -PathType Leaf)) {
        return
    }
    if ($null -eq $firstPath) {
        $firstPath = $resolved
    }

}

Get-Command codex -ErrorAction SilentlyContinue | Select-Object -First 1 | ForEach-Object {
    Consider-CodexPath $_.Source
}

$codexHome = if ($env:CODEX_HOME) { $env:CODEX_HOME } else { Join-Path $HOME '.codex' }
$commonCandidates = @(
    (Join-Path $codexHome 'packages\standalone\current\codex.exe'),
    (Join-Path $codexHome 'packages\standalone\current\codex.cmd'),
    (Join-Path $HOME 'AppData\Roaming\npm\codex.cmd'),
    (Join-Path $HOME '.cargo\bin\codex.exe'),
    (Join-Path $HOME '.bun\bin\codex.exe'),
    (Join-Path $HOME '.bun\bin\codex.cmd'),
    (Join-Path $HOME '.volta\bin\codex.exe'),
    (Join-Path $HOME '.volta\bin\codex.cmd'),
    (Join-Path $HOME '.local\bin\codex.exe')
)
foreach ($candidate in $commonCandidates) {
    Consider-CodexPath $candidate
}

if ($null -ne $firstPath) {
    Write-Output "codex:$firstPath"
    exit 0
}
