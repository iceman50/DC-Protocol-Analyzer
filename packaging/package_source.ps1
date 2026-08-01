[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$OutputZip
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$fixedTimestamp = [System.DateTimeOffset]::new(
    1980, 1, 1, 0, 0, 0, [System.TimeSpan]::Zero)

if ([string]::IsNullOrWhiteSpace($RepoRoot)) {
    $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
}

function Get-PluginVersion {
    param([Parameter(Mandatory = $true)][string]$VersionHeader)
    $text = Get-Content -LiteralPath $VersionHeader -Raw
    $match = [regex]::Match(
        $text,
        '(?m)^\s*#\s*define\s+PLUGIN_VERSION_STR\s+"([^"]+)"\s*$')
    if (-not $match.Success) {
        throw "PLUGIN_VERSION_STR was not found in '$VersionHeader'."
    }
    return $match.Groups[1].Value
}

function Assert-NoReparsePoint {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd("\", "/")
    $pathFull = [System.IO.Path]::GetFullPath($Path)
    $prefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
    if ($pathFull -cne $rootFull -and -not $pathFull.StartsWith(
        $prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Source path is outside the repository root: $pathFull"
    }

    $relative = $pathFull.Substring($rootFull.Length).TrimStart("\", "/")
    $current = $rootFull
    foreach ($part in @($relative -split '[\\/]' | Where-Object Length -gt 0)) {
        $current = Join-Path $current $part
        $item = Get-Item -LiteralPath $current -Force
        if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Source packaging refuses reparse points: $($item.FullName)"
        }
    }
}

function Get-AllowlistedTreeFiles {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$RelativeDirectory,
        [Parameter(Mandatory = $true)][string[]]$AllowedExtensions
    )

    $treeRoot = Join-Path $Root $RelativeDirectory
    if (-not (Test-Path -LiteralPath $treeRoot -PathType Container)) {
        return @()
    }
    Assert-NoReparsePoint -Root $Root -Path $treeRoot

    $result = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
    $queue = [System.Collections.Generic.Queue[string]]::new()
    $queue.Enqueue($treeRoot)
    while ($queue.Count -gt 0) {
        $directory = $queue.Dequeue()
        foreach ($item in Get-ChildItem -LiteralPath $directory -Force) {
            if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Source packaging refuses reparse points: $($item.FullName)"
            }
            if ($item.PSIsContainer) {
                $queue.Enqueue($item.FullName)
                continue
            }
            $extension = $item.Extension.ToLowerInvariant()
            if ($AllowedExtensions -notcontains $extension) {
                if ($extension -in @(
                    ".a", ".d", ".dbg", ".dll", ".dcext", ".exe", ".exp",
                    ".gch", ".gcda", ".gcno", ".ilk", ".lib", ".log", ".map",
                    ".o", ".obj", ".pdb", ".res", ".tmp", ".zip")) {
                    continue
                }
                throw "Unexpected file type in allowlisted source tree: $($item.FullName)"
            }
            $result.Add($item)
        }
    }
    return @($result)
}

function Move-FileAtomically {
    param(
        [Parameter(Mandatory = $true)][string]$TemporaryPath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )
    if (Test-Path -LiteralPath $DestinationPath) {
        $destination = Get-Item -LiteralPath $DestinationPath -Force
        if ($destination.PSIsContainer -or
            ($destination.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Atomic destination must be a regular file: $DestinationPath"
        }
        $backupPath = Join-Path (Split-Path -Parent $DestinationPath) (
            ".{0}.{1}.replace-backup.tmp" -f
                (Split-Path -Leaf $DestinationPath),
                [guid]::NewGuid().ToString("N"))
        try {
            [System.IO.File]::Replace(
                $TemporaryPath, $DestinationPath, $backupPath, $true)
        }
        finally {
            if (Test-Path -LiteralPath $backupPath) {
                Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
            }
        }
    }
    else {
        [System.IO.File]::Move($TemporaryPath, $DestinationPath)
    }
}

function Get-EntrySha256 {
    param([Parameter(Mandatory = $true)][System.IO.Compression.ZipArchiveEntry]$Entry)
    $stream = $Entry.Open()
    try {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        try {
            return ([System.BitConverter]::ToString($sha.ComputeHash($stream))).Replace("-", "")
        }
        finally {
            $sha.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-Sha256Text {
    param([Parameter(Mandatory = $true)][string]$Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($Text)
        return ([System.BitConverter]::ToString($sha.ComputeHash($bytes))).Replace("-", "")
    }
    finally {
        $sha.Dispose()
    }
}

$RepoRoot = [System.IO.Path]::GetFullPath((Resolve-Path -LiteralPath $RepoRoot).Path)
$rootItem = Get-Item -LiteralPath $RepoRoot -Force
if (-not $rootItem.PSIsContainer -or
    ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "Repository root must be a real directory, not a reparse point: $RepoRoot"
}

$sentinels = @(
    "build_dist.ps1",
    "src\version.h",
    "pluginsdk\PluginDefs.h",
    "projects\make\Makefile",
    "packaging\info.xml",
    "dwt\include\dwt\Version.h"
)
foreach ($relativePath in $sentinels) {
    $path = Join-Path $RepoRoot $relativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Repository sentinel is missing: $path"
    }
    Assert-NoReparsePoint -Root $RepoRoot -Path $path
}

$version = Get-PluginVersion -VersionHeader (Join-Path $RepoRoot "src\version.h")
if ($version -notmatch '^[0-9]+(?:\.[0-9]+){1,3}$') {
    throw "Plugin version is not safe for a release filename: $version"
}
$archiveRoot = "ProtocolAnalyzer-$version"

if ([string]::IsNullOrWhiteSpace($OutputZip)) {
    $OutputZip = Join-Path $RepoRoot "dist\ProtocolAnalyzer-$version-source.zip"
}
$OutputZip = [System.IO.Path]::GetFullPath($OutputZip)
$distRoot = [System.IO.Path]::GetFullPath((Join-Path $RepoRoot "dist"))
if (-not (Test-Path -LiteralPath $distRoot)) {
    [void](New-Item -ItemType Directory -Path $distRoot)
}
elseif (-not (Test-Path -LiteralPath $distRoot -PathType Container)) {
    throw "Repository dist path is not a directory: $distRoot"
}
Assert-NoReparsePoint -Root $RepoRoot -Path $distRoot
if ([System.IO.Path]::GetExtension($OutputZip) -ine ".zip") {
    throw "Source archive output must use the .zip extension: $OutputZip"
}
$distPrefix = $distRoot.TrimEnd("\", "/") +
    [System.IO.Path]::DirectorySeparatorChar
if (-not $OutputZip.StartsWith(
    $distPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
    throw "Source archive output must resolve beneath the repository dist directory: $distRoot"
}
$outputDirectory = Split-Path -Parent $OutputZip
if (-not (Test-Path -LiteralPath $outputDirectory -PathType Container)) {
    [void](New-Item -ItemType Directory -Path $outputDirectory -Force)
}
Assert-NoReparsePoint -Root $RepoRoot -Path $outputDirectory

$fixedFiles = @(
    "build_dist.ps1",
    "README.md",
    "CHANGELOG.md",
    "LICENSE",
    "gpl-2.0.txt",
    "projects\make\Makefile",
    "packaging\info.xml",
    "packaging\ProtocolAnalyzer.ico",
    "packaging\README.txt",
    "packaging\THIRD_PARTY.txt",
    "packaging\package_source.ps1",
    "packaging\clean_and_zip_source.ps1",
    "scripts\audit_release.ps1",
    "scripts\normalize_pe_timestamp.ps1",
    "doc\Plugin format (dcext).txt",
    "dwt\License.txt",
    "dwt\Preprocessor macros.txt",
    "dwt\readme.txt"
)

$sourceFiles = [System.Collections.Generic.List[System.IO.FileInfo]]::new()
foreach ($relativePath in $fixedFiles) {
    $path = Join-Path $RepoRoot $relativePath
    if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
        throw "Required source-release file is missing: $path"
    }
    Assert-NoReparsePoint -Root $RepoRoot -Path $path
    $sourceFiles.Add((Get-Item -LiteralPath $path))
}

foreach ($item in Get-AllowlistedTreeFiles `
    -Root $RepoRoot -RelativeDirectory "src" `
    -AllowedExtensions @(".cpp", ".h", ".rc")) {
    $sourceFiles.Add($item)
}
foreach ($item in Get-AllowlistedTreeFiles `
    -Root $RepoRoot -RelativeDirectory "pluginsdk" `
    -AllowedExtensions @(".cpp", ".h")) {
    $sourceFiles.Add($item)
}
foreach ($item in Get-AllowlistedTreeFiles `
    -Root $RepoRoot -RelativeDirectory "dwt\include" `
    -AllowedExtensions @(".h")) {
    $sourceFiles.Add($item)
}
foreach ($item in Get-AllowlistedTreeFiles `
    -Root $RepoRoot -RelativeDirectory "dwt\src" `
    -AllowedExtensions @(".cpp")) {
    $sourceFiles.Add($item)
}
if (Test-Path -LiteralPath (Join-Path $RepoRoot "tests") -PathType Container) {
    foreach ($item in Get-AllowlistedTreeFiles `
        -Root $RepoRoot -RelativeDirectory "tests" `
        -AllowedExtensions @(".cpp", ".h", ".ps1", ".md", ".txt")) {
        $sourceFiles.Add($item)
    }
}

$rootPrefix = $RepoRoot.TrimEnd("\", "/") + [System.IO.Path]::DirectorySeparatorChar
$records = @(
    $sourceFiles |
        ForEach-Object {
            $fullPath = [System.IO.Path]::GetFullPath($_.FullName)
            if (-not $fullPath.StartsWith(
                $rootPrefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                throw "Allowlisted source escaped repository root: $fullPath"
            }
            $relative = $fullPath.Substring($rootPrefix.Length).Replace("\", "/")
            [pscustomobject]@{
                FullPath = $fullPath
                EntryName = "$archiveRoot/$relative"
            }
        }
)

$outputAliasesInput = @(
    $records | Where-Object {
        $_.FullPath -ieq $OutputZip -or
        $_.FullPath -ieq "$OutputZip.sha256"
    }
)
if ($outputAliasesInput) {
    throw "Source archive output aliases an allowlisted input: $($outputAliasesInput.FullPath -join ', ')"
}
foreach ($existingOutput in @($OutputZip, "$OutputZip.sha256")) {
    if (Test-Path -LiteralPath $existingOutput) {
        $existingItem = Get-Item -LiteralPath $existingOutput -Force
        if (($existingItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Source packaging refuses a reparse-point output: $existingOutput"
        }
    }
}

$duplicateEntries = @($records.EntryName | Group-Object | Where-Object Count -gt 1)
if ($duplicateEntries) {
    throw "Source allowlist contains duplicate entries: $($duplicateEntries.Name -join ', ')"
}
$records = @($records | Sort-Object EntryName)
foreach ($record in $records) {
    if ($record.EntryName -match '(^/|^[A-Za-z]:|(^|/)\.\.(/|$)|\\|[^\x00-\x7F])') {
        throw "Unsafe source archive entry name: $($record.EntryName)"
    }
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$temporaryZip = Join-Path $outputDirectory (
    ".{0}.{1}.tmp" -f (Split-Path -Leaf $OutputZip), [guid]::NewGuid().ToString("N"))
$mutexSeed = Get-Sha256Text -Text $RepoRoot.ToUpperInvariant()
$mutexName = "Local\ProtocolAnalyzerBuild-$($mutexSeed.Substring(0, 24))"
$mutex = [System.Threading.Mutex]::new($false, $mutexName)
$mutexAcquired = $false
try {
    try {
        $mutexAcquired = $mutex.WaitOne(0)
    }
    catch [System.Threading.AbandonedMutexException] {
        $mutexAcquired = $true
    }
    if (-not $mutexAcquired) {
        throw "Another Protocol Analyzer source-packaging process is already using this workspace."
    }
    foreach ($existingOutput in @($OutputZip, "$OutputZip.sha256")) {
        if (Test-Path -LiteralPath $existingOutput) {
            $existingItem = Get-Item -LiteralPath $existingOutput -Force
            if ($existingItem.PSIsContainer -or
                ($existingItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
                throw "Source packaging refuses a non-file or reparse-point output: $existingOutput"
            }
        }
    }

    $zip = [System.IO.Compression.ZipFile]::Open(
        $temporaryZip, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($record in $records) {
            $entry = $zip.CreateEntry(
                $record.EntryName,
                [System.IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = $fixedTimestamp
            $entry.ExternalAttributes = 0
            $input = [System.IO.File]::OpenRead($record.FullPath)
            try {
                $output = $entry.Open()
                try {
                    $input.CopyTo($output)
                }
                finally {
                    $output.Dispose()
                }
            }
            finally {
                $input.Dispose()
            }
        }
    }
    finally {
        $zip.Dispose()
    }

    $validationZip = [System.IO.Compression.ZipFile]::OpenRead($temporaryZip)
    try {
        $actualNames = @($validationZip.Entries | ForEach-Object FullName)
        $expectedNames = @($records | ForEach-Object EntryName)
        if ($actualNames.Count -ne $expectedNames.Count) {
            throw "Source archive entry count mismatch."
        }
        for ($i = 0; $i -lt $expectedNames.Count; ++$i) {
            if ($actualNames[$i] -cne $expectedNames[$i]) {
                throw "Source archive ordering/content mismatch at entry $i."
            }
            $entry = $validationZip.Entries[$i]
            if ($entry.Length -le 0) {
                throw "Source archive contains an empty file: $($entry.FullName)"
            }
            if ($entry.LastWriteTime.Year -ne 1980 -or
                $entry.LastWriteTime.Month -ne 1 -or
                $entry.LastWriteTime.Day -ne 1 -or
                $entry.LastWriteTime.Hour -ne 0 -or
                $entry.LastWriteTime.Minute -ne 0 -or
                $entry.LastWriteTime.Second -ne 0) {
                throw "Source archive timestamp is not deterministic: $($entry.FullName)"
            }
            $archiveHash = Get-EntrySha256 -Entry $entry
            $sourceHash = (Get-FileHash `
                -LiteralPath $records[$i].FullPath -Algorithm SHA256).Hash
            if ($archiveHash -cne $sourceHash) {
                throw "Source archive content mismatch: $($entry.FullName)"
            }
        }
    }
    finally {
        $validationZip.Dispose()
    }

    Move-FileAtomically -TemporaryPath $temporaryZip -DestinationPath $OutputZip
    $hash = (Get-FileHash -LiteralPath $OutputZip -Algorithm SHA256).Hash.ToLowerInvariant()
    $checksumPath = "$OutputZip.sha256"
    $checksumTemporary = Join-Path $outputDirectory (
        ".{0}.{1}.tmp" -f (Split-Path -Leaf $checksumPath), [guid]::NewGuid().ToString("N"))
    try {
        [System.IO.File]::WriteAllText(
            $checksumTemporary,
            "$hash  $(Split-Path -Leaf $OutputZip)`n",
            [System.Text.UTF8Encoding]::new($false))
        Move-FileAtomically `
            -TemporaryPath $checksumTemporary `
            -DestinationPath $checksumPath
    }
    finally {
        if (Test-Path -LiteralPath $checksumTemporary) {
            Remove-Item -LiteralPath $checksumTemporary -Force -ErrorAction SilentlyContinue
        }
    }

    Write-Host ("Source release passed allowlist and content audit: {0} files" -f $records.Count) -ForegroundColor Green
    Write-Host "Created $OutputZip (SHA-256 $($hash.ToUpperInvariant()))" -ForegroundColor Green
    Write-Output $OutputZip
}
finally {
    if (Test-Path -LiteralPath $temporaryZip) {
        Remove-Item -LiteralPath $temporaryZip -Force -ErrorAction SilentlyContinue
    }
    if ($mutexAcquired) {
        [void]$mutex.ReleaseMutex()
    }
    $mutex.Dispose()
}
