[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$PackagePath,

    [Parameter(Mandatory = $true)]
    [string]$DllPath,

    [Parameter(Mandatory = $true)]
    [string]$DebugPath,

    [Parameter(Mandatory = $true)]
    [ValidateSet("Debug", "Release")]
    [string]$Configuration,

    [Parameter(Mandatory = $true)]
    [string]$ObjdumpPath,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedVersion,

    [Parameter(Mandatory = $true)]
    [string]$ExpectedGuid,

    [Parameter(Mandatory = $true)]
    [int]$ExpectedApiVersion,

    [string]$SmokeTestPath,

    [ValidateRange(5, 300)]
    [int]$SmokeTimeoutSeconds = 60
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$packageDllName = "ProtocolAnalyzer.dll"
$packageDebugName = "ProtocolAnalyzer.dbg"
$fixedTimestamp = [System.DateTimeOffset]::new(
    1980, 1, 1, 0, 0, 0, [System.TimeSpan]::Zero)
$expectedEntries = @(
    "BUILD-PROVENANCE.txt",
    "ProtocolAnalyzer.ico",
    $packageDebugName,
    $packageDllName,
    "GPL-2.0.txt",
    "info.xml",
    "LibDWT-License.txt",
    "LICENSE.txt",
    "SHA256SUMS",
    "THIRD-PARTY.txt"
) | Sort-Object

function Assert-LeafFile {
    param([Parameter(Mandatory = $true)][string]$Path)
    if (-not (Test-Path -LiteralPath $Path -PathType Leaf)) {
        throw "Required audit input is not a file: $Path"
    }
}

function Invoke-Objdump {
    param([Parameter(Mandatory = $true)][string[]]$Arguments)

    $savedPreference = $ErrorActionPreference
    $ErrorActionPreference = "Continue"
    try {
        $output = @(& $ObjdumpPath @Arguments 2>&1 | ForEach-Object ToString)
        $exitCode = $LASTEXITCODE
    }
    finally {
        $ErrorActionPreference = $savedPreference
    }
    if ($exitCode -ne 0) {
        throw "objdump $($Arguments -join ' ') failed with exit code $exitCode.`n$($output -join "`n")"
    }
    return $output
}

function Get-StreamSha256 {
    param([Parameter(Mandatory = $true)][System.IO.Stream]$Stream)

    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        return ([System.BitConverter]::ToString($sha.ComputeHash($Stream))).Replace("-", "")
    }
    finally {
        $sha.Dispose()
    }
}

function Get-ZipEntryText {
    param([Parameter(Mandatory = $true)][System.IO.Compression.ZipArchiveEntry]$Entry)

    $stream = $Entry.Open()
    try {
        $reader = [System.IO.StreamReader]::new(
            $stream, [System.Text.UTF8Encoding]::new($false), $true)
        try {
            return $reader.ReadToEnd()
        }
        finally {
            $reader.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

function Get-ZipEntrySha256 {
    param([Parameter(Mandatory = $true)][System.IO.Compression.ZipArchiveEntry]$Entry)

    $stream = $Entry.Open()
    try {
        return Get-StreamSha256 -Stream $stream
    }
    finally {
        $stream.Dispose()
    }
}

function Write-CapturedProcessOutput {
    param(
        [string]$StandardOutput,
        [string]$StandardError
    )

    if (-not [string]::IsNullOrWhiteSpace($StandardOutput)) {
        Write-Host $StandardOutput.TrimEnd()
    }
    if (-not [string]::IsNullOrWhiteSpace($StandardError)) {
        Write-Host $StandardError.TrimEnd() -ForegroundColor Yellow
    }
}

function Test-ByteSequence {
    param(
        [Parameter(Mandatory = $true)][byte[]]$Haystack,
        [Parameter(Mandatory = $true)][byte[]]$Needle
    )

    if ($Needle.Length -eq 0 -or $Needle.Length -gt $Haystack.Length) {
        return $false
    }
    for ($i = 0; $i -le $Haystack.Length - $Needle.Length; ++$i) {
        $matches = $true
        for ($j = 0; $j -lt $Needle.Length; ++$j) {
            if ($Haystack[$i + $j] -ne $Needle[$j]) {
                $matches = $false
                break
            }
        }
        if ($matches) {
            return $true
        }
    }
    return $false
}

function Assert-PeX64Dll {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$ArtifactName
    )

    $stream = [System.IO.File]::OpenRead($Path)
    try {
        $reader = [System.IO.BinaryReader]::new($stream)
        try {
            if ($reader.ReadUInt16() -ne 0x5A4D) {
                throw "$ArtifactName does not have an MZ header: $Path"
            }
            $stream.Position = 0x3C
            $peOffset = $reader.ReadInt32()
            if ($peOffset -lt 0x40 -or $peOffset -gt $stream.Length - 24) {
                throw "$ArtifactName has an invalid PE header offset: $Path"
            }
            $stream.Position = $peOffset
            if ($reader.ReadUInt32() -ne 0x00004550) {
                throw "$ArtifactName does not have a PE signature: $Path"
            }
            if ($reader.ReadUInt16() -ne 0x8664) {
                throw "$ArtifactName is not PE x86-64: $Path"
            }
            [void]$reader.ReadUInt16()
            $coffTimestamp = $reader.ReadUInt32()
            if ($coffTimestamp -ne 0) {
                throw "$ArtifactName COFF timestamp is not deterministic (expected zero): $coffTimestamp"
            }
            $stream.Position = $peOffset + 22
            $characteristics = $reader.ReadUInt16()
            if (($characteristics -band 0x2000) -eq 0) {
                throw "$ArtifactName does not retain PE DLL identity: $Path"
            }
        }
        finally {
            $reader.Dispose()
        }
    }
    finally {
        $stream.Dispose()
    }
}

foreach ($path in @($PackagePath, $DllPath, $DebugPath, $ObjdumpPath)) {
    Assert-LeafFile -Path $path
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

Assert-PeX64Dll -Path $DllPath -ArtifactName "DLL"
Assert-PeX64Dll -Path $DebugPath -ArtifactName "GNU debug companion"

$dllBytes = [System.IO.File]::ReadAllBytes($DllPath)
$debugLinkBytes = [System.Text.Encoding]::ASCII.GetBytes($packageDebugName)
if (-not (Test-ByteSequence -Haystack $dllBytes -Needle $debugLinkBytes)) {
    throw "DLL does not reference the expected GNU debug companion '$packageDebugName'."
}
$dllAscii = [System.Text.Encoding]::ASCII.GetString($dllBytes)
$boostReferencePattern = '(?i)(boost::|boost[/\\]|_ZN5boost|@boost@@|libboost[_-])'
if ($dllAscii -match $boostReferencePattern) {
    throw "DLL contains a Boost symbol or path reference."
}
$debugAscii = [System.Text.Encoding]::ASCII.GetString(
    [System.IO.File]::ReadAllBytes($DebugPath))
if ($debugAscii -match $boostReferencePattern) {
    throw "GNU debug companion contains a Boost symbol or path reference."
}

$objdumpHeaders = Invoke-Objdump -Arguments @("-p", $DllPath)
$headerText = $objdumpHeaders -join "`n"
if ($headerText -notmatch '(?m)^\s*MajorSubsystemVersion\s+6\s*$' -or
    $headerText -notmatch '(?m)^\s*MinorSubsystemVersion\s+1\s*$') {
    throw "DLL subsystem version is not Windows 6.1."
}

$dllCharacteristicsMatch = [regex]::Match(
    $headerText, '(?m)^\s*DllCharacteristics\s+([0-9a-fA-F]+)\s*$')
if (-not $dllCharacteristicsMatch.Success) {
    throw "objdump did not report DLL characteristics."
}
$dllCharacteristics = [Convert]::ToUInt32(
    $dllCharacteristicsMatch.Groups[1].Value, 16)
foreach ($requiredFlag in @(0x20, 0x40, 0x100)) {
    if (($dllCharacteristics -band $requiredFlag) -eq 0) {
        throw ("DLL is missing required PE hardening flag 0x{0:X}." -f $requiredFlag)
    }
}

$imports = @(
    $objdumpHeaders |
        Select-String -Pattern 'DLL Name:\s*(\S+)' |
        ForEach-Object { $_.Matches[0].Groups[1].Value }
)
if ($imports | Where-Object { $_ -match '(?i)boost|libstdc\+\+|libgcc|libwinpthread' }) {
    throw "DLL has a forbidden external runtime/Boost import: $($imports -join ', ')"
}

$exports = @()
$insideExportNames = $false
foreach ($line in $objdumpHeaders) {
    if ($line -match '^\[Ordinal/Name Pointer\] Table') {
        $insideExportNames = $true
        continue
    }
    if ($insideExportNames -and $line -match '^The Function Table') {
        break
    }
    if ($insideExportNames -and $line -match '^\s*\[\s*\d+\]\s+(\S.*?)\s*$') {
        $exports += $matches[1]
    }
}
if ($exports.Count -ne 1 -or $exports[0] -cne "pluginInit") {
    throw "DLL exports must be exactly 'pluginInit'; got: $($exports -join ', ')"
}

$dllSections = (Invoke-Objdump -Arguments @("-h", $DllPath)) -join "`n"
if ($dllSections -notmatch '\.gnu_debuglink') {
    throw "DLL is missing a .gnu_debuglink section."
}
$debugSections = (Invoke-Objdump -Arguments @("-h", $DebugPath)) -join "`n"
if ($debugSections -notmatch '\.debug_info' -or
    $debugSections -notmatch '\.debug_line') {
    throw "GNU debug companion is missing DWARF info/line sections."
}

$versionInfo = (Get-Item -LiteralPath $DllPath).VersionInfo
if ($versionInfo.FileVersion -cne $ExpectedVersion -or
    $versionInfo.ProductVersion -cne $ExpectedVersion) {
    throw "DLL resource version '$($versionInfo.FileVersion)'/'$($versionInfo.ProductVersion)' does not match '$ExpectedVersion'."
}
$expectedDebugFlag = $Configuration -eq "Debug"
if ([bool]$versionInfo.IsDebug -ne $expectedDebugFlag) {
    throw "DLL resource debug flag '$($versionInfo.IsDebug)' does not match $Configuration."
}

$archive = [System.IO.Compression.ZipFile]::OpenRead(
    [System.IO.Path]::GetFullPath($PackagePath))
try {
    $actualNames = @($archive.Entries | ForEach-Object FullName)
    if ($actualNames.Count -ne (@($actualNames | Sort-Object -Unique)).Count) {
        throw "Package contains duplicate entry names."
    }
    foreach ($name in $actualNames) {
        if ($name -match '(^/|^[A-Za-z]:|(^|/)\.\.(/|$)|\\|[^\x00-\x7F])') {
            throw "Package contains an unsafe or non-ASCII entry name: $name"
        }
    }
    if (Compare-Object -CaseSensitive `
        -ReferenceObject $expectedEntries `
        -DifferenceObject @($actualNames | Sort-Object)) {
        throw "Package entry set does not match the release contract."
    }
    if ($actualNames.Count -ne $expectedEntries.Count) {
        throw "Package entry count does not match the release contract."
    }
    for ($i = 0; $i -lt $expectedEntries.Count; ++$i) {
        if ($actualNames[$i] -cne $expectedEntries[$i]) {
            throw "Package entries are not in deterministic ordinal order at index $i."
        }
    }
    foreach ($entry in $archive.Entries) {
        if ($entry.Length -le 0) {
            throw "Package contains an empty entry: $($entry.FullName)"
        }
        # ZIP stores DOS local time without a UTC offset. Compare the fixed
        # clock fields, not DateTimeOffset equality, which varies by host zone.
        if ($entry.LastWriteTime.Year -ne $fixedTimestamp.Year -or
            $entry.LastWriteTime.Month -ne $fixedTimestamp.Month -or
            $entry.LastWriteTime.Day -ne $fixedTimestamp.Day -or
            $entry.LastWriteTime.Hour -ne $fixedTimestamp.Hour -or
            $entry.LastWriteTime.Minute -ne $fixedTimestamp.Minute -or
            $entry.LastWriteTime.Second -ne $fixedTimestamp.Second) {
            throw "Package entry timestamp is not deterministic: $($entry.FullName)"
        }
    }

    $dllEntry = $archive.GetEntry($packageDllName)
    $debugEntry = $archive.GetEntry($packageDebugName)
    $diskDllHash = (Get-FileHash -LiteralPath $DllPath -Algorithm SHA256).Hash
    $diskDebugHash = (Get-FileHash -LiteralPath $DebugPath -Algorithm SHA256).Hash
    if ((Get-ZipEntrySha256 -Entry $dllEntry) -cne $diskDllHash) {
        throw "Packaged DLL does not match the audited build output."
    }
    if ((Get-ZipEntrySha256 -Entry $debugEntry) -cne $diskDebugHash) {
        throw "Packaged debug companion does not match the audited build output."
    }

    $manifestText = Get-ZipEntryText -Entry $archive.GetEntry("info.xml")
    [xml]$manifest = $manifestText
    $root = $manifest.DocumentElement
    if (-not $root -or $root.LocalName -cne "dcext" -or
        -not [string]::IsNullOrEmpty($root.NamespaceURI)) {
        throw "Package manifest root is invalid."
    }
    if ($root.UUID -notmatch '^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$') {
        throw "Package manifest UUID is invalid."
    }
    if ($root.UUID.Trim() -cne $ExpectedGuid) {
        throw "Package manifest UUID '$($root.UUID.Trim())' does not match '$ExpectedGuid'."
    }
    if ([string]$root.Version -cne $ExpectedVersion -or
        [int]$root.ApiVersion -ne $ExpectedApiVersion) {
        throw "Package manifest version/API does not match the build."
    }

    $pluginNodes = @($root.SelectNodes("Plugin"))
    if ($pluginNodes.Count -ne 1 -or
        $pluginNodes[0].GetAttribute("Platform") -cne "pe-x64" -or
        $pluginNodes[0].InnerText -cne $packageDllName) {
        throw "Package manifest must contain exactly the expected pe-x64 plugin."
    }

    $fileNodes = @($root.SelectNodes("Files/File"))
    $manifestFiles = @($fileNodes | ForEach-Object InnerText | Sort-Object)
    $expectedManifestFiles = @(
        $expectedEntries | Where-Object { $_ -notin @("info.xml", $packageDllName) }
    ) | Sort-Object
    if (Compare-Object -CaseSensitive `
        -ReferenceObject $expectedManifestFiles `
        -DifferenceObject $manifestFiles) {
        throw "Manifest <Files> entries do not match package contents."
    }
    foreach ($node in $fileNodes) {
        $platform = $node.GetAttribute("Platform")
        if ($node.InnerText -eq $packageDebugName) {
            if ($platform -cne "pe-x64") {
                throw "GNU debug companion must be marked pe-x64."
            }
        }
        elseif (-not [string]::IsNullOrEmpty($platform)) {
            throw "Platform-independent package file has an unexpected Platform attribute: $($node.InnerText)"
        }
    }

    $checksumText = Get-ZipEntryText -Entry $archive.GetEntry("SHA256SUMS")
    $checksumMap = @{}
    foreach ($line in @($checksumText -split "`r?`n" | Where-Object Length -gt 0)) {
        if ($line -notmatch '^([0-9a-f]{64})  ([A-Za-z0-9._-]+)$') {
            throw "Invalid SHA256SUMS line: $line"
        }
        if ($checksumMap.ContainsKey($matches[2])) {
            throw "Duplicate SHA256SUMS filename: $($matches[2])"
        }
        $checksumMap[$matches[2]] = $matches[1].ToUpperInvariant()
    }
    $checksummedEntries = @($expectedEntries | Where-Object { $_ -ne "SHA256SUMS" })
    if (Compare-Object -CaseSensitive `
        -ReferenceObject @($checksummedEntries | Sort-Object) `
        -DifferenceObject @($checksumMap.Keys | Sort-Object)) {
        throw "SHA256SUMS does not cover every non-checksum package entry exactly once."
    }
    foreach ($name in $checksummedEntries) {
        $actualHash = Get-ZipEntrySha256 -Entry $archive.GetEntry($name)
        if ($actualHash -cne $checksumMap[$name]) {
            throw "SHA256SUMS mismatch for '$name'."
        }
    }

    $provenance = Get-ZipEntryText -Entry $archive.GetEntry("BUILD-PROVENANCE.txt")
    foreach ($requiredLine in @(
        "Plugin-Version: $ExpectedVersion",
        "Configuration: $Configuration",
        "Target: x86_64-w64-mingw32")) {
        if ($provenance -notmatch "(?m)^$([regex]::Escape($requiredLine))`r?$") {
            throw "Build provenance is missing '$requiredLine'."
        }
    }
}
finally {
    $archive.Dispose()
}

if (-not [string]::IsNullOrWhiteSpace($SmokeTestPath)) {
    Assert-LeafFile -Path $SmokeTestPath
    $resolvedSmokeTest = (Resolve-Path -LiteralPath $SmokeTestPath).Path
    $resolvedDll = (Resolve-Path -LiteralPath $DllPath).Path
    if ([System.IO.Path]::GetExtension($resolvedSmokeTest) -ine ".exe") {
        throw "Smoke-test override must be a directly executable .exe file: $resolvedSmokeTest"
    }
    if ($resolvedDll.Contains('"')) {
        throw "DLL path contains an unsupported quote character: $resolvedDll"
    }

    $startInfo = [System.Diagnostics.ProcessStartInfo]::new()
    $startInfo.FileName = $resolvedSmokeTest
    $startInfo.Arguments = '"' + $resolvedDll + '"'
    $startInfo.WorkingDirectory = Split-Path -Parent $resolvedDll
    $startInfo.UseShellExecute = $false
    $startInfo.CreateNoWindow = $true
    $startInfo.RedirectStandardOutput = $true
    $startInfo.RedirectStandardError = $true

    $process = [System.Diagnostics.Process]::new()
    $process.StartInfo = $startInfo
    try {
        if (-not $process.Start()) {
            throw "Failed to start ABI/UI smoke test: $resolvedSmokeTest"
        }
        $standardOutputTask = $process.StandardOutput.ReadToEndAsync()
        $standardErrorTask = $process.StandardError.ReadToEndAsync()
        $completed = $process.WaitForExit($SmokeTimeoutSeconds * 1000)
        if (-not $completed) {
            $terminated = $false
            try {
                if (-not $process.HasExited) {
                    $process.Kill()
                }
            }
            finally {
                $terminated = $process.WaitForExit(5000)
            }
            if (-not $terminated) {
                throw "Plugin ABI/UI smoke test timed out and its termination could not be confirmed."
            }
        }
        else {
            $process.WaitForExit()
        }

        $standardOutput = $standardOutputTask.GetAwaiter().GetResult()
        $standardError = $standardErrorTask.GetAwaiter().GetResult()
        Write-CapturedProcessOutput `
            -StandardOutput $standardOutput `
            -StandardError $standardError

        if (-not $completed) {
            throw "Plugin ABI/UI smoke test exceeded the $SmokeTimeoutSeconds-second timeout and was terminated."
        }
        if ($process.ExitCode -ne 0) {
            throw "Plugin ABI/UI smoke test failed with exit code $($process.ExitCode)."
        }
    }
    finally {
        $process.Dispose()
    }
}

Write-Host "Release audit passed: $PackagePath" -ForegroundColor Green
