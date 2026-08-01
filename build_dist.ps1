[CmdletBinding()]
param(
    [ValidateSet("Debug", "Release", "All")]
    [string]$Configuration = "All",

    [string]$MinGWPrefix = "x86_64-w64-mingw32-",

    # Clean builds are the default. Use -Incremental only for local iteration.
    [switch]$Incremental,

    # Retained for command-line compatibility; clean is already the default.
    [switch]$Rebuild,

    [switch]$SourceArchive,

    [string]$SmokeTestPath,

    # Skip GCC -fanalyzer for faster local test builds. Compiler warnings,
    # tests, packaging checks, and the release audit still run.
    [switch]$SkipStaticAnalysis,

    # Preserve the historical no-argument Debug + Release behavior for
    # automation that cannot answer prompts.
    [switch]$NonInteractive
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

if ($Incremental -and $Rebuild) {
    throw "-Incremental and -Rebuild cannot be used together."
}

function Read-BuildConfiguration {
    Write-Host ""
    Write-Host "Protocol Analyzer build" -ForegroundColor Cyan
    Write-Host "  [1] Debug"
    Write-Host "  [2] Release"
    Write-Host "  [3] Debug + Release"

    while ($true) {
        $choice = Read-Host "Configuration [1]"
        switch ($choice.Trim().ToLowerInvariant()) {
            { $_ -in @("", "1", "d", "debug") } { return "Debug" }
            { $_ -in @("2", "r", "release") } { return "Release" }
            { $_ -in @("3", "a", "all") } { return "All" }
            default {
                Write-Host "Enter 1 for Debug, 2 for Release, or 3 for both." `
                    -ForegroundColor Yellow
            }
        }
    }
}

function Read-StaticAnalysisChoice {
    while ($true) {
        $choice = Read-Host "Run full GCC static analysis? [y/N]"
        switch ($choice.Trim().ToLowerInvariant()) {
            { $_ -in @("", "n", "no") } { return $false }
            { $_ -in @("y", "yes") } { return $true }
            default {
                Write-Host "Enter Y to run static analysis or N to skip it." `
                    -ForegroundColor Yellow
            }
        }
    }
}

$configurationWasSpecified = $PSBoundParameters.ContainsKey("Configuration")
if (-not $NonInteractive -and -not $configurationWasSpecified) {
    $Configuration = Read-BuildConfiguration
    if (-not $PSBoundParameters.ContainsKey("SkipStaticAnalysis")) {
        $SkipStaticAnalysis = -not (Read-StaticAnalysisChoice)
    }

    $analysisLabel = if ($SkipStaticAnalysis) { "skipped" } else { "enabled" }
    $buildModeLabel = if ($Incremental) { "incremental" } else { "clean" }
    Write-Host ""
    Write-Host ("Selected: {0}, {1}, static analysis {2}" -f
        $Configuration, $buildModeLabel, $analysisLabel) -ForegroundColor Cyan
}

$projectRoot = [System.IO.Path]::GetFullPath($PSScriptRoot)
$makeDir = Join-Path $projectRoot "projects\make"
$makefilePath = Join-Path $makeDir "Makefile"
$distDir = Join-Path $projectRoot "dist"
$stagingRoot = Join-Path $distDir ".staging"
$pluginBaseName = "ProtocolAnalyzer"
$packageDllName = "$pluginBaseName.dll"
$packageDebugName = "$pluginBaseName.dbg"
$manifestTemplate = Join-Path $projectRoot "packaging\info.xml"
$iconPath = Join-Path $projectRoot "packaging\$pluginBaseName.ico"
$thirdPartyPath = Join-Path $projectRoot "packaging\THIRD_PARTY.txt"
$auditScript = Join-Path $projectRoot "scripts\audit_release.ps1"
$peTimestampNormalizer = Join-Path $projectRoot "scripts\normalize_pe_timestamp.ps1"
$sourcePackager = Join-Path $projectRoot "packaging\package_source.ps1"
$smokeTestSource = Join-Path $projectRoot "tests\plugin_abi_smoke.cpp"
$protocolAnalyzerTestSource = Join-Path $projectRoot "tests\protocol_analyzer_tests.cpp"
$protocolAnalyzerSource = Join-Path $projectRoot "src\ProtocolAnalyzer.cpp"
$protocolAnalyzerHeader = Join-Path $projectRoot "src\ProtocolAnalyzer.h"
$fixedArchiveTimestamp = [System.DateTimeOffset]::new(
    1980, 1, 1, 0, 0, 0, [System.TimeSpan]::Zero)

function Convert-ToMakePath {
    param([Parameter(Mandatory = $true)][string]$Path)
    return $Path.Replace("\", "/")
}

function Invoke-NativeCommand {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$Description
    )

    Write-Host ""
    Write-Host "==> $Description" -ForegroundColor Cyan

    Push-Location $WorkingDirectory
    try {
        $savedPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            & $FilePath @Arguments 2>&1 | ForEach-Object { Write-Host $_ }
            $exitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $savedPreference
        }

        if ($exitCode -ne 0) {
            throw "$Description failed with exit code $exitCode."
        }
    }
    finally {
        Pop-Location
    }
}

function Invoke-NativeCapture {
    param(
        [Parameter(Mandatory = $true)][string]$FilePath,
        [Parameter(Mandatory = $true)][string[]]$Arguments,
        [Parameter(Mandatory = $true)][string]$WorkingDirectory,
        [Parameter(Mandatory = $true)][string]$Description
    )

    Push-Location $WorkingDirectory
    try {
        $savedPreference = $ErrorActionPreference
        $ErrorActionPreference = "Continue"
        try {
            $output = @(& $FilePath @Arguments 2>&1)
            $exitCode = $LASTEXITCODE
        }
        finally {
            $ErrorActionPreference = $savedPreference
        }

        if ($exitCode -ne 0) {
            $rendered = ($output | ForEach-Object ToString) -join [Environment]::NewLine
            throw "$Description failed with exit code $exitCode.$([Environment]::NewLine)$rendered"
        }

        return @($output | ForEach-Object ToString)
    }
    finally {
        Pop-Location
    }
}

function Get-ApplicationPath {
    param(
        [Parameter(Mandatory = $true)][string]$Name,
        [Parameter(Mandatory = $true)][string]$InstallHint
    )

    $command = Get-Command $Name -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $command) {
        throw "Required command '$Name' was not found. $InstallHint"
    }
    return [System.IO.Path]::GetFullPath($command.Source)
}

function Resolve-CompilerTool {
    param(
        [Parameter(Mandatory = $true)][string]$CompilerPath,
        [Parameter(Mandatory = $true)][string]$ToolName
    )

    $reported = (Invoke-NativeCapture `
        -FilePath $CompilerPath `
        -Arguments @("-print-prog-name=$ToolName") `
        -WorkingDirectory $projectRoot `
        -Description "Resolve $ToolName from the selected compiler" |
        Select-Object -Last 1).Trim()

    if ([string]::IsNullOrWhiteSpace($reported)) {
        throw "The selected compiler did not report a path for '$ToolName'."
    }

    if ([System.IO.Path]::IsPathRooted($reported) -or
        $reported.Contains("\") -or $reported.Contains("/")) {
        $candidate = [System.IO.Path]::GetFullPath($reported)
        if (-not (Test-Path -LiteralPath $candidate -PathType Leaf)) {
            throw "Compiler-reported tool '$ToolName' does not exist: $candidate"
        }
        return (Resolve-Path -LiteralPath $candidate).Path
    }

    return Get-ApplicationPath `
        -Name $reported `
        -InstallHint "Install the binutils distributed with the selected x64 MinGW-w64 compiler."
}

function Get-StringDefine {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $text = Get-Content -LiteralPath $Path -Raw
    $match = [regex]::Match(
        $text,
        "(?m)^\s*#\s*define\s+$([regex]::Escape($Name))\s+`"([^`"]+)`"\s*$")
    if (-not $match.Success) {
        throw "String define '$Name' was not found in '$Path'."
    }
    return $match.Groups[1].Value
}

function Get-IntegerDefine {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Name
    )

    $text = Get-Content -LiteralPath $Path -Raw
    $match = [regex]::Match(
        $text,
        "(?m)^\s*#\s*define\s+$([regex]::Escape($Name))\s+([0-9]+)\s*$")
    if (-not $match.Success) {
        throw "Integer define '$Name' was not found in '$Path'."
    }
    return [int]$match.Groups[1].Value
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

function Move-FileAtomically {
    param(
        [Parameter(Mandatory = $true)][string]$TemporaryPath,
        [Parameter(Mandatory = $true)][string]$DestinationPath
    )

    if (Test-Path -LiteralPath $DestinationPath) {
        $destination = Get-Item -LiteralPath $DestinationPath -Force
        if (-not $destination.PSIsContainer -and
            ($destination.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -eq 0) {
            $backupPath = Join-Path (Split-Path -Parent $DestinationPath) (
                ".{0}.{1}.replace-backup.tmp" -f
                    (Split-Path -Leaf $DestinationPath),
                    [guid]::NewGuid().ToString("N"))
            try {
                [System.IO.File]::Replace(
                    $TemporaryPath, $DestinationPath, $backupPath, $true)
                return
            }
            finally {
                if (Test-Path -LiteralPath $backupPath) {
                    Remove-Item -LiteralPath $backupPath -Force -ErrorAction SilentlyContinue
                }
            }
        }
        throw "Atomic destination must be a regular file: $DestinationPath"
    }
    else {
        [System.IO.File]::Move($TemporaryPath, $DestinationPath)
    }
}

function Assert-RealDirectoryPath {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    $rootFull = [System.IO.Path]::GetFullPath($Root).TrimEnd("\", "/")
    $pathFull = [System.IO.Path]::GetFullPath($Path).TrimEnd("\", "/")
    $prefix = $rootFull + [System.IO.Path]::DirectorySeparatorChar
    if ($pathFull -cne $rootFull -and -not $pathFull.StartsWith(
        $prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Directory '$pathFull' is outside the required root '$rootFull'."
    }

    $rootItem = Get-Item -LiteralPath $rootFull -Force
    if (-not $rootItem.PSIsContainer -or
        ($rootItem.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        throw "Directory root must be a real directory, not a reparse point: $rootFull"
    }

    $relative = $pathFull.Substring($rootFull.Length).TrimStart("\", "/")
    $current = $rootFull
    foreach ($part in @($relative -split '[\\/]' | Where-Object Length -gt 0)) {
        $current = Join-Path $current $part
        if (-not (Test-Path -LiteralPath $current)) {
            break
        }
        $item = Get-Item -LiteralPath $current -Force
        if (-not $item.PSIsContainer -or
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Release directory path contains a file or reparse point: $($item.FullName)"
        }
    }
}

function Initialize-RealDirectory {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    Assert-RealDirectoryPath -Root $Root -Path $Path
    if (-not (Test-Path -LiteralPath $Path)) {
        [void](New-Item -ItemType Directory -Path $Path)
    }
    Assert-RealDirectoryPath -Root $Root -Path $Path
}

function Assert-RegularOutputFile {
    param(
        [Parameter(Mandatory = $true)][string]$Root,
        [Parameter(Mandatory = $true)][string]$Path
    )

    Assert-ChildPath -Parent $Root -Child $Path
    if (Test-Path -LiteralPath $Path) {
        $item = Get-Item -LiteralPath $Path -Force
        if ($item.PSIsContainer -or
            ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
            throw "Release output must be a regular file: $Path"
        }
    }
}

function Write-AtomicText {
    param(
        [Parameter(Mandatory = $true)][string]$Path,
        [Parameter(Mandatory = $true)][string]$Text
    )

    $directory = Split-Path -Parent $Path
    if (-not (Test-Path -LiteralPath $directory -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $directory -Force)
    }

    $temporaryPath = Join-Path $directory (
        ".{0}.{1}.tmp" -f (Split-Path -Leaf $Path), [guid]::NewGuid().ToString("N"))
    try {
        [System.IO.File]::WriteAllText(
            $temporaryPath,
            $Text,
            [System.Text.UTF8Encoding]::new($false))
        Move-FileAtomically -TemporaryPath $temporaryPath -DestinationPath $Path
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Remove-DirectoryWithRetry {
    param([Parameter(Mandatory = $true)][string]$Path)

    if (-not (Test-Path -LiteralPath $Path)) {
        return
    }
    Assert-ChildPath -Parent $stagingRoot -Child $Path
    $directory = Get-Item -LiteralPath $Path -Force
    if (-not $directory.PSIsContainer -or
        ($directory.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
        Write-Warning "Refusing to remove a non-directory or reparse-point staging path: $Path"
        return
    }

    $delays = @(0, 100, 250, 500, 1000)
    foreach ($delay in $delays) {
        if ($delay -gt 0) {
            Start-Sleep -Milliseconds $delay
        }
        try {
            Remove-Item -LiteralPath $Path -Recurse -Force -ErrorAction Stop
            return
        }
        catch {
            if ($delay -eq $delays[-1]) {
                Write-Warning "Could not remove temporary staging directory '$Path': $($_.Exception.Message)"
            }
        }
    }
}

function Assert-ChildPath {
    param(
        [Parameter(Mandatory = $true)][string]$Parent,
        [Parameter(Mandatory = $true)][string]$Child
    )

    $parentFull = [System.IO.Path]::GetFullPath($Parent).TrimEnd("\", "/") +
        [System.IO.Path]::DirectorySeparatorChar
    $childFull = [System.IO.Path]::GetFullPath($Child)
    if (-not $childFull.StartsWith(
        $parentFull, [System.StringComparison]::OrdinalIgnoreCase)) {
        throw "Path '$childFull' is outside the required parent '$parentFull'."
    }
}

function Write-PackageManifest {
    param(
        [Parameter(Mandatory = $true)][string]$Destination,
        [Parameter(Mandatory = $true)][string]$ExpectedGuid,
        [Parameter(Mandatory = $true)][string]$ExpectedVersion,
        [Parameter(Mandatory = $true)][int]$ExpectedApiVersion,
        [Parameter(Mandatory = $true)][string[]]$AdditionalFiles
    )

    [xml]$manifest = Get-Content -LiteralPath $manifestTemplate -Raw
    $root = $manifest.DocumentElement
    if (-not $root -or $root.LocalName -ne "dcext" -or
        -not [string]::IsNullOrEmpty($root.NamespaceURI)) {
        throw "Manifest template must contain an unnamespaced dcext root element."
    }

    $requiredText = @{
        UUID = $ExpectedGuid
        Name = $null
        Version = $ExpectedVersion
        ApiVersion = [string]$ExpectedApiVersion
    }
    foreach ($name in $requiredText.Keys) {
        $node = $root.SelectSingleNode($name)
        if (-not $node -or [string]::IsNullOrWhiteSpace($node.InnerText)) {
            throw "Manifest template is missing a non-empty <$name> value."
        }
        if ($null -ne $requiredText[$name] -and
            $node.InnerText.Trim() -cne $requiredText[$name]) {
            throw "Manifest <$name> '$($node.InnerText)' does not match '$($requiredText[$name])'."
        }
    }
    if ($root.UUID -notmatch '^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$') {
        throw "Manifest UUID is not in canonical braced UUID form."
    }

    foreach ($plugin in @($root.SelectNodes("Plugin"))) {
        [void]$root.RemoveChild($plugin)
    }

    $files = $root.SelectSingleNode("Files")
    if (-not $files) {
        $files = $manifest.CreateElement("Files")
        [void]$root.AppendChild($files)
    }
    foreach ($file in @($files.SelectNodes("File"))) {
        [void]$files.RemoveChild($file)
    }

    $pluginNode = $manifest.CreateElement("Plugin")
    $pluginNode.SetAttribute("Platform", "pe-x64")
    $pluginNode.InnerText = $packageDllName
    [void]$root.InsertBefore($pluginNode, $files)

    foreach ($fileName in $AdditionalFiles) {
        $fileNode = $manifest.CreateElement("File")
        if ($fileName -eq $packageDebugName) {
            $fileNode.SetAttribute("Platform", "pe-x64")
        }
        $fileNode.InnerText = $fileName
        [void]$files.AppendChild($fileNode)
    }

    $temporaryPath = "$Destination.$([guid]::NewGuid().ToString('N')).tmp"
    $settings = [System.Xml.XmlWriterSettings]::new()
    $settings.Encoding = [System.Text.UTF8Encoding]::new($false)
    $settings.Indent = $true
    $settings.NewLineChars = "`r`n"
    $settings.NewLineHandling = [System.Xml.NewLineHandling]::Replace

    try {
        $writer = [System.Xml.XmlWriter]::Create($temporaryPath, $settings)
        try {
            $manifest.Save($writer)
        }
        finally {
            $writer.Dispose()
        }

        if ((Get-Item -LiteralPath $temporaryPath).Length -eq 0) {
            throw "Generated manifest is empty: $temporaryPath"
        }
        [void]([xml](Get-Content -LiteralPath $temporaryPath -Raw))
        Move-FileAtomically -TemporaryPath $temporaryPath -DestinationPath $Destination
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }
}

function Write-InternalChecksums {
    param([Parameter(Mandatory = $true)][string]$StageDirectory)

    $lines = Get-ChildItem -LiteralPath $StageDirectory -File |
        Where-Object Name -ne "SHA256SUMS" |
        Sort-Object Name |
        ForEach-Object {
            $hash = (Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256).Hash.ToLowerInvariant()
            "$hash  $($_.Name)"
        }
    $text = (($lines -join "`n") + "`n")
    [System.IO.File]::WriteAllText(
        (Join-Path $StageDirectory "SHA256SUMS"),
        $text,
        [System.Text.UTF8Encoding]::new($false))
}

function New-DeterministicZip {
    param(
        [Parameter(Mandatory = $true)][string]$SourceDirectory,
        [Parameter(Mandatory = $true)][string]$Destination
    )

    $archive = [System.IO.Compression.ZipFile]::Open(
        $Destination, [System.IO.Compression.ZipArchiveMode]::Create)
    try {
        foreach ($file in Get-ChildItem -LiteralPath $SourceDirectory -File | Sort-Object Name) {
            $entry = $archive.CreateEntry(
                $file.Name, [System.IO.Compression.CompressionLevel]::Optimal)
            $entry.LastWriteTime = $fixedArchiveTimestamp
            $entry.ExternalAttributes = 0
            $input = [System.IO.File]::OpenRead($file.FullName)
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
        $archive.Dispose()
    }
}

function Get-BuildContext {
    param(
        [Parameter(Mandatory = $true)][string]$BuildConfiguration,
        [Parameter(Mandatory = $true)][hashtable]$Tools,
        [Parameter(Mandatory = $true)][string]$CompilerTarget,
        [Parameter(Mandatory = $true)][string]$CompilerVersion
    )

    $toolHashes = [ordered]@{}
    foreach ($name in @("gcc", "gxx", "windres", "objcopy", "objdump")) {
        $toolHashes[$name] = (Get-FileHash -LiteralPath $Tools[$name] -Algorithm SHA256).Hash
    }

    $data = [ordered]@{
        format = 2
        configuration = $BuildConfiguration
        target = $CompilerTarget
        compilerVersion = $CompilerVersion
        makefileSha256 = (Get-FileHash -LiteralPath $makefilePath -Algorithm SHA256).Hash
        buildScriptSha256 = (Get-FileHash -LiteralPath $PSCommandPath -Algorithm SHA256).Hash
        peTimestampNormalizerSha256 = (
            Get-FileHash -LiteralPath $peTimestampNormalizer -Algorithm SHA256).Hash
        tools = $toolHashes
    }
    $canonical = $data | ConvertTo-Json -Depth 5 -Compress
    return [pscustomobject]@{
        Data = $data
        Canonical = $canonical
        Signature = Get-Sha256Text -Text $canonical
    }
}

function Get-BuildDirectory {
    param([Parameter(Mandatory = $true)][string]$BuildConfiguration)
    if ($BuildConfiguration -eq "Debug") {
        return Join-Path $makeDir "build-mingw-x64-debug"
    }
    return Join-Path $makeDir "build-mingw-x64"
}

function Build-SmokeTest {
    param(
        [Parameter(Mandatory = $true)][string]$BuildConfiguration,
        [Parameter(Mandatory = $true)][hashtable]$Tools,
        [Parameter(Mandatory = $true)][string]$OutputDirectory
    )

    if (-not [string]::IsNullOrWhiteSpace($SmokeTestPath)) {
        $resolvedOverride = Resolve-Path -LiteralPath $SmokeTestPath -ErrorAction Stop
        if (-not (Test-Path -LiteralPath $resolvedOverride.Path -PathType Leaf)) {
            throw "Smoke-test override is not a file: $($resolvedOverride.Path)"
        }
        return $resolvedOverride.Path
    }

    if (-not (Test-Path -LiteralPath $smokeTestSource -PathType Leaf)) {
        throw "Required ABI/UI smoke-test source was not found: $smokeTestSource"
    }
    if (-not (Test-Path -LiteralPath $OutputDirectory -PathType Container)) {
        [void](New-Item -ItemType Directory -Path $OutputDirectory -Force)
    }

    $outputPath = Join-Path $OutputDirectory "plugin_abi_smoke.exe"
    $temporaryPath = Join-Path $OutputDirectory (
        ".plugin_abi_smoke.$([guid]::NewGuid().ToString('N')).tmp.exe")
    $compilerRoot = Convert-ToMakePath -Path $projectRoot
    $compilerSource = Convert-ToMakePath -Path $smokeTestSource
    $compilerOutput = Convert-ToMakePath -Path $temporaryPath
    $configurationFlags = if ($BuildConfiguration -eq "Debug") {
        @("-D_DEBUG", "-O0", "-g3", "-fno-omit-frame-pointer")
    }
    else {
        @("-DNDEBUG", "-O2", "-g")
    }
    $arguments = @(
        "-std=gnu++17",
        "-Wall",
        "-Wextra",
        "-Wpedantic",
        "-Werror",
        "-Wformat=2",
        "-Wformat-security",
        "-Wconversion",
        "-Wsign-conversion",
        "-D_WIN32_WINNT=0x0601",
        "-DWINVER=0x0601",
        "-D_WIN32_IE=0x0A00",
        "-DNOMINMAX",
        "-DSTRICT",
        "-DWIN32_LEAN_AND_MEAN",
        "-DUNICODE",
        "-D_UNICODE",
        "-I$compilerRoot",
        "-fstack-protector-strong",
        "-ffile-prefix-map=$compilerRoot=.",
        "-fdebug-prefix-map=$compilerRoot=.",
        "-fmacro-prefix-map=$compilerRoot=.",
        "-frandom-seed=plugin-abi-smoke-$($BuildConfiguration.ToLowerInvariant())",
        "-static-libgcc",
        "-static-libstdc++",
        "-Wl,--dynamicbase",
        "-Wl,--nxcompat",
        "-Wl,--high-entropy-va",
        "-Wl,--major-subsystem-version,6,--minor-subsystem-version,1",
        "-Wl,--no-insert-timestamp"
    ) + $configurationFlags + @(
        $compilerSource,
        "-o",
        $compilerOutput,
        "-lcomctl32"
    )

    try {
        Invoke-NativeCommand `
            -FilePath $Tools.gxx `
            -Arguments $arguments `
            -WorkingDirectory $projectRoot `
            -Description "Compile strict MinGW-w64 $BuildConfiguration ABI/UI smoke test"
        Move-FileAtomically `
            -TemporaryPath $temporaryPath `
            -DestinationPath $outputPath
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPath) {
            Remove-Item -LiteralPath $temporaryPath -Force -ErrorAction SilentlyContinue
        }
    }

    return $outputPath
}

function Invoke-MinGWBuild {
    param(
        [Parameter(Mandatory = $true)][string]$BuildConfiguration,
        [Parameter(Mandatory = $true)][string]$MakePath,
        [Parameter(Mandatory = $true)][hashtable]$Tools,
        [Parameter(Mandatory = $true)][pscustomobject]$Context,
        [switch]$SkipAnalysis
    )

    $outputDirectory = Get-BuildDirectory -BuildConfiguration $BuildConfiguration
    $contextPath = Join-Path $outputDirectory ".build-context.json"
    $mustClean = -not $Incremental
    Assert-RealDirectoryPath -Root $projectRoot -Path $makeDir
    Assert-RealDirectoryPath -Root $projectRoot -Path $outputDirectory

    if ($Incremental) {
        if (-not (Test-Path -LiteralPath $contextPath -PathType Leaf)) {
            $mustClean = $true
        }
        else {
            try {
                $previous = Get-Content -LiteralPath $contextPath -Raw | ConvertFrom-Json
                if ($previous.signature -cne $Context.Signature) {
                    $mustClean = $true
                }
            }
            catch {
                $mustClean = $true
            }
        }
    }

    $makeArgs = @(
        "CONFIG=$BuildConfiguration",
        "CC=$(Convert-ToMakePath $Tools.gcc)",
        "CXX=$(Convert-ToMakePath $Tools.gxx)",
        "WINDRES=$(Convert-ToMakePath $Tools.windres)",
        "OBJCOPY=$(Convert-ToMakePath $Tools.objcopy)"
    )

    if ($mustClean) {
        Invoke-NativeCommand `
            -FilePath $MakePath `
            -Arguments ($makeArgs + @("clean")) `
            -WorkingDirectory $makeDir `
            -Description "Clean MinGW-w64 $BuildConfiguration x64"
    }

    if ($SkipAnalysis) {
        Write-Host ""
        Write-Host "==> Skip MinGW-w64 $BuildConfiguration static analysis" `
            -ForegroundColor Yellow
        Write-Host "Fast local-build mode: GCC -fanalyzer was not run." `
            -ForegroundColor Yellow
    }
    else {
        Invoke-NativeCommand `
            -FilePath $MakePath `
            -Arguments ($makeArgs + @("source-audit")) `
            -WorkingDirectory $makeDir `
            -Description "Analyze MinGW-w64 $BuildConfiguration sources"
    }

    Invoke-NativeCommand `
        -FilePath $MakePath `
        -Arguments ($makeArgs + @("protocol-analyzer-test")) `
        -WorkingDirectory $makeDir `
        -Description "Run bounded ADC/NMDC protocol analyzer tests ($BuildConfiguration)"

    Invoke-NativeCommand `
        -FilePath $MakePath `
        -Arguments ($makeArgs + @("all")) `
        -WorkingDirectory $makeDir `
        -Description "Build MinGW-w64 $BuildConfiguration x64"

    Assert-RealDirectoryPath -Root $projectRoot -Path $outputDirectory
    $compiledSmokeTest = Build-SmokeTest `
        -BuildConfiguration $BuildConfiguration `
        -Tools $Tools `
        -OutputDirectory $outputDirectory

    $contextRecord = [ordered]@{
        signature = $Context.Signature
        context = $Context.Data
    } | ConvertTo-Json -Depth 6
    Write-AtomicText -Path $contextPath -Text ($contextRecord + "`n")

    return [pscustomobject]@{
        OutputDirectory = $outputDirectory
        DllPath = Join-Path $outputDirectory "$pluginBaseName.dll"
        DebugPath = Join-Path $outputDirectory "$pluginBaseName.dbg"
        SmokeTestPath = $compiledSmokeTest
        ContextSignature = $Context.Signature
        WasClean = $mustClean
        StaticAnalysis = -not $SkipAnalysis
    }
}

function New-DcextPackage {
    param(
        [Parameter(Mandatory = $true)][string]$BuildConfiguration,
        [Parameter(Mandatory = $true)][pscustomobject]$BuildResult,
        [Parameter(Mandatory = $true)][hashtable]$Tools,
        [Parameter(Mandatory = $true)][string]$CompilerTarget,
        [Parameter(Mandatory = $true)][string]$CompilerVersion,
        [Parameter(Mandatory = $true)][string]$PluginGuid,
        [Parameter(Mandatory = $true)][string]$PluginVersion,
        [Parameter(Mandatory = $true)][int]$ApiVersion,
        [Parameter(Mandatory = $true)][string]$LibDwtVersion
    )

    $requiredInputs = @(
        $BuildResult.DllPath,
        $BuildResult.DebugPath,
        $BuildResult.SmokeTestPath,
        $manifestTemplate,
        $iconPath,
        $thirdPartyPath,
        (Join-Path $projectRoot "LICENSE"),
        (Join-Path $projectRoot "gpl-2.0.txt"),
        (Join-Path $projectRoot "dwt\License.txt"),
        $auditScript
    )
    foreach ($path in $requiredInputs) {
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Required package input was not found: $path"
        }
    }

    $slug = "mingw-w64-x64-$($BuildConfiguration.ToLowerInvariant())"
    $packageName = "$pluginBaseName-$slug.dcext"
    $packagePath = Join-Path $distDir $packageName
    $checksumPath = "$packagePath.sha256"
    $stageName = "$slug-$PID-$([guid]::NewGuid().ToString('N'))"
    $stageDirectory = Join-Path $stagingRoot $stageName
    $temporaryPackage = Join-Path $distDir ".$packageName.$([guid]::NewGuid().ToString('N')).tmp"
    Assert-ChildPath -Parent $stagingRoot -Child $stageDirectory
    Assert-RegularOutputFile -Root $distDir -Path $packagePath
    Assert-RegularOutputFile -Root $distDir -Path $checksumPath
    [void](New-Item -ItemType Directory -Path $stageDirectory)
    Assert-RealDirectoryPath -Root $projectRoot -Path $stageDirectory

    try {
        Copy-Item -LiteralPath $BuildResult.DllPath -Destination (
            Join-Path $stageDirectory $packageDllName)
        Copy-Item -LiteralPath $BuildResult.DebugPath -Destination (
            Join-Path $stageDirectory $packageDebugName)
        Copy-Item -LiteralPath $iconPath -Destination (
            Join-Path $stageDirectory "$pluginBaseName.ico")
        Copy-Item -LiteralPath (Join-Path $projectRoot "LICENSE") -Destination (
            Join-Path $stageDirectory "LICENSE.txt")
        Copy-Item -LiteralPath (Join-Path $projectRoot "gpl-2.0.txt") -Destination (
            Join-Path $stageDirectory "GPL-2.0.txt")
        Copy-Item -LiteralPath (Join-Path $projectRoot "dwt\License.txt") -Destination (
            Join-Path $stageDirectory "LibDWT-License.txt")
        Copy-Item -LiteralPath $thirdPartyPath -Destination (
            Join-Path $stageDirectory "THIRD-PARTY.txt")

        $provenanceLines = @(
            "Format-Version: 1",
            "Plugin: $pluginBaseName",
            "Plugin-Version: $PluginVersion",
            "Configuration: $BuildConfiguration",
            "Target: $CompilerTarget",
            "Compiler: $CompilerVersion",
            "Compiler-SHA256: $((Get-FileHash -LiteralPath $Tools.gxx -Algorithm SHA256).Hash)",
            "Makefile-SHA256: $((Get-FileHash -LiteralPath $makefilePath -Algorithm SHA256).Hash)",
            "Build-Context-SHA256: $($BuildResult.ContextSignature)",
            "Protocol-Analyzer-Source-SHA256: $((Get-FileHash -LiteralPath $protocolAnalyzerSource -Algorithm SHA256).Hash)",
            "Protocol-Analyzer-Header-SHA256: $((Get-FileHash -LiteralPath $protocolAnalyzerHeader -Algorithm SHA256).Hash)",
            "Protocol-Analyzer-Test-SHA256: $((Get-FileHash -LiteralPath $protocolAnalyzerTestSource -Algorithm SHA256).Hash)",
            "ABI-Smoke-Test-SHA256: $((Get-FileHash -LiteralPath $smokeTestSource -Algorithm SHA256).Hash)",
            "Static-Analysis: $(if ($BuildResult.StaticAnalysis) { 'Passed' } else { 'Skipped' })",
            "LibDWT-Version: $LibDwtVersion",
            "LibDWT-Source: https://github.com/iceman50/LibDWT.git",
            "LibDWT-Commit: 5f8b9957ca35323b8dd89dd4cf7eb0db7c058882"
        )
        [System.IO.File]::WriteAllText(
            (Join-Path $stageDirectory "BUILD-PROVENANCE.txt"),
            (($provenanceLines -join "`n") + "`n"),
            [System.Text.UTF8Encoding]::new($false))

        $additionalFiles = @(
            $packageDebugName,
            "$pluginBaseName.ico",
            "LICENSE.txt",
            "GPL-2.0.txt",
            "LibDWT-License.txt",
            "THIRD-PARTY.txt",
            "BUILD-PROVENANCE.txt",
            "SHA256SUMS"
        )
        Write-PackageManifest `
            -Destination (Join-Path $stageDirectory "info.xml") `
            -ExpectedGuid $PluginGuid `
            -ExpectedVersion $PluginVersion `
            -ExpectedApiVersion $ApiVersion `
            -AdditionalFiles $additionalFiles
        Write-InternalChecksums -StageDirectory $stageDirectory
        New-DeterministicZip `
            -SourceDirectory $stageDirectory `
            -Destination $temporaryPackage

        $auditArguments = @{
            PackagePath = $temporaryPackage
            DllPath = $BuildResult.DllPath
            DebugPath = $BuildResult.DebugPath
            Configuration = $BuildConfiguration
            ObjdumpPath = $Tools.objdump
            ExpectedVersion = $PluginVersion
            ExpectedGuid = $PluginGuid
            ExpectedApiVersion = $ApiVersion
        }
        $auditArguments.SmokeTestPath = $BuildResult.SmokeTestPath
        & $auditScript @auditArguments

        Move-FileAtomically -TemporaryPath $temporaryPackage -DestinationPath $packagePath
        $packageHash = (Get-FileHash -LiteralPath $packagePath -Algorithm SHA256).Hash.ToLowerInvariant()
        Write-AtomicText `
            -Path $checksumPath `
            -Text "$packageHash  $packageName`n"

        Write-Host "Created and audited $packagePath" -ForegroundColor Green
        return [pscustomobject]@{
            PackagePath = $packagePath
            ChecksumPath = $checksumPath
            Sha256 = $packageHash.ToUpperInvariant()
        }
    }
    finally {
        if (Test-Path -LiteralPath $temporaryPackage) {
            Remove-Item -LiteralPath $temporaryPackage -Force -ErrorAction SilentlyContinue
        }
        Remove-DirectoryWithRetry -Path $stageDirectory
    }
}

foreach ($requiredPath in @(
    $makefilePath, $manifestTemplate, $iconPath, $thirdPartyPath, $auditScript,
    $smokeTestSource, $protocolAnalyzerTestSource, $protocolAnalyzerSource,
    $protocolAnalyzerHeader, $peTimestampNormalizer)) {
    if (-not (Test-Path -LiteralPath $requiredPath -PathType Leaf)) {
        throw "Required release input was not found: $requiredPath"
    }
}

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem
Assert-RealDirectoryPath -Root $projectRoot -Path $projectRoot

$mutexSeed = Get-Sha256Text -Text $projectRoot.ToUpperInvariant()
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
        throw "Another Protocol Analyzer build/package process is already using this workspace."
    }

    Initialize-RealDirectory -Root $projectRoot -Path $distDir
    Initialize-RealDirectory -Root $projectRoot -Path $stagingRoot

    $makeCommand = Get-Command mingw32-make -CommandType Application -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $makeCommand) {
        $makeCommand = Get-Command make -CommandType Application -ErrorAction SilentlyContinue |
            Select-Object -First 1
    }
    if (-not $makeCommand) {
        throw "Neither mingw32-make nor make was found. Install an x64 MinGW-w64 toolchain."
    }
    $makePath = [System.IO.Path]::GetFullPath($makeCommand.Source)

    $gccPath = Get-ApplicationPath `
        -Name "$($MinGWPrefix)gcc" `
        -InstallHint "Install an x64 MinGW-w64 compiler or pass -MinGWPrefix."
    $gxxPath = Get-ApplicationPath `
        -Name "$($MinGWPrefix)g++" `
        -InstallHint "Install an x64 MinGW-w64 compiler or pass -MinGWPrefix."
    $tools = @{
        gcc = $gccPath
        gxx = $gxxPath
        windres = Resolve-CompilerTool -CompilerPath $gccPath -ToolName "windres"
        objcopy = Resolve-CompilerTool -CompilerPath $gccPath -ToolName "objcopy"
        objdump = Resolve-CompilerTool -CompilerPath $gccPath -ToolName "objdump"
    }

    $gccTarget = (Invoke-NativeCapture `
        -FilePath $gccPath -Arguments @("-dumpmachine") `
        -WorkingDirectory $projectRoot -Description "Read GCC target" |
        Select-Object -Last 1).Trim()
    $gxxTarget = (Invoke-NativeCapture `
        -FilePath $gxxPath -Arguments @("-dumpmachine") `
        -WorkingDirectory $projectRoot -Description "Read G++ target" |
        Select-Object -Last 1).Trim()
    if ($gccTarget -cne $gxxTarget -or
        $gccTarget -notmatch '^x86_64(?:-[^-]+)*-mingw32$') {
        throw "Only one matching x86_64 MinGW-w64 GCC/G++ toolchain is supported; got '$gccTarget' and '$gxxTarget'."
    }

    $compilerVersion = (Invoke-NativeCapture `
        -FilePath $gxxPath -Arguments @("--version") `
        -WorkingDirectory $projectRoot -Description "Read compiler version" |
        Select-Object -First 1).Trim()
    $pluginVersion = Get-StringDefine `
        -Path (Join-Path $projectRoot "src\version.h") `
        -Name "PLUGIN_VERSION_STR"
    $pluginGuid = Get-StringDefine `
        -Path (Join-Path $projectRoot "src\version.h") `
        -Name "PLUGIN_GUID"
    if ($pluginGuid -notmatch '^\{[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}$') {
        throw "PLUGIN_GUID is not in canonical braced UUID form."
    }
    $apiVersion = Get-IntegerDefine `
        -Path (Join-Path $projectRoot "pluginsdk\PluginDefs.h") `
        -Name "DCAPI_CORE_VER"
    $libDwtVersion = Get-StringDefine `
        -Path (Join-Path $projectRoot "dwt\include\dwt\Version.h") `
        -Name "DWT_VERSION_STRING"

    $selectedConfigurations = if ($Configuration -eq "All") {
        @("Debug", "Release")
    }
    else {
        @($Configuration)
    }

    $packages = @()
    foreach ($selectedConfiguration in $selectedConfigurations) {
        $context = Get-BuildContext `
            -BuildConfiguration $selectedConfiguration `
            -Tools $tools `
            -CompilerTarget $gccTarget `
            -CompilerVersion $compilerVersion
        $buildResult = Invoke-MinGWBuild `
            -BuildConfiguration $selectedConfiguration `
            -MakePath $makePath `
            -Tools $tools `
            -Context $context `
            -SkipAnalysis:$SkipStaticAnalysis
        $packages += New-DcextPackage `
            -BuildConfiguration $selectedConfiguration `
            -BuildResult $buildResult `
            -Tools $tools `
            -CompilerTarget $gccTarget `
            -CompilerVersion $compilerVersion `
            -PluginGuid $pluginGuid `
            -PluginVersion $pluginVersion `
            -ApiVersion $apiVersion `
            -LibDwtVersion $libDwtVersion
    }

    $sourceResult = $null
    if ($SourceArchive) {
        if (-not (Test-Path -LiteralPath $sourcePackager -PathType Leaf)) {
            throw "Source packager was not found: $sourcePackager"
        }
        $sourceOutput = Join-Path $distDir "$pluginBaseName-$pluginVersion-source.zip"
        $sourceResult = & $sourcePackager `
            -RepoRoot $projectRoot `
            -OutputZip $sourceOutput
    }

    if ((Test-Path -LiteralPath $stagingRoot) -and
        -not (Get-ChildItem -LiteralPath $stagingRoot -Force | Select-Object -First 1)) {
        Remove-Item -LiteralPath $stagingRoot -Force -ErrorAction SilentlyContinue
    }

    Write-Host ""
    Write-Host "Audited distribution outputs:" -ForegroundColor Cyan
    foreach ($package in $packages) {
        $item = Get-Item -LiteralPath $package.PackagePath
        Write-Host ("  {0} ({1:N0} bytes, SHA-256 {2})" -f
            $item.FullName, $item.Length, $package.Sha256)
    }
    if ($null -ne $sourceResult) {
        Write-Host ("  {0}" -f $sourceResult)
    }
}
finally {
    if ($mutexAcquired) {
        [void]$mutex.ReleaseMutex()
    }
    $mutex.Dispose()
}
