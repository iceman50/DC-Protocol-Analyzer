[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string]$OutputZip
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Write-Warning "clean_and_zip_source.ps1 is deprecated; it no longer deletes files. Using the allowlisted package_source.ps1 implementation."

$arguments = @{}
if (-not [string]::IsNullOrWhiteSpace($RepoRoot)) {
    $arguments.RepoRoot = $RepoRoot
}
if (-not [string]::IsNullOrWhiteSpace($OutputZip)) {
    $arguments.OutputZip = $OutputZip
}

& (Join-Path $PSScriptRoot "package_source.ps1") @arguments
