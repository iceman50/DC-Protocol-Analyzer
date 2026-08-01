[CmdletBinding()]
param(
    [string]$Configuration,
    [string]$Platform,
    [string]$Win32WinNt,
    [switch]$IncludeWin32,
    [string]$PluginName
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

throw "The MSVC/x86 packaging path is retired. Use the repository-root build_dist.ps1 script for audited MinGW-w64 x64 Debug/Release packages."
