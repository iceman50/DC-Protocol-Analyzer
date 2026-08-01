[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$fullPath = [System.IO.Path]::GetFullPath($Path)
if (-not (Test-Path -LiteralPath $fullPath -PathType Leaf)) {
    throw "PE timestamp target is not a file: $fullPath"
}
$item = Get-Item -LiteralPath $fullPath -Force
if (($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint) -ne 0) {
    throw "PE timestamp normalization refuses reparse points: $fullPath"
}

$stream = [System.IO.File]::Open(
    $fullPath,
    [System.IO.FileMode]::Open,
    [System.IO.FileAccess]::ReadWrite,
    [System.IO.FileShare]::None)
try {
    $reader = [System.IO.BinaryReader]::new(
        $stream, [System.Text.Encoding]::UTF8, $true)
    $writer = [System.IO.BinaryWriter]::new(
        $stream, [System.Text.Encoding]::UTF8, $true)
    try {
        if ($stream.Length -lt 0x40 -or $reader.ReadUInt16() -ne 0x5A4D) {
            throw "Timestamp target does not have a valid MZ header: $fullPath"
        }
        $stream.Position = 0x3C
        $peOffset = $reader.ReadInt32()
        if ($peOffset -lt 0x40 -or $peOffset -gt $stream.Length - 24) {
            throw "Timestamp target has an invalid PE header offset: $fullPath"
        }
        $stream.Position = $peOffset
        if ($reader.ReadUInt32() -ne 0x00004550) {
            throw "Timestamp target does not have a PE signature: $fullPath"
        }
        if ($reader.ReadUInt16() -ne 0x8664) {
            throw "Timestamp target is not PE x86-64: $fullPath"
        }

        $stream.Position = $peOffset + 8
        $writer.Write([uint32]0)
        $writer.Flush()
        $stream.Flush($true)
    }
    finally {
        $writer.Dispose()
        $reader.Dispose()
    }
}
finally {
    $stream.Dispose()
}
