Protocol Analyzer release packaging
===================================

The supported release path is the root build_dist.ps1 script. With no
configuration argument it interactively selects Debug, Release, or both and
whether to run GCC static analysis. It creates deterministic .dcext archives
in dist/, validates their manifests and PE/debug artifacts, and writes SHA-256
checksum sidecars.

    powershell -NoProfile -ExecutionPolicy Bypass -File ..\build_dist.ps1

For a fast local build:

    powershell -NoProfile -ExecutionPolicy Bypass -File ..\build_dist.ps1 -Configuration Debug -Incremental -SkipStaticAnalysis

Use -NonInteractive with no configuration argument to build and audit both
configurations with static analysis.

Use package_source.ps1 to create a deterministic, allowlisted source archive
without deleting or modifying any source/build files:

    powershell -NoProfile -ExecutionPolicy Bypass -File .\package_source.ps1

clean_and_zip_source.ps1 is retained as a safe compatibility wrapper and no
longer performs cleanup. The old MSVC/x86 packagers are intentionally disabled.
