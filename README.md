# Protocol Analyzer

Protocol Analyzer is a Windows DC++ plugin for capturing, decoding, filtering,
and safely inspecting Direct Connect protocol traffic. It understands ADC,
NMDC, client-to-client, hub, UDP search, and DHT-related messages without
altering network traffic.

- Plugin: **Protocol Analyzer**
- Binary: `ProtocolAnalyzer.dll`
- Version: **1.02**
- Author and project copyright: **iceman50**
- License: **GNU GPL version 2 or later**
- Platform: **Windows x86-64**
- Plugin API: **DC++ Plugin API 8**

## Features

### Live traffic capture

Protocol Analyzer observes traffic in both directions for:

- ADC and NMDC hub connections;
- ADC and NMDC client-to-client connections;
- incoming and outgoing ADC/NMDC UDP search traffic; and
- host-reported DHT traffic.

Capture hooks are observational: they do not block, rewrite, consume, or
execute captured messages. Expensive parsing and UI updates run after messages
leave the network callback.

### Protocol table

The virtual table displays:

- timestamp and sequential message number;
- incoming or outgoing direction;
- protocol family;
- decoded command and category;
- remote address and port;
- hub or peer identity;
- bounded summary; and
- redacted raw message.

ADC line-feed keep-alives are identified as valid `KEEPALIVE` control traffic,
including the delimiter-stripped form supplied by the host for incoming lines.

The virtual list retains responsive scrolling with large histories. Columns
may be resized or reordered, and rows use protocol-, direction-, category-,
selection-, and alternating-row colors. Hovering a cell shows its complete
bounded text only when the column is too narrow to display it.

### Decoded inspector

Selecting a row opens a read-only RichEdit structural analysis that fills the
decoded inspector panel. Labels, field codes, values, validation states,
warnings, and redacted wire data receive distinct syntax highlighting. The
inspector contains:

- protocol family and routing type;
- command/action name and category;
- semantic summary;
- decoded positional and named fields;
- recognized feature names;
- validity status and validation warnings; and
- the safely redacted wire representation.

Unknown vendor commands remain visible through a generic bounded decoder.
They are marked with a warning instead of being discarded.

### Filtering and search

Traffic can be filtered by:

- protocol;
- IP address;
- port;
- peer or hub;
- decoded command;
- decoded category;
- free-text search across all displayed fields; and
- a deliberately limited regular-expression syntax.

Filter choices update from captured traffic. Text search is live, while the
regular expression is applied with Enter or the **Apply** button. **Reset**
clears every filter without clearing captured history.

The safe regular-expression implementation supports literals, `.`, character
classes, negated classes, ranges, escaping, `^`, and `$`. It does not expose
the application to an unbounded general-purpose regex engine.

### Row and view actions

The context menu and action bar provide:

- copy selected redacted messages;
- copy the decoded analysis;
- remove selected messages;
- select all visible messages;
- open the relevant ADC or NMDC documentation;
- follow the newest matching traffic;
- keep the monitor always on top;
- clear all retained history; and
- open settings.

Closing the window hides it; capture and bounded background processing
continue. The plugin menu contains commands to show or hide the monitor, and
Show restores a hidden or minimized monitor to the foreground.

### Appearance and preferences

The interface includes:

- live light and dark modes;
- independent editable light and dark display palettes;
- colors for table backgrounds, text, selection, protocol, direction, and
  category;
- configurable decoded-inspector colors for its background, headings, labels,
  field codes, values, validation states, warnings, errors, and raw data;
- reset for one color or the complete palette;
- configurable pending-message capture queue capacity;
- configurable timestamp format;
- optional UTF-8 protocol logging; and
- DPI-aware, accessible Windows controls; and
- a fully client-drawn, theme-aware window frame on Windows 7 and later that
  eliminates the native light border while retaining resizing, window dragging,
  maximize/restore, and system commands.

Theme changes apply immediately. Settings and active filters persist through
the host configuration interface.

### Logging

Optional file logging writes only redacted message data in UTF-8. Logs rotate
at 10 MiB and retain three backups. Log batches, paths, messages, and error
reporting are bounded, and logging failures are displayed in the monitor
without interrupting capture.

## ADC analysis

ADC headers are split into routing type and three-character action. This
correctly distinguishes forms such as `BINF`, `IINF`, `CSUP`, `HSUP`, `DCTM`,
and the remaining broadcast, client, direct, echo, feature, hub, info, and UDP
routing variants.

The analyzer decodes ADC escaping, positional parameters, named fields, SIDs,
CID/PID values, feature negotiation, feature routing, and support lists.
Malformed escapes and invalid identifiers are reported rather than accepted
silently.

### ADC BASE actions

Recognized BASE actions include:

| Area | Actions |
| --- | --- |
| Handshake and identity | `SUP`, `SID`, `INF` |
| Status and authentication | `STA`, `GPA`, `PAS`, `QUI` |
| Chat and commands | `MSG`, `CMD` |
| Search | `SCH`, `RES` |
| Connections | `CTM`, `RCM` |
| Transfers | `GET`, `GFI`, `SND` |

### ADC extensions

Protocol Analyzer recognizes the documented feature identifiers:

`TIGR`, `BZIP`, `ZLIF`, `ZLIG`, `PING`, `DFAV`, `UCMD`, `BLOM`, `NATT`,
`PFSR`, `KEYP`, `SUDP`, `TYPE`, `FEED`, `SEGA`, `ADCS`, `ONID`, `ASCH`, and
`RDEX`.

It structurally recognizes extension actions including:

`OID`, `OIR`, `GFA`, `RFA`, `NAT`, `RNT`, `ZON`, `ZOF`, `TPN`, `RSS`, and
`PSR`.

Named-field decoding covers identity, application, slots, speeds, hub counts,
IPv4/IPv6 addressing, search constraints, files and hashes, transfer ranges,
user commands, Bloom filters, pinger information, redirect choices, encrypted
UDP, feeds, typing state, partial sharing, and bundle state.

#### BLOM binary transfers

The analyzer recognizes and validates the BLOM sequence `IGET blom / 0
<bytes> BK<k> BH<h>`, `HSND blom / 0 <bytes> BK<k>`, followed by the opaque
Bloom-filter bit array. The binary callback is correlated with its request and
response on the same hub connection, then replaced with bounded metadata before
it can reach UTF-8 conversion, logging, retained history, or the RichEdit
inspector. Raw Bloom-filter bytes are never displayed or copied.

Reference: [ADC BLOM extension](https://adc.sourceforge.io/ADC-EXT.html#_blom_bloom_filter)

### Deployed ADC extension detection

The official extension registry and locally verified DC++/AirDC++ implementations
were reviewed for deployed extensions. Legacy protocol revisions are labeled by
their wire meaning rather than attributed to a particular client. Detection
includes:

- feature variants `BAS0`, `UCM0`, `BLO0`, `NAT0`, and `SUD1`, plus `ADC0`
  for legacy ADC-over-TLS (`ADCS/0.10`);
- transport features `TCP4`, `TCP6`, `UDP4`, and `UDP6`;
- `HBRI`, `MCN1`, `CPMI`, `CCPM`, and `UBN1`; and
- actions `TCP`, `PMI`, `PBD`, `UBD`, and `UBN`.

## NMDC analysis

NMDC messages are split at bounded delimiters and classified by command,
category, and extension. The parser handles chat framing, `$To:` private
messages, `$MyINFO`, active/passive searches, search results, transfers,
connection negotiation, login, user lists, operator commands, compression,
hub metadata, and support negotiation.

### NMDC command coverage

| Area | Commands and families |
| --- | --- |
| Chat | Public chat, `$To:`, `$MCTo:` |
| Handshake/authentication | `$Lock`, `$Key`, `$Supports`, `$ValidateNick`, `$Hello`, `$Version`, `$GetPass`, `$MyPass`, `$LogedIn` |
| Identity and lists | `$MyINFO`, `$GetINFO`, `$NickList`, `$OpList`, `$BotList`, `$UserIP`, `$IN`, `$NickChange`, `$ClientNick`, `$GetCID`, `$CID`, `$ClientID` |
| Search | `$Search`, `$SR`, `$MultiSearch`, `$SA`, `$SP` |
| Connections | `$ConnectToMe`, `$RevConnectToMe`, `$MultiConnectToMe`, `$CTM`, `$RCTM`, `$DHTConnect`, `$Ping` |
| Transfers | `$Get`, `$Send`, `$FileLength`, `$Direction`, `$ADCGET`, `$ADCSND`, `$GetBlock`, `$GetZBlock`, `$UGetBlock`, `$UGetZBlock`, `$Sending` |
| Hub and operator | `$HubName`, `$HubTopic`, `$GetTopic`, `$SetTopic`, `$Kick`, `$Close`, `$ForceMove`, `$OpForceMove`, `$Ban`, `$TempBan`, `$UnBan`, `$GetBanList`, `$WhoIP`, `$Banned`, `$UserCommand`, `$FailOver` |
| Hub metadata/rules | `$BotINFO`, `$HubINFO`, `$SetIcon`, `$SetLogo`, `$NickRule`, `$BadNick`, `$SearchRule`, `$GetHubURL`, `$MyHubURL`, `$SetHubURL` |
| Compression | `$Z`, `$ZOn`, compressed block commands |
| Status/errors | `$BadPass`, `$HubIsFull`, `$ValidateDenide`, `$MaxedOut`, `$Failed`, `$Error`, `$Canceled` |

Additional legacy and vendor commands are classified when known and preserved
through the generic decoder when unknown.

### NMDC extension detection

`$Supports` tokens are labeled for:

`ADCGet`, `BotList`, `UserIP2`, `BotINFO`, `HubINFO`, `HubTopic`, `IN`,
`MCTo`, `NickChange`, `ClientNick`, `FeaturedNetworks`, `ZLine`, `ZPipe0`,
`GetZBlock`, `ClientID`, `UserCommand`, `NoHello`, `ChatOnly`, `QuickList`,
`TTHSearch`, `XmlBZList`, `MiniSlots`, `TTHL`, `TTHF`, `TTHS`, `ZLIG`,
`ACTM`, `NoGetINFO`, `BZList`, `CHUNK`, `OpPlus`, `Feed`, `SaltPass`, `IPv4`,
`IP64`, `TLS`, `NAT`, `DHT0`, `FailOver`, `NickRule`, `SearchRule`, and
`HubURL`.

Reference: [NMDC protocol documentation](https://dc-protocols.github.io/NMDC.html)

## Security model

Protocol Analyzer treats every captured byte as untrusted.

- ADC private IDs (`PD`), password responses, and SUDP keys (`KY`) are
  redacted.
- NMDC passwords and credential-like vendor commands are redacted.
- Redaction happens before table display, inspector rendering, clipboard
  output, history retention, or file logging.
- ZLIB, ZPipe, compressed blocks, and encrypted UDP payloads remain opaque.
  The plugin never decompresses or executes captured content.
- Control characters are escaped before presentation.
- Invalid and oversized input is truncated or rejected with a visible warning.
- Exceptions are contained at plugin/host callback boundaries.
- Plugin load failures roll back registered hooks and commands.
- Unload waits for active callbacks and releases host interfaces safely.

### Resource limits

Important hard limits include:

| Resource | Limit |
| --- | ---: |
| Captured/analyzed message | 64 KiB |
| Decoded fields | 64 |
| Field value | 4 KiB |
| Parser warnings | 16 |
| Summary | 512 bytes |
| Inspector output | 32 KiB |
| Capture queue | 64–65,536 messages (default 1,024) / fixed 4 MiB |
| Retained history | 20,000 messages / 64 MiB |
| Clipboard output | 4 MiB |
| Regex pattern | 256 characters |
| Log file before rotation | 10 MiB |
| Active `/fetch` requests | 16 |

The message-count queue limit is set in **Preferences → Capture queue** and is
clamped to its supported range. The independent 4 MiB ceiling cannot be
disabled. Reducing the limit discards only excess unprocessed messages and
accounts for them as dropped traffic. When a queue or history limit is
reached, traffic is dropped or the oldest history is evicted in a controlled
manner and the UI reports the condition.

## Chat commands

### `/raw <message>`

Sends one bounded protocol message to the current hub. Empty input, CR/LF, and
other unsafe control characters are rejected. This is an expert diagnostic
command; use it only on hubs where protocol testing is authorized.

### `/fetch <http-or-https-url> [localpath]`

Starts a host-managed HTTP(S) request, optionally writing it to a local file.
Only `http://` and `https://` URLs are accepted. URI/path lengths, duplicate
requests, concurrency, callbacks, and accounted byte counts are bounded. The
plugin records completion statistics but does not retain unused response
bodies.

`/help` appends both command syntaxes to the host help output.

## Installation

1. Build or download the x86-64 `.dcext` package.
2. Install it through the DC++-compatible host's plugin manager.
3. The monitor opens immediately after runtime installation or activation.
   It also opens at startup when it was visible during the previous session.

Use **Protocol Analyzer → Show the dialog** from the plugin menu to restore a
window that was hidden manually. Monitor-creation failures are written to the
host system log with bounded diagnostic text.

The package contains `ProtocolAnalyzer.dll`, `ProtocolAnalyzer.dbg`, the
plugin icon, licenses, third-party notices, build provenance, and internal
SHA-256 checksums.

## Building

The canonical build uses MinGW-w64 for Windows x86-64:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\build_dist.ps1
```

With no configuration argument, the script interactively asks for Debug,
Release, or both and whether to run the slower GCC static-analysis pass. Select
a configuration non-interactively with:

```powershell
.\build_dist.ps1 -Configuration Debug
.\build_dist.ps1 -Configuration Release
```

For a fast local test build:

```powershell
.\build_dist.ps1 -Configuration Debug -Incremental -SkipStaticAnalysis
```

`-SkipStaticAnalysis` skips only GCC `-fanalyzer`; strict compiler warnings,
parser tests, ABI/UI smoke tests, packaging checks, and archive auditing still
run. `-NonInteractive` preserves the historical no-argument Debug + Release
build with static analysis for automation.

`-Configuration All` is the non-interactive default. Builds are clean by default.
`-Incremental` is intended for local development and automatically falls back
to a clean build when the toolchain or build fingerprint changes; ordinary
source and test edits use Makefile dependencies and remain incremental.

Create the deterministic allowlisted source archive with:

```powershell
.\packaging\package_source.ps1
```

Outputs and `.sha256` sidecars are written to `dist`.

The Visual Studio development solution is:
`projects/vs2022/ProtocolAnalyzer.sln`. Audited release artifacts are produced
by the MinGW-w64 pipeline.

## Validation

Each canonical build runs:

- strict Debug and Release compiler warnings;
- GCC static analysis with warnings treated as errors unless explicitly skipped
  for a fast local build;
- bounded ADC/NMDC unit and adversarial-input tests;
- parser allocation and performance-budget tests;
- plugin ABI, lifecycle, callback-race, UI, and redaction smoke tests;
- PE architecture, import/export, version-resource, hardening, and debug-link
  checks;
- manifest, deterministic timestamp, path, checksum, provenance, and archive
  audits; and
- staged DLL loading.

## Project files

- `src/ProtocolAnalyzer.cpp` — bounded ADC/NMDC parser.
- `src/GUI.cpp` — capture monitor, filters, inspector, logging, and themes.
- `src/Plugin.cpp` — host lifecycle, network hooks, and chat commands.
- `tests/protocol_analyzer_tests.cpp` — parser/security/performance tests.
- `tests/plugin_abi_smoke.cpp` — ABI, lifecycle, and UI integration tests.
- `build_dist.ps1` — canonical build and packaging pipeline.
- `packaging/info.xml` — package metadata template.
- `CHANGELOG.md` — complete release history.

## License and third-party code

Protocol Analyzer is distributed under GNU GPL version 2 or later. See
`gpl-2.0.txt` and `LICENSE`.

The repository contains DC++ plugin SDK and LibDWT-derived code with their
original copyright and license notices preserved. See
`packaging/THIRD_PARTY.txt` and `dwt/License.txt`.
