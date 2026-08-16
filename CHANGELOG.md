# Changelog

All notable changes to Protocol Analyzer are documented in this file.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
The project uses a two-component public version, beginning with 1.00 after the
Protocol Analyzer rebrand. Earlier DevPlugin releases are retained below as
legacy history.

## [1.01] - 2026-08-16

### Added

- Added detection for uHub's ADC `RTF0` rich-text chat extension and the
  `MSG` `RT1` formatting flag.
- Added decoding for the additive ADC `INF` `CT` client-type flags, including
  bot, registered user, operator, super user, hub owner, hub, and hidden types.
- Added detection for NMDC delimiter-only keep-alive messages, including the
  delimiter-stripped incoming form supplied by the host, and decoding for the
  status and capability flags in the `$MyINFO` connection-status byte.
- Added an opt-in setting to show sensitive protocol values in newly captured
  rows and protocol logs by disabling the default redaction policy.
- Added capture Address, Port, and Peer metadata to the decoded inspector.
- Added a Copy column submenu that copies the selected rows from any individual
  capture-table column while retaining the clipboard safety limit.
- Added independent 1–64 MiB preferences for pending capture-queue memory and
  clipboard output, retaining 4 MiB as the default for each safeguard.

### Changed

- Standardized UI-related namespaces by moving UI helpers under
  `protocol_analyzer::ui` and renamed the table-specific color subsystem to
  `Palette` because it also styles the decoded inspector. Existing
  customized colors migrate from the legacy `Table*` configuration keys.
- Changed UDP analysis to preserve UDP as the capture transport and classify
  payloads as ADC or NMDC only when complete protocol framing supplies enough
  evidence; ambiguous payloads remain Unknown.
- Preserved structurally valid unknown and vendor-specific ADC/NMDC datagrams
  through generic decoding so future commands are not discarded or mislabeled.
- Added inline documentation for the analyzer API, decoder architecture,
  framing decisions, trust boundaries, sensitive-span masking, bounded output,
  and opaque binary-payload handling.
- Changed warning and invalid Raw output to use the corresponding validation
  colors in both the capture table and decoded inspector.

### Security

- Redacts credential-shaped content in ambiguous UDP and unknown-protocol
  payloads without falsely assigning an ADC or NMDC family.
- Sanitizes host-provided Address, Port, and Peer values before inserting them
  into the inspector so control characters cannot create forged metadata rows.

### Fixed

- Fixed arbitrary or malformed UDP payloads being inferred as ADC by default or
  as NMDC from a leading character alone, while retaining recognition of
  correctly framed known, vendor-specific, and future protocol commands.
- Fixed the custom-title-bar Close glyph rendering with uneven diagonal arms.

## [1.00] - 2026-07-25

### Added

- Added bounded, read-only structural analysis for ADC routing forms and BASE
  commands, including `BINF`, `IINF`, `CSUP`, `HSUP`, searches, transfers,
  status, identity, chat, connection negotiation, and user commands.
- Added detection for ADC extensions documented by ADC-EXT: TIGR, BZIP, ZLIB,
  PING, DFAV, UCMD, BLOM, NATT, PFSR, KEYP, SUDP, TYPE, FEED, SEGA, ADCS,
  ONID, ASCH, and RDEX.
- Added structural decoding for ADC extension commands `GFA`, `RFA`, `NAT`,
  `RNT`, `ZON`, `ZOF`, `TPN`, `RSS`, and `PSR`.
- Added detection for AirDC++ ADC features and commands, including BAS0, UCM0,
  BLO0, ADC0, NAT0, SUD1, TCP4/TCP6, UDP4/UDP6, HBRI, MCN1, CPMI, CCPM,
  UBN1, `TCP`, `PMI`, `PBD`, `UBD`, and `UBN`.
- Added classification for documented NMDC commands and support features,
  including ADCGet, UserIP2, IN, TTH search/transfer variants, compression,
  ACTM, TLS, NAT, DHT, FailOver, operator extensions, and hub metadata.
- Added decoding for the newer NMDC `TTHS`, `SetIcon`, `SetLogo`, `NickRule`,
  `BadNick`, `SearchRule`, and `HubURL` command families.
- Added Command, Category, Summary, and redacted Raw columns, command/category
  filters, full-field searching, and a selection-driven decoded inspector.
- Added light and dark palettes covering protocol, direction, category,
  selection, header, and row colors, with live preview and reset controls.
- Added deterministic parser, adversarial-input, ABI, lifecycle, race, UI,
  redaction, packaging, import/export, hardening, and reproducibility tests.

### Changed

- Renamed the plugin and project from DevPlugin/DC Protocol Analyzer to
  Protocol Analyzer.
- Renamed the binary and packaged plugin entry to `ProtocolAnalyzer.dll`.
- Reset the public project version to 1.00 and assigned project author and
  copyright metadata to iceman50.
- Replaced the legacy DWT snapshot with LibDWT 0.883.1 and removed Boost.
- Standardized the supported release toolchain on MinGW-w64 x86-64 with
  deterministic Debug and Release packages plus split GNU debug information.
- Moved protocol parsing out of network callbacks and into the bounded UI drain
  path so capture callbacks remain observational and low latency.

### Security

- Redacts ADC private IDs, password responses, SUDP keys, NMDC passwords,
  credential-like vendor commands, and compressed payloads before display,
  clipboard use, retained history, or persistent logging.
- Treats ZLIB/ZPipe/SUDP payloads as opaque and never decompresses or executes
  captured network data.
- Limits analyzer input, decoded fields, field sizes, warnings, summaries,
  inspector output, queued traffic, retained history, clipboard data, log
  batches, HTTP request tracking, and regex complexity.
- Hardened plugin load/unload rollback, callback draining, registry races,
  incomplete host interfaces, null ABI inputs, duplicate registrations, and
  exceptions crossing the plugin boundary.
- Restricted `/fetch` to bounded HTTP(S) requests and stopped retaining
  response bodies that the plugin does not consume.
- Hardened UTF-8 logging, field escaping, rotation, archive creation, source
  allowlisting, reparse-point checks, atomic replacement, PE validation,
  package checksums, and build provenance.

### Fixed

- Fixed owner-data rows occasionally remaining invisible after clearing the
  monitor by resetting the viewport, item count, and repaint state.
- Fixed filter clearing, invalid regular-expression feedback, independent text
  and regex matching, and stale queued rows reappearing after Clear.
- Fixed log-path updates so they apply without reopening the monitor.
- Fixed dark-mode checkbox/group captions, combo-box faces, DPI padding, and
  clipped text descenders.
- Fixed LibDWT MinGW warnings and hardened Windows-boundary behavior for
  application lifetime, clipboard ownership, timers, dialogs, GDI buffering,
  DPI, accessibility, tables, combo boxes, and callback containment.
- Fixed plugin loading in hosts without an active version-6 common-controls
  context by resolving TaskDialog APIs at runtime.
- Fixed reproducible stripped DLL/debug-companion timestamps after GNU objcopy.

## [Legacy DevPlugin 1.41] - 2026-07-25

### Added

- Added bounded ADC/NMDC decoding with generic vendor-command fallback.
- Added decoded columns, filters, inspector fields, validation warnings, and
  redacted raw-message presentation.
- Added authentication/private-ID/compressed-payload redaction across every
  presentation and persistence surface.
- Added deterministic adversarial parser tests and decoded-rendering ABI/UI
  smoke coverage.

### Changed

- Kept parsing off network callback threads and imposed strict resource limits.
- Removed the eager `TaskDialogIndirect` import and normalized PE timestamps
  after GNU objcopy.
