/*
* Copyright (C) 2022-2026 iceman50
*
* This program is free software; you can redistribute it and/or modify
* it under the terms of the GNU General Public License as published by
* the Free Software Foundation; either version 2 of the License, or
* (at your option) any later version.
*
* This program is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU General Public License
* along with this program; if not, write to the Free Software
* Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
*/

#ifndef PROTOCOL_ANALYZER_CORE_H
#define PROTOCOL_ANALYZER_CORE_H

#include <cstddef>
#include <string>
#include <vector>

namespace protocol_analyzer {

/** Overall structural validity of the decoded frame. */
enum class Status {
	Valid,
	Warning,
	Invalid
};

/** Per-call presentation policy. Parsing and classification are unaffected. */
struct AnalysisOptions {
	bool redactSensitiveValues = true;
};

/** One decoded positional or named protocol value. */
struct Field {
	/** Stable machine-readable field identifier used by tests and renderers. */
	std::string code;
	/** Human-readable explanation of the field's protocol meaning. */
	std::string name;
	/** Optional longer explanation supplied by the XML definition catalog. */
	std::string description;
	/** Sanitized decoded value, or <redacted> when policy requires it. */
	std::string value;
	/** True when the source value contains credentials or private identity data. */
	bool sensitive = false;
};

/**
 * Bounded, presentation-safe analysis of one captured frame.
 *
 * `family` is the decoded wire family, which may differ from the caller's
 * transport label. In particular, a UDP capture becomes ADC or NMDC only when
 * its framing supplies enough evidence; otherwise its family is Unknown and
 * its routing remains UDP.
 */
struct Result {
	/** Detected wire family: ADC, NMDC, DHT, or Unknown. */
	std::string family;
	/** Complete command token as it appeared on the wire (for example BINF). */
	std::string command;
	/** Family-level action without routing information (for example INF). */
	std::string action;
	/** Human-readable command name. */
	std::string name;
	/** Optional longer explanation supplied by the XML definition catalog. */
	std::string description;
	/** Broad functional grouping used by filters and colors. */
	std::string category;
	/** Routing type or transport context. */
	std::string routing;
	/** Short, bounded description suitable for the capture table. */
	std::string summary;
	/** Sanitized and policy-redacted wire representation. */
	std::string safeMessage;
	std::vector<Field> fields;
	std::vector<std::string> warnings;
	Status status = Status::Valid;
	/** False for unknown/vendor commands and unclassified payloads. */
	bool known = true;
	/** True when any source field was considered sensitive. */
	bool sensitive = false;
	/** Records the policy used to construct fields and safeMessage. */
	bool redactionEnabled = true;
	/*
	 * A BLOM HSND command is followed by an opaque, unframed byte stream.
	 * The capture layer must correlate this hint by connection and direction
	 * and pass the next payload to analyzeBinaryPayload instead of treating it
	 * as another ADC command.
	 */
	bool binaryPayloadFollows = false;
	bool binaryPayload = false;
	bool observedBinaryPayloadBytesKnown = false;
	std::size_t expectedBinaryPayloadBytes = 0;
	std::size_t observedBinaryPayloadBytes = 0;
	std::string binaryPayloadType;
};

/*
 * Analyze one host-delivered protocol command or UDP datagram.
 *
 * Input is bounded again here even though the capture layer already imposes a
 * limit. Unknown commands are retained as structured warnings, never rejected
 * or executed. safeMessage is suitable for display, clipboard output, and
 * persistent logging. Authentication/private identity values are redacted by
 * default; callers may explicitly disable redaction for diagnostic use.
 *
 * ADC and NMDC labels supplied by the host are authoritative because the host
 * knows the connection negotiation. UDP is only a transport label, so its
 * payload is classified conservatively from complete ADC/NMDC framing. Other
 * labels are kept opaque and are never guessed from a leading character.
 */
Result analyze(const std::string& displayedProtocol, const std::string& raw);
Result analyze(const std::string& displayedProtocol, const std::string& raw,
	const AnalysisOptions& options);

/*
 * Build a display-safe result for a correlated opaque transfer payload.
 * No payload bytes are accepted or retained: callers pass only the observed
 * byte count, preventing arbitrary binary data from reaching text controls.
 */
Result analyzeBinaryPayload(const std::string& displayedProtocol,
	const std::string& transferType, std::size_t observedBytes,
	std::size_t expectedBytes);

/*
 * Variant for host hooks that identify the payload event but do not expose a
 * trustworthy raw-body length (notably DC++ HUB_OUT).
 */
Result analyzeBinaryPayload(const std::string& displayedProtocol,
	const std::string& transferType, std::size_t expectedBytes);

/* Produce a bounded, control-character-safe inspector representation. */
std::string formatDetails(const Result& result);

const char* statusName(Status status) noexcept;

} // namespace protocol_analyzer

#endif
