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

enum class Status {
	Valid,
	Warning,
	Invalid
};

struct Field {
	std::string code;
	std::string name;
	std::string value;
	bool sensitive = false;
};

struct Result {
	std::string family;
	std::string command;
	std::string action;
	std::string name;
	std::string category;
	std::string routing;
	std::string summary;
	std::string safeMessage;
	std::vector<Field> fields;
	std::vector<std::string> warnings;
	Status status = Status::Valid;
	bool known = true;
	bool sensitive = false;
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
 * Analyze one host-delivered protocol command.
 *
 * Input is bounded again here even though the capture layer already imposes a
 * limit. Unknown commands are retained as structured warnings, never rejected
 * or executed. safeMessage is suitable for display, clipboard output, and
 * persistent logging; authentication/private identity values are redacted.
 */
Result analyze(const std::string& displayedProtocol, const std::string& raw);

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
