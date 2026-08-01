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

#include "ProtocolAnalyzer.h"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <limits>
#include <sstream>
#include <string_view>
#include <utility>

namespace protocol_analyzer {
namespace {

using std::string;
using std::string_view;

constexpr size_t MAX_ANALYZER_INPUT_BYTES = 64 * 1024;
constexpr size_t MAX_FIELDS = 64;
constexpr size_t MAX_WARNINGS = 16;
constexpr size_t MAX_FIELD_VALUE_BYTES = 4096;
constexpr size_t MAX_SUMMARY_BYTES = 512;
constexpr size_t MAX_DETAIL_BYTES = 32 * 1024;

struct Span {
	size_t offset;
	size_t length;
};

struct Definition {
	const char* command;
	const char* name;
	const char* category;
};

struct FeatureDefinition {
	const char* code;
	const char* name;
};

constexpr std::array<Definition, 32> ADC_DEFINITIONS {{
	{ "STA", "Status", "Status" },
	{ "SUP", "Supported features", "Handshake" },
	{ "SID", "Session ID assignment", "Handshake" },
	{ "INF", "Entity information", "Identity" },
	{ "MSG", "Chat message", "Chat" },
	{ "SCH", "Search request", "Search" },
	{ "RES", "Search result", "Search" },
	{ "CTM", "Connect request", "Connection" },
	{ "RCM", "Reverse connect request", "Connection" },
	{ "GPA", "Password challenge", "Authentication" },
	{ "PAS", "Password response", "Authentication" },
	{ "QUI", "Disconnect notification", "Status" },
	{ "GET", "Transfer request", "Transfer" },
	{ "GFI", "File information request", "Transfer" },
	{ "SND", "Transfer response", "Transfer" },
	{ "CMD", "User command", "Hub" },
	{ "OID", "Identity service notification", "Extension" },
	{ "OIR", "Identity service request or response", "Extension" },
	{ "GFA", "Distributed-favorites request", "Extension" },
	{ "RFA", "Distributed-favorites response", "Extension" },
	{ "NAT", "NAT traversal request", "Connection" },
	{ "RNT", "NAT traversal response", "Connection" },
	{ "ZON", "Compressed stream activation", "Compression" },
	{ "ZOF", "Compressed stream deactivation", "Compression" },
	{ "TPN", "Typing-state notification", "Chat" },
	{ "RSS", "Feed notification", "Extension" },
	{ "PSR", "Partial-file availability", "Transfer" },
	{ "TCP", "Hybrid IP reachability validation", "Connection" },
	{ "PMI", "Private-message state information", "Chat" },
	{ "PBD", "Partial-bundle information", "Transfer" },
	{ "UBD", "Upload-bundle definition", "Transfer" },
	{ "UBN", "Upload-bundle notification", "Transfer" }
}};

constexpr std::array<Definition, 90> NMDC_DEFINITIONS {{
	{ "$To:", "Private chat message", "Chat" },
	{ "$MCTo:", "Main-chat-style private message", "Chat" },
	{ "$ConnectToMe", "Connect request", "Connection" },
	{ "$RevConnectToMe", "Reverse connect request", "Connection" },
	{ "$Ping", "Connection probe", "Connection" },
	{ "$GetPass", "Password challenge", "Authentication" },
	{ "$MyPass", "Password response", "Authentication" },
	{ "$LogedIn", "Successful login", "Authentication" },
	{ "$Get", "Legacy transfer request", "Transfer" },
	{ "$Send", "Legacy transfer response", "Transfer" },
	{ "$FileLength", "File length", "Transfer" },
	{ "$GetListLen", "File-list length request", "Transfer" },
	{ "$ListLen", "File-list length", "Transfer" },
	{ "$Direction", "Transfer direction negotiation", "Transfer" },
	{ "$Cancel", "Transfer cancellation", "Transfer" },
	{ "$Canceled", "Transfer cancelled", "Transfer" },
	{ "$BadPass", "Invalid password", "Status" },
	{ "$HubIsFull", "Hub capacity error", "Status" },
	{ "$ValidateDenide", "Nickname rejected", "Status" },
	{ "$MaxedOut", "No upload slots", "Status" },
	{ "$Failed", "Operation failed", "Status" },
	{ "$Error", "Protocol error", "Status" },
	{ "$Search", "Search request", "Search" },
	{ "$SR", "Search result", "Search" },
	{ "$MyINFO", "User information", "Identity" },
	{ "$GetINFO", "User information request", "Identity" },
	{ "$Hello", "User accepted", "Handshake" },
	{ "$Version", "Legacy client version marker", "Handshake" },
	{ "$HubName", "Hub name", "Hub" },
	{ "$GetNickList", "User-list request", "Identity" },
	{ "$NickList", "User list", "Identity" },
	{ "$OpList", "Operator list", "Identity" },
	{ "$BotList", "Bot list", "Identity" },
	{ "$Kick", "Kick request", "Hub" },
	{ "$Close", "Silent kick request", "Hub" },
	{ "$OpForceMove", "Operator redirect", "Hub" },
	{ "$ForceMove", "Hub redirect", "Hub" },
	{ "$MyNick", "Peer nickname", "Handshake" },
	{ "$Lock", "Lock challenge", "Handshake" },
	{ "$Key", "Lock response", "Handshake" },
	{ "$Supports", "Supported extensions", "Handshake" },
	{ "$ValidateNick", "Nickname validation", "Handshake" },
	{ "$Quit", "User disconnected", "Identity" },
	{ "$ADCGET", "Transfer request", "Transfer" },
	{ "$ADCSND", "Transfer response", "Transfer" },
	{ "$UserIP", "User IP information", "Identity" },
	{ "$BotINFO", "Hub-list bot information", "Hub" },
	{ "$HubINFO", "Hub information", "Hub" },
	{ "$HubTopic", "Hub topic", "Hub" },
	{ "$Capabilities", "Capabilities", "Handshake" },
	{ "$IN", "Incremental user information", "Identity" },
	{ "$NickChange", "Nickname change", "Identity" },
	{ "$ClientNick", "Nickname change confirmation", "Identity" },
	{ "$FeaturedNetworks", "Network-prefix information", "Extension" },
	{ "$Z", "Compressed command block", "Compression" },
	{ "$ZOn", "Compressed stream activation", "Compression" },
	{ "$GetZBlock", "Compressed block request", "Transfer" },
	{ "$UGetBlock", "UTF-8 block request", "Transfer" },
	{ "$UGetZBlock", "Compressed UTF-8 block request", "Transfer" },
	{ "$Sending", "Block transfer response", "Transfer" },
	{ "$GetCID", "Client ID request", "Identity" },
	{ "$CID", "Client ID response", "Identity" },
	{ "$FailOver", "Failover hub list", "Hub" },
	{ "$DHTConnect", "DHT connection request", "Connection" },
	{ "$UserCommand", "User command definition", "Hub" },
	{ "$Ban", "Operator ban command", "Hub" },
	{ "$TempBan", "Operator temporary ban command", "Hub" },
	{ "$MultiConnectToMe", "Linked-hub connect request", "Connection" },
	{ "$MultiSearch", "Linked-hub search request", "Search" },
	{ "$GetTestZBlock", "Deprecated compressed block request", "Transfer" },
	{ "$ClientID", "Client ID notification", "Identity" },
	{ "$CTM", "Advanced connect request", "Connection" },
	{ "$RCTM", "Advanced reverse connect request", "Connection" },
	{ "$UnBan", "Operator unban command", "Hub" },
	{ "$GetBanList", "Operator ban-list request", "Hub" },
	{ "$WhoIP", "Operator IP lookup", "Hub" },
	{ "$Banned", "Operator ban-list response", "Hub" },
	{ "$GetTopic", "Hub-topic request", "Hub" },
	{ "$SetTopic", "Hub-topic update", "Hub" },
	{ "$GetBlock", "Legacy block request", "Transfer" },
	{ "$SA", "Short active TTH search", "Search" },
	{ "$SP", "Short passive TTH search", "Search" },
	{ "$SetIcon", "Hub icon", "Hub" },
	{ "$SetLogo", "Hub logo", "Hub" },
	{ "$NickRule", "Nickname rules", "Hub" },
	{ "$BadNick", "Nickname rule violation", "Status" },
	{ "$SearchRule", "Search rules", "Hub" },
	{ "$GetHubURL", "Hub URL request", "Hub" },
	{ "$MyHubURL", "Client hub URL", "Hub" },
	{ "$SetHubURL", "Preferred hub URL", "Hub" }
}};

constexpr std::array<FeatureDefinition, 35> ADC_FEATURE_DEFINITIONS {{
	{ "BASE", "ADC base protocol" },
	{ "BAS0", "Legacy ADC/0.10 base protocol" },
	{ "TIGR", "Tiger tree hashes" },
	{ "BZIP", "Bzip2 file lists" },
	{ "ZLIF", "Full-stream zlib compression" },
	{ "ZLIG", "Compressed transfer data" },
	{ "PING", "Hub pinger information" },
	{ "DFAV", "Distributed favorites" },
	{ "UCMD", "User commands" },
	{ "UCM0", "User commands revision 0" },
	{ "BLOM", "Bloom-filter sharing" },
	{ "BLO0", "Bloom-filter sharing revision 0" },
	{ "NATT", "NAT traversal" },
	{ "NAT0", "NAT traversal revision 0" },
	{ "PFSR", "Partial-file sharing" },
	{ "KEYP", "TLS certificate keyprints" },
	{ "SUDP", "Encrypted UDP traffic" },
	{ "SUD1", "Encrypted UDP traffic revision 1" },
	{ "TYPE", "Typing-state notifications" },
	{ "FEED", "RSS feed notifications" },
	{ "SEGA", "Grouped search extensions" },
	{ "ADCS", "ADC-over-TLS capability (ADCS/1.0)" },
	{ "ADC0", "Legacy ADC-over-TLS capability (ADCS/0.10)" },
	{ "ONID", "Online-service identities" },
	{ "ASCH", "Advanced search" },
	{ "RDEX", "Extended redirects" },
	{ "TCP4", "Incoming TCP connections over IPv4" },
	{ "TCP6", "Incoming TCP connections over IPv6" },
	{ "UDP4", "Incoming UDP packets over IPv4" },
	{ "UDP6", "Incoming UDP packets over IPv6" },
	{ "HBRI", "Hybrid IPv4/IPv6 reachability validation" },
	{ "MCN1", "Multiple client connections" },
	{ "CPMI", "Client private-message information" },
	{ "CCPM", "Client-to-client private messages" },
	{ "UBN1", "Upload-bundle notifications revision 1" }
}};

constexpr std::array<FeatureDefinition, 42> NMDC_FEATURE_DEFINITIONS {{
	{ "ADCGet", "ADC-style transfers" },
	{ "BotList", "Bot list" },
	{ "UserIP2", "Full user IP updates" },
	{ "BotINFO", "Hub-list bot information" },
	{ "HubINFO", "Hub-list information" },
	{ "HubTopic", "Hub topic" },
	{ "IN", "Incremental user information" },
	{ "MCTo", "Main-chat-style private messages" },
	{ "NickChange", "Runtime nickname changes" },
	{ "ClientNick", "Nickname-change confirmation" },
	{ "FeaturedNetworks", "Multi-hub chat prefixes" },
	{ "ZLine", "Compressed command lines" },
	{ "ZPipe0", "Compressed command stream" },
	{ "GetZBlock", "Compressed block transfers" },
	{ "ClientID", "Client identifiers" },
	{ "UserCommand", "Hub-provided user commands" },
	{ "NoHello", "Reduced login handshake" },
	{ "ChatOnly", "Chat-only client" },
	{ "QuickList", "Quick user-list handshake" },
	{ "TTHSearch", "TTH searches" },
	{ "XmlBZList", "XML bzip2 file lists" },
	{ "MiniSlots", "Small-file mini slots" },
	{ "TTHL", "Tiger-tree leaves" },
	{ "TTHF", "TTH file identifiers" },
	{ "TTHS", "Short TTH searches" },
	{ "ZLIG", "Compressed ADCGET transfers" },
	{ "ACTM", "Advanced connection requests" },
	{ "NoGetINFO", "Unsolicited user information" },
	{ "BZList", "Bzip2 legacy file lists" },
	{ "CHUNK", "Chunked legacy transfers" },
	{ "OpPlus", "Extended operator commands" },
	{ "Feed", "Operator activity feed" },
	{ "SaltPass", "Salted password authentication" },
	{ "IPv4", "IPv4 support over an IPv6 hub connection" },
	{ "IP64", "IPv6 capability and dual-address reporting" },
	{ "TLS", "TLS-encrypted client-to-client connections" },
	{ "NAT", "NAT traversal" },
	{ "DHT0", "Distributed hash table" },
	{ "FailOver", "Alternative hub addresses" },
	{ "NickRule", "Nickname rules" },
	{ "SearchRule", "Search rules" },
	{ "HubURL", "Connected hub URL reporting" }
}};

constexpr std::array<std::pair<const char*, const char*>, 115> ADC_FIELD_NAMES {{
	{ "ID", "Client ID" }, { "PD", "Private ID" },
	{ "NI", "Name" }, { "DE", "Description" },
	{ "AP", "Application" }, { "VE", "Version" },
	{ "EM", "Email" }, { "SS", "Share size" },
	{ "SF", "Shared files" }, { "SL", "Upload slots" },
	{ "FS", "Free slots" }, { "US", "Upload speed" },
	{ "DS", "Download speed" }, { "HN", "Normal hubs" },
	{ "HR", "Registered hubs" }, { "HO", "Operator hubs" },
	{ "CT", "Client type" }, { "AW", "Away" },
	{ "SU", "Supported features" }, { "I4", "IPv4 address" },
	{ "I6", "IPv6 address" }, { "U4", "IPv4 UDP port" },
	{ "U6", "IPv6 UDP port" }, { "KP", "Certificate keyprint" },
	{ "RF", "Referrer" }, { "TO", "Token" },
	{ "PM", "Private-message group SID" }, { "ME", "Third person" },
	{ "TS", "Timestamp" }, { "AN", "Included term" },
	{ "NO", "Excluded term" }, { "EX", "Extension" },
	{ "LE", "Maximum size" }, { "GE", "Minimum size" },
	{ "EQ", "Exact size" }, { "TY", "File type" },
	{ "TR", "Tiger tree hash" }, { "TD", "Tree depth" },
	{ "FN", "Filename" }, { "SI", "Size" },
	{ "FI", "File count" }, { "FO", "Directory count" },
	{ "DA", "Modified time" }, { "MT", "Matching mode" },
	{ "PP", "Return parent path" }, { "OT", "Older than" },
	{ "NT", "Newer than" }, { "MR", "Maximum results" },
	{ "PA", "Search path" }, { "RE", "Reply requested" },
	{ "FC", "Related command" }, { "RC", "Result count" },
	{ "PR", "Protocol" }, { "MS", "Message" },
	{ "DI", "Disconnect transfers" }, { "TL", "Reconnect delay" },
	{ "HH", "Hub address" }, { "WS", "Website" },
	{ "NE", "Network" }, { "OW", "Owner" },
	{ "UC", "Current users" }, { "XS", "Maximum share" },
	{ "ML", "Minimum slots" }, { "XL", "Maximum slots" },
	{ "MU", "Minimum user hubs" }, { "XR", "Maximum registered hubs" },
	{ "XO", "Maximum operator hubs" }, { "MC", "Maximum users" },
	{ "UP", "Uptime or update flag" }, { "HA", "Hub address" },
	{ "LG", "Last successful login" }, { "RM", "Remove flag" },
	{ "TT", "Command template" }, { "CO", "Constrained execution" },
	{ "SP", "Separator flag" }, { "BK", "Bloom sub-hash count" },
	{ "BH", "Bloom sub-hash width" }, { "KY", "UDP encryption key" },
	{ "HI", "Hub IP and port" }, { "PC", "Partial chunk count" },
	{ "PI", "Partial chunk intervals" }, { "LC", "Locale" },
	{ "QP", "Upload queue position" }, { "GR", "Extension group" },
	{ "RX", "Excluded extensions or redirect choices" },
	{ "RP", "Accepted redirect protocols" }, { "PT", "Permanent redirect" },
	{ "CR", "Author" }, { "TI", "Title" },
	{ "LI", "Link" }, { "DT", "Publication time" },
	{ "DB", "Downloaded and verified bytes" }, { "P4", "IPv4 TCP port" },
	{ "P6", "IPv6 TCP port" }, { "BU", "Bundle token" },
	{ "TH", "Tiger tree hash" }, { "PE", "Progress percentage" },
	{ "NA", "Bundle name" }, { "DL", "Downloaded bytes" },
	{ "CH", "Change flag" }, { "UD", "Update flag" },
	{ "AD", "Add flag or search term" }, { "SN", "Seen state" },
	{ "TP", "Typing state" }, { "AC", "Automatic-connect state" },
	{ "QU", "Conversation closed" },
	{ "AS", "Automatic-slot speed limit" },
	{ "AM", "Minimum automatic upload slots" },
	{ "FM", "Missing INF field" }, { "FB", "Invalid INF field" },
	{ "RD", "Redirect URL" }, { "ZL", "Compressed transfer flag" },
	{ "MO", "Minimum operator hubs" }, { "XU", "Maximum normal-user hubs" },
	{ "DM", "Modified time" }
}};

bool asciiEqualNoCase(string_view a, string_view b) {
	if(a.size() != b.size()) {
		return false;
	}
	for(size_t i = 0; i < a.size(); ++i) {
		const auto ac = static_cast<unsigned char>(a[i]);
		const auto bc = static_cast<unsigned char>(b[i]);
		if(std::tolower(ac) != std::tolower(bc)) {
			return false;
		}
	}
	return true;
}

bool asciiContainsNoCase(string_view value, string_view needle) {
	if(needle.empty() || needle.size() > value.size()) {
		return false;
	}
	for(size_t i = 0; i <= value.size() - needle.size(); ++i) {
		if(asciiEqualNoCase(value.substr(i, needle.size()), needle)) {
			return true;
		}
	}
	return false;
}

string_view trimAscii(string_view value) {
	while(!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
		value.remove_prefix(1);
	}
	while(!value.empty() && (value.back() == ' ' || value.back() == '\t')) {
		value.remove_suffix(1);
	}
	return value;
}

string_view trimProtocolEnd(string_view value) {
	while(!value.empty() &&
		(value.back() == '\r' || value.back() == '\n' || value.back() == '|'))
	{
		value.remove_suffix(1);
	}
	return value;
}

string bounded(string_view value, size_t limit = MAX_FIELD_VALUE_BYTES) {
	if(value.size() <= limit) {
		return string(value);
	}
	string result(value.substr(0, limit));
	result += "...";
	return result;
}

size_t validUtf8SequenceLength(string_view value, size_t offset) {
	const auto remaining = value.size() - offset;
	const auto first = static_cast<unsigned char>(value[offset]);
	auto continuation = [&](size_t index) {
		return index < remaining &&
			(static_cast<unsigned char>(value[offset + index]) & 0xc0U) == 0x80U;
	};

	if(first >= 0xc2U && first <= 0xdfU) {
		return continuation(1) ? 2U : 0U;
	}
	if(first >= 0xe0U && first <= 0xefU) {
		if(remaining < 3 || !continuation(1) || !continuation(2)) {
			return 0;
		}
		const auto second = static_cast<unsigned char>(value[offset + 1]);
		if((first == 0xe0U && second < 0xa0U) ||
			(first == 0xedU && second > 0x9fU))
		{
			return 0;
		}
		return 3;
	}
	if(first >= 0xf0U && first <= 0xf4U) {
		if(remaining < 4 || !continuation(1) || !continuation(2) ||
			!continuation(3))
		{
			return 0;
		}
		const auto second = static_cast<unsigned char>(value[offset + 1]);
		if((first == 0xf0U && second < 0x90U) ||
			(first == 0xf4U && second > 0x8fU))
		{
			return 0;
		}
		return 4;
	}
	return 0;
}

string sanitize(string_view value, size_t limit) {
	string result;
	result.reserve(std::min(limit, value.size()));
	bool truncated = false;
	for(size_t i = 0; i < value.size();) {
		const auto ch = static_cast<unsigned char>(value[i]);
		string replacement;
		size_t consumed = 1;
		if(ch == '\r') {
			replacement = "\\r";
		} else if(ch == '\n') {
			replacement = "\\n";
		} else if(ch == '\t') {
			replacement = "\\t";
		} else if(ch < 0x20U || ch == 0x7fU) {
			constexpr char hex[] = "0123456789ABCDEF";
			replacement = "\\x";
			replacement += hex[ch >> 4];
			replacement += hex[ch & 0x0f];
		} else if(ch < 0x80U) {
			replacement.assign(1, static_cast<char>(ch));
		} else {
			consumed = validUtf8SequenceLength(value, i);
			if(consumed) {
				replacement.assign(value.data() + i, consumed);
			} else {
				consumed = 1;
				constexpr char hex[] = "0123456789ABCDEF";
				replacement = "\\x";
				replacement += hex[ch >> 4];
				replacement += hex[ch & 0x0f];
			}
		}
		if(result.size() + replacement.size() > limit) {
			truncated = true;
			break;
		}
		result += replacement;
		i += consumed;
	}
	if(truncated) {
		result += "...";
	}
	return result;
}

void setSummary(Result& result, string value) {
	if(value.size() > MAX_SUMMARY_BYTES) {
		value.resize(MAX_SUMMARY_BYTES);
		value += "...";
	}
	result.summary = std::move(value);
}

void addWarning(Result& result, string warning, bool invalid = false) {
	if(result.warnings.size() < MAX_WARNINGS) {
		if(warning.size() > 256) {
			warning.resize(256);
		}
		result.warnings.emplace_back(std::move(warning));
	}
	if(invalid) {
		result.status = Status::Invalid;
	} else if(result.status == Status::Valid) {
		result.status = Status::Warning;
	}
}

void addField(Result& result, string code, string name, string value,
	bool sensitive = false)
{
	if(result.fields.size() >= MAX_FIELDS) {
		if(result.fields.size() == MAX_FIELDS) {
			addWarning(result, "Additional fields were omitted by the analyzer safety limit.");
		}
		return;
	}
	if(value.size() > MAX_FIELD_VALUE_BYTES) {
		value.resize(MAX_FIELD_VALUE_BYTES);
		value += "...";
		addWarning(result, "A decoded field exceeded the display limit and was truncated.");
	}
	result.fields.push_back(Field {
		sanitize(code, 128), sanitize(name, 256),
		sensitive ? string("<redacted>") : sanitize(value, MAX_FIELD_VALUE_BYTES),
		sensitive
	});
	result.sensitive = result.sensitive || sensitive;
}

const Definition* findDefinition(
	const Definition* first, const Definition* last, string_view command)
{
	const auto i = std::find_if(first, last, [command](const Definition& definition) {
		return command == definition.command;
	});
	return i == last ? nullptr : i;
}

const char* genericAdcFieldName(string_view code) {
	const auto i = std::find_if(ADC_FIELD_NAMES.begin(), ADC_FIELD_NAMES.end(),
		[code](const auto& entry) { return code == entry.first; });
	return i == ADC_FIELD_NAMES.end() ? "Extension field" : i->second;
}

const char* adcFieldName(const Result& result, string_view code) {
	const string_view action = result.action;

	// ADC reuses its two-character identifiers between commands and extensions.
	// Keep command-specific meanings here instead of forcing ambiguous labels into
	// the generic fallback table.
	if(action == "INF") {
		if(code == "MS") return "Minimum share";
		if(code == "MR") return "Minimum registered hubs";
		if(code == "MO") return "Minimum operator hubs";
		if(code == "MU") return "Minimum normal-user hubs";
		if(code == "XU") return "Maximum normal-user hubs";
		if(code == "FO") return "Failover hub addresses";
		if(code == "UP") return "Hub uptime";
		if(code == "SL") return "Total upload slots";
		if(code == "SU") return "Supported features";
		if(result.command == "CINF" && code == "PM") {
			return "Private-message connection";
		}
		if(result.command == "CINF" && code == "CO") {
			return "Connection count";
		}
	}
	if(action == "STA") {
		if(code == "FM") return "Missing required INF field";
		if(code == "FB") return "Invalid INF field";
		if(code == "FC") return "Related command";
	}
	if(action == "QUI") {
		if(code == "ID") return "Disconnect initiator SID";
		if(code == "MS") return "Message";
		if(code == "RD") return "Redirect URL";
		if(code == "TL") return "Reconnect delay";
	}
	if(action == "GET") {
		if(code == "RE") return "Recursive file-list request";
		if(code == "ZL") return "Compressed transfer requested";
		if(code == "TL") return "TTH list requested";
		if(code == "ID") return "Requester SID";
		if(code == "DB") return "Downloaded and verified bytes";
		if(code == "BK") return "Bloom sub-hash count (k)";
		if(code == "BH") return "Bloom sub-hash width (h, bits)";
	}
	if(action == "SND") {
		if(code == "ZL") return "Compressed transfer";
		if(code == "TL") return "TTH list included";
		if(code == "ID") return "Requester SID (GET-only)";
		if(code == "DB") return "Downloaded and verified bytes (GET-only)";
		if(code == "BK") return "Bloom sub-hash count (k, echoed)";
		if(code == "BH") return "Bloom sub-hash width (h, echoed)";
	}
	if(action == "CMD") {
		if(code == "CT") return "Command context";
		if(code == "CO") return "Constrained execution";
		if(code == "RM") return "Remove command";
		if(code == "TT") return "Command text";
		if(code == "SP") return "Separator";
	}
	if(action == "SCH") {
		if(code == "NO") return "Excluded term";
		if(code == "MR") return "Maximum results";
		if(code == "RE") return "Status reply requested";
		if(code == "AD") return "Additional search term";
		if(code == "RX") return "Excluded extension groups";
	}
	if(action == "RES") {
		if(code == "SL") return "Slots currently available";
		if(code == "FI") return "Recursive file count";
		if(code == "FO") return "Recursive folder count";
		if(code == "DM") return "Modified time";
	}
	if(action == "RSS") {
		if(code == "FN") return "Feed name or description";
		if(code == "RM") return "Remove feed";
	}
	if(action == "PBD") {
		if(code == "NO") return "Completion notification subscription";
		if(code == "RE") return "Reply flag";
		if(code == "AD") return "Add finished files";
		if(code == "UP") return "File completion update";
		if(code == "RM") return "Remove bundle association";
	}
	if(action == "UBD") {
		if(code == "FI") return "Bundle finished";
		if(code == "SU") return "Single-user bundle";
		if(code == "MU") return "Multi-user bundle";
		if(code == "RM") return "Remove bundle";
		if(code == "UD") return "Update bundle information";
		if(code == "AD") return "Add bundle";
		if(code == "CH") return "Change existing bundle";
	}
	if(action == "UBN" && code == "DS") {
		return "Current bundle speed";
	}
	if(action == "OID" || action == "OIR") {
		string_view service;
		const auto serviceField = std::find_if(result.fields.begin(),
			result.fields.end(), [](const Field& field) {
				return field.code == "service";
			});
		if(serviceField != result.fields.end()) {
			service = serviceField->value;
		}
		if(asciiEqualNoCase(service, "LoL")) {
			if(code == "SU") return "Summoner name";
			if(code == "SE") return "Region";
		}
		if((asciiEqualNoCase(service, "Google") ||
			asciiEqualNoCase(service, "mslive")) && code == "EM")
		{
			return "Email address";
		}
		return "Service-specific field";
	}
	if(action == "RFA") {
		if(code == "MS") return "Minimum share";
		if(code == "MR") return "Minimum registered hubs";
		if(code == "MO") return "Minimum operator hubs";
		if(code == "MU") return "Minimum normal-user hubs";
		if(code == "XU") return "Maximum normal-user hubs";
		if(code == "FO") return "Failover hub addresses";
		if(code == "UP") return "Hub uptime";
	}
	return genericAdcFieldName(code);
}

std::vector<string_view> split(string_view value, char delimiter, size_t maximum);

template<size_t Size>
const char* featureName(const std::array<FeatureDefinition, Size>& definitions,
	string_view code, bool ignoreCase = false)
{
	const auto i = std::find_if(definitions.begin(), definitions.end(),
		[code, ignoreCase](const FeatureDefinition& definition) {
			return ignoreCase ? asciiEqualNoCase(code, definition.code) :
				code == definition.code;
		});
	return i == definitions.end() ? nullptr : i->name;
}

string describeFeature(string_view code, const char* name) {
	string value = bounded(code, 64);
	if(name) {
		value += " (";
		value += name;
		value += ')';
	}
	return value;
}

string describeAdcFeatureList(string_view value) {
	const auto features = split(value, ',', MAX_FIELDS);
	string description;
	for(const auto feature : features) {
		if(!description.empty()) {
			description += ", ";
		}
		description += describeFeature(feature,
			featureName(ADC_FEATURE_DEFINITIONS, feature));
		if(description.size() > MAX_FIELD_VALUE_BYTES) {
			description.resize(MAX_FIELD_VALUE_BYTES);
			description += "...";
			break;
		}
	}
	return description;
}

bool isSensitiveAdcField(string_view code) {
	return code == "PD" || code == "KY";
}

bool isAdcAlpha(char ch) {
	return ch >= 'A' && ch <= 'Z';
}

bool isAdcAlphaNum(char ch) {
	return isAdcAlpha(ch) || (ch >= '0' && ch <= '9');
}

bool isBase32(string_view value) {
	return !value.empty() && std::all_of(value.begin(), value.end(), [](char ch) {
		return (ch >= 'A' && ch <= 'Z') || (ch >= '2' && ch <= '7');
	});
}

bool parseUnsigned(string_view value, uint64_t& number) {
	if(value.empty()) {
		return false;
	}
	uint64_t parsed = 0;
	for(char ch : value) {
		if(ch < '0' || ch > '9') {
			return false;
		}
		const auto digit = static_cast<uint64_t>(ch - '0');
		if(parsed > (std::numeric_limits<uint64_t>::max() - digit) / 10) {
			return false;
		}
		parsed = parsed * 10 + digit;
	}
	number = parsed;
	return true;
}

string formatBytes(uint64_t value) {
	static constexpr std::array<const char*, 5> units {{
		"bytes", "KiB", "MiB", "GiB", "TiB"
	}};
	double amount = static_cast<double>(value);
	size_t unit = 0;
	while(amount >= 1024.0 && unit + 1 < units.size()) {
		amount /= 1024.0;
		++unit;
	}
	std::ostringstream out;
	if(unit == 0) {
		out << value << ' ' << units[unit];
	} else {
		out.setf(std::ios::fixed);
		out.precision(2);
		out << amount << ' ' << units[unit];
	}
	return out.str();
}

std::vector<string_view> split(
	string_view value, char delimiter, size_t maximum = MAX_FIELDS + 16)
{
	std::vector<string_view> result;
	result.reserve(std::min(maximum, static_cast<size_t>(16)));
	size_t start = 0;
	while(start <= value.size() && result.size() < maximum) {
		const auto end = value.find(delimiter, start);
		result.push_back(value.substr(start,
			end == string_view::npos ? value.size() - start : end - start));
		if(end == string_view::npos) {
			break;
		}
		start = end + 1;
	}
	return result;
}

string decodeAdcValue(Result& result, string_view value) {
	string decoded;
	decoded.reserve(std::min(value.size(), MAX_FIELD_VALUE_BYTES));
	for(size_t i = 0; i < value.size() && decoded.size() < MAX_FIELD_VALUE_BYTES; ++i) {
		if(value[i] != '\\') {
			decoded += value[i];
			continue;
		}
		if(++i >= value.size()) {
			addWarning(result, "ADC value ends with an incomplete escape sequence.", true);
			decoded += '\\';
			break;
		}
		switch(value[i]) {
		case 's': decoded += ' '; break;
		case 'n': decoded += "\\n"; break;
		case '\\': decoded += '\\'; break;
		default:
			addWarning(result, "ADC value contains an unknown escape sequence.");
			decoded += '\\';
			decoded += value[i];
			break;
		}
	}
	return decoded;
}

void addMask(std::vector<Span>& masks, string_view whole, string_view value) {
	if(value.empty() || value.data() < whole.data() ||
		value.data() + value.size() > whole.data() + whole.size())
	{
		return;
	}
	masks.push_back(Span {
		static_cast<size_t>(value.data() - whole.data()), value.size()
	});
}

bool isCredentialLikeNmdcCommand(string_view command) {
	return command == "$MyPass" ||
		asciiContainsNoCase(command, "password") ||
		asciiContainsNoCase(command, "passwd") ||
		asciiContainsNoCase(command, "auth") ||
		asciiContainsNoCase(command, "credential");
}

void findAdcSecurityMasks(string_view raw, std::vector<Span>& masks) {
	size_t lineStart = 0;
	while(lineStart < raw.size()) {
		auto lineEnd = raw.find_first_of("\r\n", lineStart);
		if(lineEnd == string_view::npos) {
			lineEnd = raw.size();
		}
		auto line = raw.substr(lineStart, lineEnd - lineStart);
		while(!line.empty() && (line.front() == ' ' || line.front() == '\t')) {
			line.remove_prefix(1);
		}

		if(line.size() >= 4 && line.substr(1, 3) == "PAS") {
			const auto separator = line.find_first_of(" \t", 4);
			if(separator != string_view::npos) {
				addMask(masks, raw, trimAscii(line.substr(separator + 1)));
			}
		}

		size_t tokenStart = 0;
		while(tokenStart < line.size()) {
			while(tokenStart < line.size() &&
				(line[tokenStart] == ' ' || line[tokenStart] == '\t'))
			{
				++tokenStart;
			}
			auto tokenEnd = tokenStart;
			while(tokenEnd < line.size() &&
				line[tokenEnd] != ' ' && line[tokenEnd] != '\t')
			{
				++tokenEnd;
			}
			const auto token = line.substr(tokenStart, tokenEnd - tokenStart);
			if(token.size() > 2 && isSensitiveAdcField(token.substr(0, 2))) {
				addMask(masks, raw, token.substr(2));
			}
			tokenStart = tokenEnd;
		}

		lineStart = lineEnd;
		while(lineStart < raw.size() &&
			(raw[lineStart] == '\r' || raw[lineStart] == '\n'))
		{
			++lineStart;
		}
	}
}

void findNmdcSecurityMasks(string_view raw, std::vector<Span>& masks) {
	size_t frameStart = 0;
	while(frameStart < raw.size()) {
		auto frameEnd = raw.find('|', frameStart);
		if(frameEnd == string_view::npos) {
			frameEnd = raw.size();
		}
		auto frame = raw.substr(frameStart, frameEnd - frameStart);
		while(!frame.empty() &&
			(frame.front() == '\r' || frame.front() == '\n' ||
				frame.front() == ' ' || frame.front() == '\t'))
		{
			frame.remove_prefix(1);
		}
		if(!frame.empty() && frame.front() == '$') {
			size_t commandEnd = 1;
			while(commandEnd < frame.size() && frame[commandEnd] != ' ' &&
				frame[commandEnd] != '\t')
			{
				++commandEnd;
			}
			auto command = frame.substr(0, commandEnd);
			if(!command.empty() && command.back() == ':') {
				command.remove_suffix(1);
			}
			const auto parameters = commandEnd < frame.size() ?
				trimAscii(frame.substr(commandEnd + 1)) : string_view();
			if(isCredentialLikeNmdcCommand(command) ||
				command == "$Z" || command == "$ZOn")
			{
				addMask(masks, raw, parameters);
			}
			if(command == "$ZOn" && frameEnd < raw.size()) {
				addMask(masks, raw, raw.substr(frameEnd + 1));
				return;
			}
		}
		frameStart = frameEnd == raw.size() ? raw.size() : frameEnd + 1;
	}
}

string applyMasks(string_view raw, std::vector<Span> masks) {
	masks.erase(std::remove_if(masks.begin(), masks.end(), [raw](const Span& mask) {
		return mask.offset > raw.size() || mask.length > raw.size() - mask.offset;
	}), masks.end());
	string result(raw);
	std::sort(masks.begin(), masks.end(), [](const Span& a, const Span& b) {
		return a.offset < b.offset ||
			(a.offset == b.offset && a.length < b.length);
	});
	std::vector<Span> merged;
	merged.reserve(masks.size());
	for(const auto& mask : masks) {
		if(merged.empty() ||
			mask.offset > merged.back().offset + merged.back().length)
		{
			merged.push_back(mask);
			continue;
		}
		const auto maskEnd = mask.offset + mask.length;
		const auto mergedEnd = merged.back().offset + merged.back().length;
		if(maskEnd > mergedEnd) {
			merged.back().length = maskEnd - merged.back().offset;
		}
	}
	for(auto i = merged.rbegin(); i != merged.rend(); ++i) {
		const auto& mask = *i;
		if(mask.offset <= result.size() && mask.length <= result.size() - mask.offset) {
			result.replace(mask.offset, mask.length, "<redacted>");
		}
	}
	return sanitize(result, MAX_ANALYZER_INPUT_BYTES + 1024);
}

const char* routingName(char type) {
	switch(type) {
	case 'B': return "Broadcast";
	case 'C': return "Client-to-client TCP";
	case 'D': return "Direct";
	case 'E': return "Echo";
	case 'F': return "Feature broadcast";
	case 'H': return "To hub";
	case 'I': return "From hub";
	case 'U': return "Client-to-client UDP";
	default: return "Unknown";
	}
}

void validateAdcSid(Result& result, string_view sid, const char* label) {
	if(sid.size() != 4 || !isBase32(sid)) {
		addWarning(result, string(label) + " must be a four-character Base32 SID.", true);
	}
}

void parseAdcNamedFields(Result& result, string_view whole,
	const std::vector<string_view>& tokens, size_t start, std::vector<Span>& masks,
	bool forceSensitive = false)
{
	for(size_t i = start; i < tokens.size(); ++i) {
		const auto token = tokens[i];
		if(token.size() < 2 || !isAdcAlpha(token[0]) || !isAdcAlphaNum(token[1])) {
			if(forceSensitive) {
				addMask(masks, whole, token);
			}
			addWarning(result, "ADC named parameter has an invalid two-character field code.",
				true);
			addField(result, "", "Malformed parameter", bounded(token), forceSensitive);
			continue;
		}
		const auto code = token.substr(0, 2);
		const auto encoded = token.substr(2);
		const bool sensitive = forceSensitive || isSensitiveAdcField(code);
		if(sensitive) {
			addMask(masks, whole, encoded);
		}
		auto decoded = decodeAdcValue(result, encoded);
		if(result.action == "INF" && code == "SU") {
			decoded = describeAdcFeatureList(decoded);
		}
		addField(result, string(code), adcFieldName(result, code),
			std::move(decoded), sensitive);
	}
}

void parseAdcGenericParameters(Result& result, string_view whole,
	const std::vector<string_view>& tokens, size_t start, std::vector<Span>& masks)
{
	size_t positionalIndex = 1;
	for(size_t i = start; i < tokens.size(); ++i) {
		const auto token = tokens[i];
		if(token.size() >= 2 && isAdcAlpha(token[0]) && isAdcAlphaNum(token[1])) {
			const auto code = token.substr(0, 2);
			const auto encoded = token.substr(2);
			const bool sensitive = isSensitiveAdcField(code);
			if(sensitive) {
				addMask(masks, whole, encoded);
			}
			auto decoded = decodeAdcValue(result, encoded);
			if(result.action == "INF" && code == "SU") {
				decoded = describeAdcFeatureList(decoded);
			}
			addField(result, string(code), adcFieldName(result, code),
				std::move(decoded), sensitive);
		} else {
			addField(result, "arg" + std::to_string(positionalIndex),
				"Positional parameter " + std::to_string(positionalIndex),
				decodeAdcValue(result, token));
			++positionalIndex;
		}
	}
}

string firstFieldValue(const Result& result, string_view code) {
	const auto i = std::find_if(result.fields.begin(), result.fields.end(),
		[code](const Field& field) { return field.code == code; });
	return i == result.fields.end() ? string() : i->value;
}

void validateBloomTransferSemantics(Result& result, bool request,
	string_view type, string_view identifier, string_view start, string_view bytes)
{
	result.binaryPayloadType = "blom";
	result.name = request ? "Bloom filter request" : "Bloom filter response";

	if(type != "blom") {
		addWarning(result,
			"BLOM transfer type must use the exact lowercase token 'blom'.", true);
	}
	if((request && result.command != "IGET") ||
		(!request && result.command != "HSND"))
	{
		addWarning(result, request ?
			"BLOM requests must use the IGET hub-to-client message type." :
			"BLOM responses must use the HSND client-to-hub message type.", true);
	}
	if(identifier != "/") {
		addWarning(result, "BLOM transfers must use '/' as the namespace.", true);
	}
	uint64_t startNumber = 0;
	if(!parseUnsigned(start, startNumber) || startNumber != 0) {
		addWarning(result, "BLOM transfers must use zero as the start position.", true);
	}

	uint64_t byteCount = 0;
	const bool byteCountValid = parseUnsigned(bytes, byteCount);
	if(!byteCountValid) {
		addWarning(result,
			"BLOM byte count must be the unsigned filter size m / 8.", true);
	} else {
		if(byteCount % 8U != 0) {
			addWarning(result,
				"BLOM byte count must be divisible by 8 because m mod 64 is zero.",
				true);
		}
		if(byteCount <= std::numeric_limits<uint64_t>::max() / 8U) {
			addField(result, "m", "Bloom filter size (bits)",
				std::to_string(byteCount * 8U));
		} else {
			addWarning(result,
				"BLOM filter bit size overflows the supported integer range.", true);
		}
		if(byteCount <=
			static_cast<uint64_t>(std::numeric_limits<size_t>::max()))
		{
			result.expectedBinaryPayloadBytes = static_cast<size_t>(byteCount);
		} else {
			addWarning(result,
				"BLOM payload size exceeds the host addressable size.", true);
		}
		if(!request && byteCount != 0) {
			// Preserve this correlation hint even if another BLOM field is
			// malformed: suppressing opaque bytes is safer than decoding them.
			result.binaryPayloadFollows = true;
		}
	}

	size_t bkCount = 0;
	size_t bhCount = 0;
	uint64_t k = 0;
	uint64_t h = 0;
	bool kValid = false;
	bool hValid = false;
	for(const auto& field : result.fields) {
		if(field.code == "BK") {
			++bkCount;
			uint64_t parsed = 0;
			if(parseUnsigned(field.value, parsed) && parsed > 0) {
				k = parsed;
				kValid = true;
			} else {
				addWarning(result,
					"BLOM BK (k) must be a positive integer.", true);
			}
		} else if(field.code == "BH") {
			++bhCount;
			uint64_t parsed = 0;
			if(parseUnsigned(field.value, parsed) && parsed >= 1 && parsed <= 64) {
				h = parsed;
				hValid = true;
			} else {
				addWarning(result,
					"BLOM BH (h) must be an integer from 1 through 64.", true);
			}
		}
	}

	if(request && bkCount != 1) {
		addWarning(result,
			"BLOM GET requires exactly one BK sub-hash-count field.", true);
	}
	if(request && bhCount != 1) {
		addWarning(result,
			"BLOM GET requires exactly one BH sub-hash-width field.", true);
	}
	if(bkCount > 1 || bhCount > 1) {
		addWarning(result, "BLOM BK and BH fields must not be repeated.", true);
	}

	if(kValid && hValid &&
		(k > 192U / h))
	{
		addWarning(result,
			"BLOM requires k * h <= 192 bits for ADC Tiger hashes.", true);
	}
	if(byteCountValid && hValid &&
		byteCount <= std::numeric_limits<uint64_t>::max() / 8U)
	{
		const auto m = byteCount * 8U;
		if(h < 64U && m >= (uint64_t { 1 } << h)) {
			addWarning(result, "BLOM requires 2^h to be greater than m.", true);
		}
	}
}

void validateTransferSemantics(Result& result, bool request) {
	const auto type = firstFieldValue(result, "type");
	const auto identifier = firstFieldValue(result, "identifier");
	const auto start = firstFieldValue(result, "start");
	const auto bytes = firstFieldValue(result, "bytes");

	if(type == "list" &&
		(identifier.empty() || identifier.front() != '/' ||
			identifier.back() != '/'))
	{
		addWarning(result,
			"List transfer identifiers must begin and end with '/'.", true);
	}
	uint64_t startNumber = 0;
	if(!start.empty() && !parseUnsigned(start, startNumber)) {
		addWarning(result,
			"Transfer start position must be a non-negative integer.", true);
	}
	if(request && type == "list" && !start.empty() &&
		(!parseUnsigned(start, startNumber) || startNumber != 0))
	{
		addWarning(result, "List GET start position must be zero.", true);
	}
	uint64_t byteCount = 0;
	if(!bytes.empty() &&
		!((request && bytes == "-1") || parseUnsigned(bytes, byteCount)))
	{
		addWarning(result, request ?
			"GET byte count must be -1 or a non-negative integer." :
			"SND byte count must be a non-negative integer.", true);
	}

	for(const auto& field : result.fields) {
		if((field.code == "RE" || field.code == "TL" || field.code == "ZL") &&
			field.value != "1")
		{
			addWarning(result, field.code +
				" transfer flag must have the exact value 1.", true);
		}
		if(field.code == "RE" && (!request || type != "list")) {
			addWarning(result,
				"RE is valid only on GET requests for partial lists.", true);
		}
		if(field.code == "TL" && type != "list") {
			addWarning(result,
				"TL is valid only for partial-list GET/SND transfers.", true);
		}
		if((field.code == "DB" || field.code == "ID") && !request) {
			addWarning(result, field.code + " is valid only on GET requests.", true);
		}
		if(field.code == "DB" && request) {
			uint64_t downloadedBytes = 0;
			if(!parseUnsigned(field.value, downloadedBytes)) {
				addWarning(result,
					"GET downloaded-byte report must be an unsigned integer.", true);
			}
		}
		if(field.code == "ID" && request &&
			(field.value.size() != 4 || !isBase32(field.value)))
		{
			addWarning(result,
				"GET requester ID must be a four-character Base32 SID.", true);
		}
	}

	if(asciiEqualNoCase(type, "blom")) {
		validateBloomTransferSemantics(result, request, type, identifier, start, bytes);
	}
}

void buildAdcSummary(Result& result) {
	const auto prefix = result.routing.empty() ? string() : result.routing + " ";
	if(result.action == "INF") {
		string summary = prefix + "information";
		const auto name = firstFieldValue(result, "NI");
		const auto share = firstFieldValue(result, "SS");
		const auto files = firstFieldValue(result, "SF");
		if(!name.empty()) {
			summary += " for " + name;
		}
		uint64_t bytes = 0;
		if(parseUnsigned(share, bytes)) {
			summary += ", sharing " + formatBytes(bytes);
		}
		if(!files.empty()) {
			summary += " in " + files + " files";
		}
		setSummary(result, std::move(summary));
		return;
	}
	if(result.action == "SUP") {
		setSummary(result, prefix + "feature negotiation");
		return;
	}
	if(result.action == "MSG") {
		const auto text = firstFieldValue(result, "text");
		setSummary(result, prefix + (text.empty() ? "chat message" : "chat: " + text));
		return;
	}
	if(result.action == "SCH") {
		const auto term = firstFieldValue(result, "AN");
		const auto hash = firstFieldValue(result, "TR");
		setSummary(result, prefix + "search" +
			(!term.empty() ? " for " + term : (!hash.empty() ? " by hash " + hash : "")));
		return;
	}
	if(result.action == "RES") {
		const auto filename = firstFieldValue(result, "FN");
		const auto size = firstFieldValue(result, "SI");
		string summary = prefix + "search result";
		if(!filename.empty()) {
			summary += ": " + filename;
		}
		uint64_t bytes = 0;
		if(parseUnsigned(size, bytes)) {
			summary += " (" + formatBytes(bytes) + ")";
		}
		setSummary(result, std::move(summary));
		return;
	}
	if((result.action == "GET" || result.action == "SND") &&
		result.binaryPayloadType == "blom")
	{
		const auto bytes = firstFieldValue(result, "bytes");
		setSummary(result, prefix +
			(result.action == "GET" ? "bloom-filter request for " :
				"bloom-filter response; ") +
			(bytes.empty() ? "unknown" : bytes) +
			(result.action == "GET" ? " binary bytes" : " binary bytes follow"));
		return;
	}
	if(result.action == "STA") {
		const auto code = firstFieldValue(result, "code");
		const auto description = firstFieldValue(result, "description");
		setSummary(result, prefix + "status " + code +
			(description.empty() ? string() : ": " + description));
		return;
	}
	if(result.action == "CTM" || result.action == "RCM" ||
		result.action == "NAT" || result.action == "RNT")
	{
		const auto protocol = firstFieldValue(result, "protocol");
		const auto port = firstFieldValue(result, "port");
		setSummary(result, prefix + result.name +
			(protocol.empty() ? string() : " using " + protocol) +
			(port.empty() ? string() : " on port " + port));
		return;
	}
	setSummary(result, prefix + (result.name.empty() ? result.action : result.name));
}

Result analyzeAdc(string_view raw) {
	Result result;
	result.family = "ADC";

	if(raw.empty() || raw == "\n") {
		result.command = "KEEPALIVE";
		result.action = result.command;
		result.name = "Keep-alive";
		result.category = "Control";
		result.routing = "Connection";
		result.summary = "ADC keep-alive";
		result.safeMessage = "\\n";
		return result;
	}

	std::vector<Span> masks;
	if(raw.size() > MAX_ANALYZER_INPUT_BYTES) {
		raw = raw.substr(0, MAX_ANALYZER_INPUT_BYTES);
		addWarning(result, "Message exceeded the analyzer input limit and was truncated.", true);
	}
	findAdcSecurityMasks(raw, masks);
	auto body = trimProtocolEnd(raw);
	const auto additionalFrame = body.find_first_of("\r\n");
	if(additionalFrame != string_view::npos) {
		body = body.substr(0, additionalFrame);
		addWarning(result,
			"Additional ADC frames were retained in raw output but not merged into this row.");
	}
	if(body.size() < 4) {
		result.command = sanitize(body, 16);
		result.action = result.command;
		result.name = "Malformed ADC message";
		result.category = "Malformed";
		result.routing = "Unknown";
		result.known = false;
		addWarning(result, "ADC messages require a routing type and three-character action.",
			true);
		setSummary(result, "Malformed ADC message");
		result.safeMessage = applyMasks(raw, std::move(masks));
		return result;
	}

	const char type = body[0];
	if(string_view("BCDEFHIU").find(type) == string_view::npos) {
		addWarning(result, "Unknown ADC routing type.", true);
	}
	result.routing = routingName(type);
	const auto action = body.substr(1, 3);
	if(!isAdcAlpha(action[0]) || !isAdcAlphaNum(action[1]) ||
		!isAdcAlphaNum(action[2]))
	{
		addWarning(result, "ADC action must be three uppercase alphanumeric characters.",
			true);
	}
	result.action = sanitize(action, 16);
	result.command = sanitize(body.substr(0, 4), 16);

	const auto definition = findDefinition(
		ADC_DEFINITIONS.data(), ADC_DEFINITIONS.data() + ADC_DEFINITIONS.size(), action);
	if(definition) {
		result.name = definition->name;
		result.category = definition->category;
	} else {
		result.name = "Unknown ADC action";
		result.category = "Unknown";
		result.known = false;
		addWarning(result, "Unknown ADC action; preserved using generic structural decoding.");
	}

	string_view parameters;
	if(body.size() > 4) {
		if(body[4] != ' ') {
			addWarning(result, "ADC header is not followed by a single space.", true);
			parameters = body.substr(4);
		} else {
			parameters = body.substr(5);
		}
	}
	auto tokens = split(parameters, ' ');
	if(parameters.empty()) {
		tokens.clear();
	}
	if(std::any_of(tokens.begin(), tokens.end(),
		[](string_view token) { return token.empty(); }))
	{
		addWarning(result, "ADC parameters contain an empty field or repeated separator.",
			true);
	}

	size_t index = 0;
	if(type == 'B') {
		if(index >= tokens.size()) {
			addWarning(result, "Broadcast ADC message is missing the sender SID.", true);
		} else {
			validateAdcSid(result, tokens[index], "Sender");
			addField(result, "SID", "Sender SID", bounded(tokens[index++]));
		}
	} else if(type == 'D' || type == 'E') {
		if(tokens.size() - index < 2) {
			addWarning(result, "Direct/echo ADC message requires sender and target SIDs.", true);
			index = tokens.size();
		} else {
			validateAdcSid(result, tokens[index], "Sender");
			addField(result, "SID", "Sender SID", bounded(tokens[index++]));
			validateAdcSid(result, tokens[index], "Target");
			addField(result, "SID", "Target SID", bounded(tokens[index++]));
		}
	} else if(type == 'F') {
		if(index >= tokens.size()) {
			addWarning(result, "Feature-broadcast ADC message is missing the sender SID.",
				true);
		} else {
			validateAdcSid(result, tokens[index], "Sender");
			addField(result, "SID", "Sender SID", bounded(tokens[index++]));
		}
		while(index < tokens.size() && tokens[index].size() == 5 &&
			(tokens[index][0] == '+' || tokens[index][0] == '-'))
		{
			const auto feature = tokens[index++];
			const auto code = feature.substr(1);
			const auto name = featureName(ADC_FEATURE_DEFINITIONS, code);
			addField(result, string(1, feature[0]), feature[0] == '+' ?
				(name ? string("Required feature — ") + name : "Required feature") :
				(name ? string("Excluded feature — ") + name : "Excluded feature"),
				bounded(code));
		}
	} else if(type == 'U') {
		if(index >= tokens.size()) {
			addWarning(result, "UDP ADC message is missing the sender CID.", true);
		} else {
			if(!isBase32(tokens[index])) {
				addWarning(result, "UDP sender CID is not valid Base32.", true);
			}
			addField(result, "CID", "Sender CID", bounded(tokens[index++]));
		}
	}

	auto require = [&](size_t count, const char* message) {
		if(tokens.size() - index < count) {
			addWarning(result, message, true);
			return false;
		}
		return true;
	};
	auto positional = [&](const char* code, const char* name, bool sensitive = false) {
		if(index >= tokens.size()) {
			return;
		}
		const auto token = tokens[index++];
		if(sensitive) {
			addMask(masks, raw, token);
		}
		addField(result, code, name, decodeAdcValue(result, token), sensitive);
	};

	if(action == "STA") {
		if(require(2, "STA requires a status code and description.")) {
			positional("code", "Status code");
			positional("description", "Description");
		}
		parseAdcNamedFields(result, raw, tokens, index, masks);
	} else if(action == "SUP") {
		for(; index < tokens.size(); ++index) {
			const auto feature = tokens[index];
			if(feature.size() != 6 ||
				(feature.substr(0, 2) != "AD" && feature.substr(0, 2) != "RM"))
			{
				addWarning(result, "SUP feature must use AD/RM followed by a FOURCC.", true);
			}
			const auto operation = feature.substr(0, std::min<size_t>(2, feature.size()));
			const auto code = feature.size() > 2 ? feature.substr(2) : string_view();
			const auto name = featureName(ADC_FEATURE_DEFINITIONS, code);
			addField(result, bounded(operation),
				operation == "RM" ?
					(name ? string("Removed feature — ") + name : "Removed feature") :
					(name ? string("Added feature — ") + name : "Added feature"),
				bounded(code));
		}
	} else if(action == "SID") {
		if(require(1, "SID requires one session identifier.")) {
			validateAdcSid(result, tokens[index], "Assigned");
			positional("SID", "Assigned SID");
		}
		parseAdcNamedFields(result, raw, tokens, index, masks);
	} else if(action == "INF" || action == "SCH" || action == "RES" ||
		action == "PSR" || action == "PBD" || action == "TCP" ||
		action == "UBD" || action == "UBN" || action == "RFA")
	{
		parseAdcNamedFields(result, raw, tokens, index, masks);
	} else if(action == "MSG") {
		if(require(1, "MSG requires message text.")) {
			positional("text", "Message text");
		}
		parseAdcNamedFields(result, raw, tokens, index, masks);
	} else if(action == "CTM" || action == "NAT" || action == "RNT") {
		if(require(3, "CTM/NAT/RNT requires protocol, port, and token.")) {
			positional("protocol", "Protocol");
			positional("port", "Port");
			positional("token", "Token");
		}
		parseAdcNamedFields(result, raw, tokens, index, masks);
	} else if(action == "RCM") {
		if(require(2, "RCM requires protocol and token.")) {
			positional("protocol", "Protocol");
			positional("token", "Token");
		}
		parseAdcNamedFields(result, raw, tokens, index, masks);
	} else if(action == "GPA") {
		if(require(1, "GPA requires challenge data.")) {
			positional("challenge", "Challenge");
		}
		parseAdcNamedFields(result, raw, tokens, index, masks);
	} else if(action == "PAS") {
		if(require(1, "PAS requires password-response data.")) {
			positional("response", "Password response", true);
		}
		parseAdcNamedFields(result, raw, tokens, index, masks, true);
	} else if(action == "QUI") {
		if(require(1, "QUI requires a SID.")) {
			validateAdcSid(result, tokens[index], "Disconnected");
			positional("SID", "Disconnected SID");
		}
		parseAdcNamedFields(result, raw, tokens, index, masks);
	} else if(action == "GET" || action == "SND") {
		if(require(4, "GET/SND requires type, identifier, start, and byte count.")) {
			positional("type", "Transfer type");
			positional("identifier", "Identifier");
			positional("start", "Start position");
			positional("bytes", "Byte count");
		}
		parseAdcNamedFields(result, raw, tokens, index, masks);
		validateTransferSemantics(result, action == "GET");
	} else if(action == "GFI") {
		if(require(2, "GFI requires type and identifier.")) {
			positional("type", "Transfer type");
			positional("identifier", "Identifier");
		}
		parseAdcNamedFields(result, raw, tokens, index, masks);
	} else if(action == "CMD") {
		if(require(1, "CMD requires a display name.")) {
			positional("name", "Display name");
		}
		parseAdcNamedFields(result, raw, tokens, index, masks);
	} else if(action == "RSS") {
		if(require(1, "RSS requires a feed URL.")) {
			positional("url", "Feed URL");
		}
		parseAdcNamedFields(result, raw, tokens, index, masks);
	} else if(action == "OID" || action == "OIR") {
		if(require(1, "OID/OIR requires an online-service name.")) {
			positional("service", "Online service");
		}
		parseAdcNamedFields(result, raw, tokens, index, masks);
	} else if(action == "TPN") {
		if(require(1, "TPN requires a typing-state code.")) {
			positional("state", "Typing-state code");
		}
		parseAdcNamedFields(result, raw, tokens, index, masks);
	} else if(action == "ZON" || action == "ZOF" || action == "GFA") {
		parseAdcNamedFields(result, raw, tokens, index, masks);
	} else {
		parseAdcGenericParameters(result, raw, tokens, index, masks);
	}

	buildAdcSummary(result);
	result.safeMessage = applyMasks(raw, std::move(masks));
	return result;
}

string decodeNmdcText(string_view value) {
	string result;
	result.reserve(std::min(value.size(), MAX_FIELD_VALUE_BYTES));
	for(size_t i = 0; i < value.size() && result.size() < MAX_FIELD_VALUE_BYTES; ++i) {
		if(value.compare(i, 5, "&#36;") == 0) {
			result += '$';
			i += 4;
		} else if(value.compare(i, 7, "&#124;") == 0) {
			result += '|';
			i += 6;
		} else if(value.compare(i, 5, "&amp;") == 0) {
			result += '&';
			i += 4;
		} else if(value.compare(i, 10, "/%DCN036%/") == 0) {
			result += '$';
			i += 9;
		} else if(value.compare(i, 10, "/%DCN124%/") == 0) {
			result += '|';
			i += 9;
		} else {
			result += value[i];
		}
	}
	return result;
}

string decodeNmdcSearchPattern(string_view value) {
	string separated;
	separated.reserve(std::min(value.size(), MAX_FIELD_VALUE_BYTES));
	for(const char ch : value) {
		if(separated.size() >= MAX_FIELD_VALUE_BYTES) {
			break;
		}
		// Literal dollar signs delimit words in NMDC searches. Escaped dollar
		// entities remain intact here and are decoded to literal '$' below.
		separated += ch == '$' ? ' ' : ch;
	}
	return decodeNmdcText(separated);
}

void genericNmdcParameters(Result& result, string_view parameters);

std::vector<string_view> splitDoubleDollar(string_view value) {
	std::vector<string_view> result;
	result.reserve(8);
	size_t start = 0;
	while(start <= value.size() && result.size() < MAX_FIELDS) {
		const auto end = value.find("$$", start);
		result.push_back(value.substr(start,
			end == string_view::npos ? value.size() - start : end - start));
		if(end == string_view::npos) {
			break;
		}
		start = end + 2;
	}
	return result;
}

const char* nmdcRuleFieldName(string_view command, string_view code) {
	if(code == "Min") {
		return command == "$SearchRule" ? "Minimum search length" :
			"Minimum nickname length";
	}
	if(code == "Max") {
		return command == "$SearchRule" ? "Maximum search command length" :
			"Maximum nickname length";
	}
	if(code == "Char") return "Forbidden character codes";
	if(code == "Pref") return "Required nickname prefixes";
	if(code == "Num") return "Searches per interval";
	if(code == "Int") return "Active-search interval";
	if(code == "IntPas") return "Passive-search interval";
	if(code == "Share") return "Minimum share size";
	return "Rule parameter";
}

void parseNmdcRule(Result& result, string_view command, string_view parameters) {
	const auto clauses = splitDoubleDollar(trimAscii(parameters));
	for(const auto clause : clauses) {
		if(clause.empty()) {
			addWarning(result, "Rule command contains an empty clause.");
			continue;
		}
		const auto separator = clause.find(' ');
		const auto code = clause.substr(0, separator);
		const auto value = separator == string_view::npos ? string_view() :
			trimAscii(clause.substr(separator + 1));
		if(value.empty() && command != "$BadNick") {
			addWarning(result, "Rule clause is missing its value.");
		}
		addField(result, bounded(code, 32), nmdcRuleFieldName(command, code),
			decodeNmdcText(value));
	}
	setSummary(result, result.name + ": " + std::to_string(result.fields.size()) +
		" rule" + (result.fields.size() == 1 ? "" : "s"));
}

void parseNmdcShortTthSearch(Result& result, string_view command,
	string_view parameters)
{
	const auto values = split(trimAscii(parameters), ' ', 4);
	if(values.size() < 2 || values[0].empty() || values[1].empty()) {
		addWarning(result, "Short TTH search requires a hash and requester.", true);
		genericNmdcParameters(result, parameters);
		return;
	}
	addField(result, "TTH", "Tiger tree hash", bounded(values[0]));
	addField(result, command == "$SA" ? "endpoint" : "nick",
		command == "$SA" ? "Active endpoint" : "Passive requester",
		decodeNmdcText(values[1]));
	if(values[0].size() != 39 || !isBase32(values[0])) {
		addWarning(result, "Short TTH search hash must be 39 Base32 characters.", true);
	}
	if(values.size() > 2) {
		addWarning(result, "Short TTH search contains unexpected additional parameters.");
	}
	setSummary(result, string(command == "$SA" ? "Active" : "Passive") +
		" short TTH search for " + bounded(values[0], 64));
}

void parseNmdcUrlCommand(Result& result, string_view command,
	string_view parameters)
{
	const auto value = trimAscii(parameters);
	if(command == "$GetHubURL") {
		if(!value.empty()) {
			addWarning(result, "$GetHubURL should not contain parameters.");
			genericNmdcParameters(result, value);
		}
		setSummary(result, result.name);
		return;
	}
	if(value.empty()) {
		addWarning(result, "URL command is missing its URL.", true);
		setSummary(result, result.name);
		return;
	}
	addField(result, "url", "URL", decodeNmdcText(value));
	if((command == "$SetIcon" || command == "$SetLogo") &&
		value.substr(0, 7) != "http://" && value.substr(0, 8) != "https://")
	{
		addWarning(result, "Hub image URL should use HTTP or HTTPS.");
	}
	setSummary(result, result.name + ": " + decodeNmdcText(value));
}

void genericNmdcParameters(Result& result, string_view parameters) {
	parameters = trimAscii(parameters);
	if(!parameters.empty()) {
		addField(result, "params", "Parameters", decodeNmdcText(parameters));
	}
}

void parseNmdcMyInfo(Result& result, string_view parameters) {
	auto value = trimAscii(parameters);
	if(value.substr(0, 5) != "$ALL ") {
		addWarning(result, "$MyINFO does not begin with the required $ALL marker.", true);
		genericNmdcParameters(result, value);
		return;
	}
	value.remove_prefix(5);
	const auto nickEnd = value.find(' ');
	if(nickEnd == string_view::npos) {
		addWarning(result, "$MyINFO is missing its structured information fields.", true);
		addField(result, "nick", "Nickname", decodeNmdcText(value));
		return;
	}
	addField(result, "nick", "Nickname", decodeNmdcText(value.substr(0, nickEnd)));
	value.remove_prefix(nickEnd + 1);
	const auto segments = split(value, '$', 12);
	if(!segments.empty()) {
		addField(result, "description", "Description", decodeNmdcText(segments[0]));
	}
	if(segments.size() > 2) {
		addField(result, "connection", "Connection and status",
			decodeNmdcText(trimAscii(segments[2])));
	}
	if(segments.size() > 3) {
		addField(result, "email", "Email", decodeNmdcText(segments[3]));
	}
	if(segments.size() > 4) {
		addField(result, "share", "Share size", decodeNmdcText(segments[4]));
	}
	if(segments.size() < 5) {
		addWarning(result, "$MyINFO contains fewer fields than the documented form.");
	}
	const auto nick = firstFieldValue(result, "nick");
	const auto share = firstFieldValue(result, "share");
	uint64_t bytes = 0;
	string summary = "User information for " + (nick.empty() ? string("[unknown]") : nick);
	if(parseUnsigned(share, bytes)) {
		summary += ", sharing " + formatBytes(bytes);
	}
	setSummary(result, std::move(summary));
}

void parseNmdcSearch(Result& result, string_view parameters) {
	parameters = trimAscii(parameters);
	const auto separator = parameters.find(' ');
	if(separator == string_view::npos) {
		addWarning(result, "$Search requires requester and search expression.", true);
		genericNmdcParameters(result, parameters);
		return;
	}
	const auto requester = parameters.substr(0, separator);
	const auto expression = parameters.substr(separator + 1);
	addField(result, "requester", requester.substr(0, 4) == "Hub:" ?
		"Passive requester" : "Active endpoint", bounded(requester));
	const auto parts = split(expression, '?', 6);
	if(parts.size() != 5) {
		addWarning(result, "$Search expression must contain five question-mark fields.",
			true);
		addField(result, "expression", "Search expression", decodeNmdcText(expression));
	} else {
		addField(result, "restricted", "Size restricted", bounded(parts[0]));
		addField(result, "maximum", "Maximum-size comparison", bounded(parts[1]));
		addField(result, "size", "Size", bounded(parts[2]));
		addField(result, "type", "Data type", bounded(parts[3]));
		addField(result, "pattern", "Search pattern",
			decodeNmdcSearchPattern(parts[4]));
	}
	const auto pattern = firstFieldValue(result, "pattern");
	setSummary(result, string(requester.substr(0, 4) == "Hub:" ? "Passive" : "Active") +
		" search" + (pattern.empty() ? string() : " for " + pattern));
}

const char* nmdcTransferOptionName(string_view command, string_view code) {
	if(code == "ZL") {
		return command == "$ADCGET" ? "Compressed transfer requested" :
			"Compressed transfer";
	}
	if(code == "RE") return "Recursive file-list request";
	if(code == "DB") {
		return command == "$ADCGET" ? "Downloaded and verified bytes" :
			"Downloaded and verified bytes (ADCGET-only)";
	}
	if(code == "TL") {
		return command == "$ADCGET" ? "TTH list requested" :
			"TTH list included";
	}
	if(code == "ID") {
		return command == "$ADCGET" ? "Requester SID" :
			"Requester SID (ADCGET-only)";
	}
	return genericAdcFieldName(code);
}

std::vector<string> parseNmdcAdcParameters(Result& result,
	string_view parameters)
{
	std::vector<string> tokens;
	tokens.reserve(8);
	string current;
	bool limitWarningAdded = false;
	for(size_t i = 0; i < parameters.size(); ++i) {
		const char ch = parameters[i];
		if(ch == '\\') {
			if(++i >= parameters.size()) {
				addWarning(result,
					"ADC transfer parameter ends with an incomplete escape sequence.",
					true);
				current += '\\';
				break;
			}
			switch(parameters[i]) {
			case 's': current += ' '; break;
			case 'n': current += '\n'; break;
			case '\\': current += '\\'; break;
			case ' ':
				// Legacy $ADCGET form retained by DC++ and AirDC++ parsers.
				current += ' ';
				break;
			default:
				addWarning(result,
					"ADC transfer parameter contains an unknown ADC escape sequence.",
					true);
				current += '\\';
				current += parameters[i];
				break;
			}
			continue;
		}
		if(ch == ' ') {
			if(current.empty()) {
				addWarning(result,
					"ADC transfer parameters contain an empty field or repeated separator.",
					true);
			}
			if(tokens.size() < MAX_FIELDS + 16) {
				tokens.emplace_back(std::move(current));
				current.clear();
			} else if(!limitWarningAdded) {
				addWarning(result,
					"Additional ADC transfer parameters were omitted by the analyzer safety limit.");
				limitWarningAdded = true;
			}
			continue;
		}
		if(current.size() < MAX_FIELD_VALUE_BYTES) {
			current += ch;
		}
	}
	if(!current.empty() || !parameters.empty()) {
		if(current.empty() && !parameters.empty() && parameters.back() == ' ') {
			addWarning(result,
				"ADC transfer parameters contain a trailing empty field.", true);
		}
		if(tokens.size() < MAX_FIELDS + 16) {
			tokens.emplace_back(std::move(current));
		} else if(!limitWarningAdded) {
			addWarning(result,
				"Additional ADC transfer parameters were omitted by the analyzer safety limit.");
		}
	}
	return tokens;
}

void parseNmdcTransfer(Result& result, string_view command,
	string_view parameters)
{
	const auto tokens = parseNmdcAdcParameters(result, parameters);
	static constexpr std::array<const char*, 4> names {{
		"Transfer type", "Identifier", "Start position", "Byte count"
	}};
	static constexpr std::array<const char*, 4> codes {{
		"type", "identifier", "start", "bytes"
	}};
	for(size_t i = 0; i < tokens.size() && i < names.size(); ++i) {
		addField(result, codes[i], names[i], tokens[i]);
	}
	for(size_t i = names.size(); i < tokens.size(); ++i) {
		const string_view option = tokens[i];
		if(option.size() < 2 || !isAdcAlpha(option[0]) ||
			!isAdcAlphaNum(option[1]))
		{
			addWarning(result,
				"ADC transfer option has an invalid two-character field code.");
			addField(result, "option", "Transfer option", string(option));
			continue;
		}
		const auto code = option.substr(0, 2);
		addField(result, string(code), nmdcTransferOptionName(command, code),
			string(option.substr(2)));
	}
	if(tokens.size() < 4) {
		addWarning(result, "Transfer command requires type, identifier, start, and byte count.",
			true);
	}
	validateTransferSemantics(result, command == "$ADCGET");
	const auto identifier = firstFieldValue(result, "identifier");
	setSummary(result, result.name + (identifier.empty() ? string() : ": " + identifier));
}

void addNmdcSlots(Result& result, string_view value) {
	const auto slash = value.find('/');
	if(slash == string_view::npos || slash == 0 || slash + 1 >= value.size()) {
		addWarning(result, "$SR slot count must use free/total form.", true);
		addField(result, "slots", "Slot count", bounded(value));
		return;
	}
	addField(result, "free", "Free slots", bounded(value.substr(0, slash)));
	addField(result, "total", "Total slots", bounded(value.substr(slash + 1)));
	uint64_t freeSlots = 0;
	uint64_t totalSlots = 0;
	if(!parseUnsigned(value.substr(0, slash), freeSlots) ||
		!parseUnsigned(value.substr(slash + 1), totalSlots))
	{
		addWarning(result, "$SR slot counts must be unsigned integers.", true);
	} else if(freeSlots > totalSlots) {
		addWarning(result, "$SR free slots cannot exceed total slots.", true);
	}
}

void validateNmdcSearchResultEndpoint(Result& result, string_view endpoint) {
	endpoint = trimAscii(endpoint);
	if(endpoint.empty()) {
		addWarning(result, "$SR hub endpoint is empty.", true);
		return;
	}

	string_view host = endpoint;
	string_view port;
	if(endpoint.front() == '[') {
		const auto close = endpoint.find(']');
		if(close == string_view::npos || close == 1) {
			addWarning(result, "$SR contains an invalid bracketed hub address.", true);
			return;
		}
		host = endpoint.substr(1, close - 1);
		if(close + 1 < endpoint.size()) {
			if(endpoint[close + 1] != ':') {
				addWarning(result,
					"$SR bracketed hub address has an invalid port separator.",
					true);
				return;
			}
			port = endpoint.substr(close + 2);
		}
	} else {
		const auto firstColon = endpoint.find(':');
		if(firstColon != string_view::npos &&
			endpoint.find(':', firstColon + 1) == string_view::npos)
		{
			host = endpoint.substr(0, firstColon);
			port = endpoint.substr(firstColon + 1);
		}
	}
	if(host.empty()) {
		addWarning(result, "$SR hub endpoint host is empty.", true);
	}
	if(!port.empty()) {
		uint64_t portNumber = 0;
		if(!parseUnsigned(port, portNumber) ||
			portNumber == 0 || portNumber > 65535)
		{
			addWarning(result,
				"$SR hub endpoint port must be an integer from 1 to 65535.",
				true);
		}
	} else if((endpoint.back() == ':') ||
		(endpoint.size() >= 2 && endpoint.substr(endpoint.size() - 2) == "]:"))
	{
		addWarning(result, "$SR hub endpoint port is empty.", true);
	}
}

void parseNmdcSearchResult(Result& result, string_view parameters) {
	const auto chunks = split(trimAscii(parameters), '\x05', 8);
	if(chunks.size() < 2 || chunks[0].empty()) {
		addWarning(result, "$SR is missing its structured result fields.", true);
		genericNmdcParameters(result, parameters);
		setSummary(result, "Malformed search result");
		return;
	}

	const auto sourceEnd = chunks[0].find(' ');
	if(sourceEnd == string_view::npos) {
		addWarning(result, "$SR is missing its source nickname or result.", true);
		addField(result, "source", "Source nickname", decodeNmdcText(chunks[0]));
		setSummary(result, "Malformed search result");
		return;
	}
	addField(result, "source", "Source nickname",
		decodeNmdcText(chunks[0].substr(0, sourceEnd)));
	auto resultPart = trimAscii(chunks[0].substr(sourceEnd + 1));
	if(sourceEnd == 0 || resultPart.empty()) {
		addWarning(result,
			"$SR source nickname and result name must not be empty.", true);
	}

	bool directoryResult = false;
	const auto lastSpace = resultPart.rfind(' ');
	if(lastSpace != string_view::npos &&
		resultPart.substr(lastSpace + 1).find('/') != string_view::npos)
	{
		directoryResult = true;
		addField(result, "result", "Directory name",
			decodeNmdcText(resultPart.substr(0, lastSpace)));
		addNmdcSlots(result, resultPart.substr(lastSpace + 1));
	} else {
		addField(result, "result", "File name", decodeNmdcText(resultPart));
	}

	size_t hubIndex = 1;
	if(!directoryResult) {
		const auto metadata = trimAscii(chunks[1]);
		const auto slotSpace = metadata.rfind(' ');
		if(slotSpace == string_view::npos) {
			addWarning(result, "$SR file result is missing size or slot counts.", true);
			addField(result, "metadata", "File result metadata",
				decodeNmdcText(metadata));
		} else {
			const auto size = trimAscii(metadata.substr(0, slotSpace));
			addField(result, "size", "File size", bounded(size));
			uint64_t fileSize = 0;
			if(!parseUnsigned(size, fileSize)) {
				addWarning(result, "$SR file size must be an unsigned integer.", true);
			}
			addNmdcSlots(result, trimAscii(metadata.substr(slotSpace + 1)));
		}
		hubIndex = 2;
	}

	if(hubIndex >= chunks.size()) {
		addWarning(result, "$SR is missing hub or TTH information.", true);
	} else {
		auto hubInfo = trimAscii(chunks[hubIndex]);
		string_view endpoint;
		const auto endpointStart = hubInfo.rfind(" (");
		if(endpointStart != string_view::npos && !hubInfo.empty() &&
			hubInfo.back() == ')')
		{
			endpoint = hubInfo.substr(endpointStart + 2,
				hubInfo.size() - endpointStart - 3);
			hubInfo = hubInfo.substr(0, endpointStart);
		}
		if(hubInfo.substr(0, 4) == "TTH:") {
			const auto hash = hubInfo.substr(4);
			addField(result, "TTH", "Tiger tree hash", bounded(hash));
			if(hash.size() != 39 || !isBase32(hash)) {
				addWarning(result,
					"$SR Tiger tree hash must be 39 Base32 characters.", true);
			}
		} else {
			addField(result, "hub", "Hub name", decodeNmdcText(hubInfo));
			if(hubInfo.empty()) {
				addWarning(result, "$SR hub name must not be empty.", true);
			}
		}
		if(!endpoint.empty()) {
			addField(result, "hub_endpoint", "Hub endpoint",
				decodeNmdcText(endpoint));
			validateNmdcSearchResultEndpoint(result, endpoint);
		} else {
			addWarning(result, "$SR is missing its hub endpoint.", true);
		}
	}

	if(hubIndex + 1 < chunks.size()) {
		if(chunks[hubIndex + 1].empty()) {
			addWarning(result,
				"$SR contains an explicit empty passive target nickname.", true);
		} else {
			addField(result, "target", "Passive target nickname",
				decodeNmdcText(chunks[hubIndex + 1]));
		}
	}
	if(hubIndex + 2 < chunks.size()) {
		addWarning(result, "$SR contains unexpected additional fields.");
	}
	setSummary(result, "Search result from " + firstFieldValue(result, "source") +
		": " + firstFieldValue(result, "result"));
}

constexpr unsigned NMDC_ENDPOINT_TLS = 1U;
constexpr unsigned NMDC_ENDPOINT_NAT_INITIATOR = 2U;
constexpr unsigned NMDC_ENDPOINT_NAT_RESPONDER = 4U;

unsigned parseNmdcConnectionEndpoint(Result& result, string_view value) {
	auto endpoint = value;
	string_view flags;
	const auto colon = endpoint.rfind(':');
	unsigned parsedFlags = 0;
	if(colon == string_view::npos || colon + 1 == endpoint.size()) {
		addWarning(result, "$ConnectToMe endpoint must contain a host and port.", true);
	} else {
		size_t flagStart = colon + 1;
		while(flagStart < endpoint.size() &&
			endpoint[flagStart] >= '0' && endpoint[flagStart] <= '9')
		{
			++flagStart;
		}
		flags = endpoint.substr(flagStart);
		endpoint = endpoint.substr(0, flagStart);
		const auto host = endpoint.substr(0, colon);
		const auto port = endpoint.substr(colon + 1);
		uint64_t portNumber = 0;
		if(host.empty()) {
			addWarning(result, "$ConnectToMe endpoint host is empty.", true);
		}
		if(!parseUnsigned(port, portNumber) ||
			portNumber == 0 || portNumber > 65535)
		{
			addWarning(result,
				"$ConnectToMe endpoint port must be an integer from 1 to 65535.",
				true);
		}
	}
	addField(result, "endpoint", "Sender endpoint", decodeNmdcText(endpoint));
	for(const char flag : flags) {
		unsigned bit = 0;
		switch(flag) {
		case 'S':
			bit = NMDC_ENDPOINT_TLS;
			break;
		case 'N':
			bit = NMDC_ENDPOINT_NAT_INITIATOR;
			break;
		case 'R':
			bit = NMDC_ENDPOINT_NAT_RESPONDER;
			break;
		default:
			addWarning(result, "Unknown $ConnectToMe endpoint suffix.", true);
			break;
		}
		if(bit != 0 && (parsedFlags & bit) != 0) {
			addWarning(result, "Duplicate $ConnectToMe endpoint suffix.", true);
		}
		parsedFlags |= bit;
	}
	if(!flags.empty() && flags != "S" && flags != "N" && flags != "R" &&
		flags != "NS" && flags != "RS")
	{
		addWarning(result,
			"$ConnectToMe suffixes must use canonical N/NS or R/RS order "
			"(TLS S last).", true);
	}
	if((parsedFlags & NMDC_ENDPOINT_TLS) != 0) {
		addField(result, "TLS", "TLS-encrypted connection", "Requested");
	}
	if((parsedFlags & NMDC_ENDPOINT_NAT_INITIATOR) != 0) {
		addField(result, "NAT", "NAT traversal role", "Initiator");
	}
	if((parsedFlags & NMDC_ENDPOINT_NAT_RESPONDER) != 0) {
		addField(result, "NAT", "NAT traversal role", "Responder");
	}
	if((parsedFlags & NMDC_ENDPOINT_NAT_INITIATOR) != 0 &&
		(parsedFlags & NMDC_ENDPOINT_NAT_RESPONDER) != 0)
	{
		addWarning(result,
			"$ConnectToMe cannot request both NAT initiator and responder roles.",
			true);
	}
	return parsedFlags;
}

void parseNmdcConnect(Result& result, string_view command,
	string_view parameters)
{
	const auto values = split(trimAscii(parameters), ' ', 8);
	if(command == "$RevConnectToMe") {
		if(values.size() < 2 || values[0].empty() || values[1].empty()) {
			addWarning(result,
				"$RevConnectToMe requires sender and remote nicknames.", true);
			genericNmdcParameters(result, parameters);
			return;
		}
		addField(result, "sender", "Sender nickname", decodeNmdcText(values[0]));
		addField(result, "remote", "Remote nickname", decodeNmdcText(values[1]));
		if(values.size() > 2) {
			addWarning(result,
				"$RevConnectToMe contains unexpected additional parameters.");
		}
		setSummary(result, "Reverse connect request from " +
			firstFieldValue(result, "sender") + " to " +
			firstFieldValue(result, "remote"));
		return;
	}

	if(values.size() < 2 || values[0].empty() || values[1].empty()) {
		addWarning(result, "$ConnectToMe requires a nickname and endpoint.", true);
		genericNmdcParameters(result, parameters);
		return;
	}
	if(values.size() >= 3 && values[2].find(':') != string_view::npos) {
		// Newer documented form: sender, remote, endpoint.
		addField(result, "sender", "Sender nickname", decodeNmdcText(values[0]));
		addField(result, "remote", "Remote nickname", decodeNmdcText(values[1]));
		parseNmdcConnectionEndpoint(result, values[2]);
		if(values.size() > 3) {
			addWarning(result,
				"$ConnectToMe contains unexpected additional parameters.");
		}
	} else {
		// Original form, also used by NAT with N/R endpoint suffixes and an
		// optional peer nickname following the endpoint.
		addField(result, "remote", "Remote nickname", decodeNmdcText(values[0]));
		const auto endpointFlags = parseNmdcConnectionEndpoint(result, values[1]);
		if(values.size() >= 3) {
			addField(result, "peer", "NAT peer nickname",
				decodeNmdcText(values[2]));
		}
		if((endpointFlags & NMDC_ENDPOINT_NAT_INITIATOR) != 0 &&
			values.size() < 3)
		{
			addWarning(result,
				"NAT initiator ConnectToMe requires a peer nickname.", true);
		}
		if(values.size() >= 3 &&
			(endpointFlags & NMDC_ENDPOINT_NAT_INITIATOR) == 0)
		{
			addWarning(result,
				"A NAT peer nickname requires the N endpoint suffix.", true);
		}
		if(values.size() > 3) {
			addWarning(result,
				"$ConnectToMe contains unexpected additional parameters.");
		}
	}
	setSummary(result, "Connect request for " + firstFieldValue(result, "remote") +
		" at " + firstFieldValue(result, "endpoint"));
}

bool isFourDigitHex(string_view value) {
	return value.size() == 4 &&
		std::all_of(value.begin(), value.end(), [](char ch) {
			return (ch >= '0' && ch <= '9') ||
				(ch >= 'A' && ch <= 'F') ||
				(ch >= 'a' && ch <= 'f');
		});
}

void parseNmdcAdvancedConnect(Result& result, string_view command,
	string_view parameters)
{
	parameters = trimAscii(parameters);
	if(command == "$RCTM") {
		if(parameters.empty() || parameters.find('$') != string_view::npos) {
			addWarning(result, "$RCTM requires exactly one remote nickname.", true);
			genericNmdcParameters(result, parameters);
			return;
		}
		addField(result, "remote", "Remote nickname", decodeNmdcText(parameters));
		setSummary(result, "Advanced reverse connect request for " +
			firstFieldValue(result, "remote"));
		return;
	}

	const auto values = split(parameters, '$', 5);
	if(values.size() == 1) {
		addField(result, "id", "Connection ID", bounded(values[0]));
		if(!isFourDigitHex(values[0])) {
			addWarning(result,
				"$CTM connection ID must contain four hexadecimal digits.", true);
		}
		setSummary(result, "Advanced connection handshake ID " +
			firstFieldValue(result, "id"));
		return;
	}
	if(values.size() != 3 || values[0].empty() || values[1].empty() ||
		values[2].empty())
	{
		addWarning(result,
			"$CTM requires peer$port$id or a four-digit handshake ID.", true);
		genericNmdcParameters(result, parameters);
		return;
	}
	addField(result, "peer", "Remote nickname or sender address",
		decodeNmdcText(values[0]));
	addField(result, "port", "Sender port", bounded(values[1]));
	addField(result, "id", "Connection ID", bounded(values[2]));
	uint64_t port = 0;
	if(!parseUnsigned(values[1], port) || port == 0 || port > 65535) {
		addWarning(result,
			"$CTM port must be an integer from 1 to 65535.", true);
	}
	if(!isFourDigitHex(values[2])) {
		addWarning(result,
			"$CTM connection ID must contain four hexadecimal digits.", true);
	}
	setSummary(result, "Advanced connect request for " +
		firstFieldValue(result, "peer") + " on port " +
		firstFieldValue(result, "port"));
}

void parseNmdcPrivateMessage(Result& result, string_view command,
	string_view parameters)
{
	parameters = trimAscii(parameters);
	if(command == "$MCTo:") {
		const auto senderMarker = parameters.find(" $");
		if(senderMarker == string_view::npos) {
			addWarning(result, "$MCTo: is missing its sender marker.", true);
			genericNmdcParameters(result, parameters);
			return;
		}
		addField(result, "target", "Target nickname",
			decodeNmdcText(parameters.substr(0, senderMarker)));
		const auto messageStart = parameters.find(' ', senderMarker + 2);
		if(messageStart == string_view::npos) {
			addWarning(result, "$MCTo: is missing its message text.", true);
			addField(result, "sender", "Sender nickname",
				decodeNmdcText(parameters.substr(senderMarker + 2)));
		} else {
			addField(result, "sender", "Sender nickname", decodeNmdcText(
				parameters.substr(senderMarker + 2,
					messageStart - senderMarker - 2)));
			addField(result, "text", "Message text",
				decodeNmdcText(parameters.substr(messageStart + 1)));
		}
		setSummary(result, "Main-chat-style private message from " +
			firstFieldValue(result, "sender") + " to " +
			firstFieldValue(result, "target") + ": " +
			firstFieldValue(result, "text"));
		return;
	}

	const auto fromMarker = parameters.find(" From: ");
	if(fromMarker == string_view::npos) {
		addWarning(result, "$To: is missing its From: marker.", true);
		genericNmdcParameters(result, parameters);
		return;
	}
	addField(result, "target", "Target nickname",
		decodeNmdcText(parameters.substr(0, fromMarker)));
	const auto displayMarker = parameters.find(" $<", fromMarker + 7);
	if(displayMarker == string_view::npos) {
		addWarning(result, "$To: is missing its displayed-sender marker.", true);
		addField(result, "sender", "Sender nickname",
			decodeNmdcText(parameters.substr(fromMarker + 7)));
		return;
	}
	addField(result, "sender", "Sender nickname", decodeNmdcText(
		parameters.substr(fromMarker + 7, displayMarker - fromMarker - 7)));
	const auto displayEnd = parameters.find('>', displayMarker + 3);
	if(displayEnd == string_view::npos) {
		addWarning(result, "$To: displayed sender is missing its closing bracket.", true);
		return;
	}
	addField(result, "display", "Displayed sender nickname",
		decodeNmdcText(parameters.substr(displayMarker + 3,
			displayEnd - displayMarker - 3)));
	if(firstFieldValue(result, "sender") != firstFieldValue(result, "display")) {
		addWarning(result,
			"$To: sender and displayed-sender nicknames do not match.");
	}
	auto text = parameters.substr(displayEnd + 1);
	if(!text.empty() && text.front() == ' ') {
		text.remove_prefix(1);
	}
	addField(result, "text", "Message text", decodeNmdcText(text));
	setSummary(result, "Private message from " + firstFieldValue(result, "sender") +
		" to " + firstFieldValue(result, "target") + ": " +
		firstFieldValue(result, "text"));
}

const char* nmdcIncrementalFieldName(char code) {
	switch(code) {
	case 'D': return "Description";
	case 'T': return "Client tag";
	case 'C': return "Connection";
	case 'F': return "Status flags";
	case 'E': return "Email";
	case 'S': return "Share size";
	default: return "Extension information";
	}
}

const char* nmdcTagFieldName(char code) {
	switch(code) {
	case 'c': return "Tag client";
	case 'v': return "Tag version";
	case 'm': return "Tag connection mode";
	case 'h': return "Tag hub counts";
	case 's': return "Tag upload slots";
	case 'f': return "Tag free slots";
	case 'l': return "Tag bandwidth limit";
	case 'o': return "Tag automatic-slot setting";
	case 'r': return "Tag reverse-bandwidth setting";
	default: return "Tag extension";
	}
}

void parseNmdcIncrementalInfo(Result& result, string_view parameters) {
	parameters = trimAscii(parameters);
	const auto firstDelimiter = parameters.find('$');
	if(firstDelimiter == string_view::npos) {
		addWarning(result, "$IN requires a nickname and at least one data part.", true);
		genericNmdcParameters(result, parameters);
		return;
	}
	addField(result, "nick", "Nickname",
		decodeNmdcText(parameters.substr(0, firstDelimiter)));
	const auto parts = split(parameters.substr(firstDelimiter + 1), '$');
	for(const auto part : parts) {
		if(part.empty()) {
			continue;
		}
		const char code = part.front();
		const auto data = part.substr(1);
		addField(result, string(1, code), nmdcIncrementalFieldName(code),
			decodeNmdcText(data));
		if(code == 'T') {
			for(const auto component : split(data, ' ', 16)) {
				if(!component.empty()) {
					addField(result, "T." + string(1, component.front()),
						nmdcTagFieldName(component.front()),
						decodeNmdcText(component.substr(1)));
				}
			}
		}
	}
	if(result.fields.size() == 1) {
		addWarning(result, "$IN does not contain any data parts.");
	}
	setSummary(result, "Incremental information for " +
		firstFieldValue(result, "nick"));
}

void parseNmdcHubInfo(Result& result, string_view parameters) {
	static constexpr std::array<const char*, 11> codes {{
		"name", "address", "description", "max_users", "min_share",
		"min_slots", "max_hubs", "hub_type", "owner_login", "category",
		"encoding"
	}};
	static constexpr std::array<const char*, 11> names {{
		"Hub name", "Hub address", "Description", "Maximum users",
		"Minimum share", "Minimum slots", "Maximum connected hubs",
		"Hub type", "Owner login", "Hub category", "Character encoding"
	}};
	const auto fields = split(trimAscii(parameters), '$', 16);
	for(size_t i = 0; i < fields.size() && i < names.size(); ++i) {
		addField(result, codes[i], names[i], decodeNmdcText(fields[i]));
	}
	if(fields.size() < 9) {
		addWarning(result, "$HubINFO contains fewer than the core documented fields.");
	}
	if(fields.size() > names.size()) {
		addWarning(result, "$HubINFO contains unexpected additional fields.");
	}
	setSummary(result, "Hub information for " + firstFieldValue(result, "name"));
}

void parseNmdcSupports(Result& result, string_view parameters) {
	const auto tokens = split(trimAscii(parameters), ' ');
	size_t recognized = 0;
	for(const auto token : tokens) {
		if(!token.empty()) {
			const auto name = featureName(NMDC_FEATURE_DEFINITIONS, token, true);
			recognized += name ? 1U : 0U;
			addField(result, "feature",
				name ? string("Supported extension — ") + name : "Supported extension",
				bounded(token));
		}
	}
	if(result.fields.empty()) {
		addWarning(result, "$Supports should contain at least one extension.");
	}
	setSummary(result, "Advertises " + std::to_string(result.fields.size()) +
		" NMDC extension" + (result.fields.size() == 1 ? "" : "s") +
		" (" + std::to_string(recognized) + " recognized)");
}

Result analyzeNmdc(string_view raw) {
	Result result;
	result.family = "NMDC";
	result.routing = "NMDC";

	if(raw == "|") {
		result.command = "KEEPALIVE";
		result.action = result.command;
		result.name = "Keep-alive";
		result.category = "Control";
		result.routing = "Connection";
		result.summary = "NMDC keep-alive";
		result.safeMessage = "|";
		return result;
	}

	std::vector<Span> masks;
	if(raw.size() > MAX_ANALYZER_INPUT_BYTES) {
		raw = raw.substr(0, MAX_ANALYZER_INPUT_BYTES);
		addWarning(result, "Message exceeded the analyzer input limit and was truncated.", true);
	}
	findNmdcSecurityMasks(raw, masks);
	auto body = trimProtocolEnd(raw);
	const auto additionalFrame = body.find('|');
	if(additionalFrame != string_view::npos) {
		body = body.substr(0, additionalFrame);
		addWarning(result,
			"Additional NMDC frames were retained in raw output but not merged into this row.");
	}
	if(body.empty()) {
		result.command = "[empty]";
		result.action = result.command;
		result.name = "Empty NMDC message";
		result.category = "Malformed";
		result.known = false;
		addWarning(result, "NMDC message is empty.", true);
		setSummary(result, "Empty NMDC message");
		result.safeMessage = applyMasks(raw, std::move(masks));
		return result;
	}

	if(body.front() == '<') {
		result.command = "Chat";
		result.action = "Chat";
		result.name = "Public chat message";
		result.category = "Chat";
		const auto close = body.find('>');
		if(close == string_view::npos) {
			addWarning(result, "Public chat message is missing the closing nickname bracket.",
				true);
			genericNmdcParameters(result, body);
		} else {
			addField(result, "nick", "Nickname", decodeNmdcText(body.substr(1, close - 1)));
			auto text = body.substr(close + 1);
			if(!text.empty() && text.front() == ' ') {
				text.remove_prefix(1);
			}
			addField(result, "text", "Message text", decodeNmdcText(text));
		}
		setSummary(result, "Public chat from " + firstFieldValue(result, "nick") +
			": " + firstFieldValue(result, "text"));
		result.safeMessage = applyMasks(raw, std::move(masks));
		return result;
	}

	if(body.front() != '$') {
		result.command = "Unknown";
		result.action = result.command;
		result.name = "Unframed NMDC data";
		result.category = "Unknown";
		result.known = false;
		addWarning(result, "NMDC command does not begin with '$' or a chat nickname.");
		genericNmdcParameters(result, body);
		setSummary(result, "Unframed NMDC data");
		result.safeMessage = applyMasks(raw, std::move(masks));
		return result;
	}

	size_t commandEnd = 1;
	while(commandEnd < body.size() && body[commandEnd] != ' ' &&
		body[commandEnd] != '\t')
	{
		++commandEnd;
	}
	auto command = body.substr(0, commandEnd);
	result.command = sanitize(command, 64);
	result.action = result.command;
	string_view parameters = commandEnd < body.size() ? body.substr(commandEnd + 1) :
		string_view();

	const auto definition = findDefinition(NMDC_DEFINITIONS.data(),
		NMDC_DEFINITIONS.data() + NMDC_DEFINITIONS.size(), command);
	if(definition) {
		result.name = definition->name;
		result.category = definition->category;
	} else {
		result.name = "Unknown NMDC command";
		result.category = "Unknown";
		result.known = false;
		addWarning(result,
			"Unknown or vendor-specific NMDC command; parameters were preserved generically.");
	}

	const bool credentialLike = isCredentialLikeNmdcCommand(command);
	if(credentialLike && !parameters.empty()) {
		addMask(masks, raw, trimAscii(parameters));
		addField(result, "secret", "Authentication material", "<redacted>", true);
		setSummary(result, result.name + " (authentication material redacted)");
	} else if(command == "$Z" || command == "$ZOn") {
		if(!parameters.empty()) {
			addMask(masks, raw, parameters);
		}
		addField(result, "blob", "Compressed payload", "<redacted>", true);
		addWarning(result,
			"Compressed NMDC content is intentionally not decompressed on the UI thread.");
		setSummary(result, result.name + " (opaque payload redacted)");
	} else if(command == "$MyINFO") {
		parseNmdcMyInfo(result, parameters);
	} else if(command == "$Search" || command == "$MultiSearch") {
		parseNmdcSearch(result, parameters);
	} else if(command == "$SA" || command == "$SP") {
		parseNmdcShortTthSearch(result, command, parameters);
	} else if(command == "$ADCGET" || command == "$ADCSND") {
		parseNmdcTransfer(result, command, parameters);
	} else if(command == "$Supports") {
		parseNmdcSupports(result, parameters);
	} else if(command == "$NickRule" || command == "$BadNick" ||
		command == "$SearchRule")
	{
		parseNmdcRule(result, command, parameters);
	} else if(command == "$SetIcon" || command == "$SetLogo" ||
		command == "$GetHubURL" || command == "$MyHubURL" ||
		command == "$SetHubURL")
	{
		parseNmdcUrlCommand(result, command, parameters);
	} else if(command == "$SR") {
		parseNmdcSearchResult(result, parameters);
	} else if(command == "$Lock") {
		const auto pk = parameters.find(" Pk=");
		const auto ref = parameters.find("Ref=");
		addField(result, "lock", "Lock challenge", decodeNmdcText(
			pk == string_view::npos ? parameters : parameters.substr(0, pk)));
		if(pk != string_view::npos) {
			const auto pkStart = pk + 4;
			const auto pkEnd = ref == string_view::npos ? parameters.size() : ref;
			addField(result, "Pk", "Legacy implementation identifier",
				decodeNmdcText(trimAscii(parameters.substr(pkStart, pkEnd - pkStart))));
		}
		if(ref != string_view::npos) {
			addField(result, "Ref", "Referring hub",
				decodeNmdcText(parameters.substr(ref + 4)));
		}
		setSummary(result, "NMDC lock challenge");
	} else if(command == "$Direction") {
		const auto values = split(trimAscii(parameters), ' ', 4);
		if(!values.empty()) addField(result, "direction", "Direction", bounded(values[0]));
		if(values.size() > 1) addField(result, "number", "Tie-break number", bounded(values[1]));
		if(values.size() < 2) {
			addWarning(result, "$Direction requires direction and tie-break number.", true);
		}
		setSummary(result, result.name + ": " + firstFieldValue(result, "direction"));
	} else if(command == "$ConnectToMe" || command == "$RevConnectToMe") {
		parseNmdcConnect(result, command, parameters);
	} else if(command == "$CTM" || command == "$RCTM") {
		parseNmdcAdvancedConnect(result, command, parameters);
	} else if(command == "$To:" || command == "$MCTo:") {
		parseNmdcPrivateMessage(result, command, parameters);
	} else if(command == "$IN") {
		parseNmdcIncrementalInfo(result, parameters);
	} else if(command == "$HubINFO") {
		parseNmdcHubInfo(result, parameters);
	} else {
		genericNmdcParameters(result, parameters);
		setSummary(result, result.name.empty() ? result.command : result.name);
	}

	result.safeMessage = applyMasks(raw, std::move(masks));
	return result;
}

Result analyzeOpaque(string_view family, string_view raw) {
	Result result;
	result.family = sanitize(family, 32);
	result.command = result.family;
	result.action = result.command;
	result.name = result.family + " payload";
	result.category = result.family;
	result.routing = result.family;
	result.summary = result.name;
	if(raw.size() > MAX_ANALYZER_INPUT_BYTES) {
		raw = raw.substr(0, MAX_ANALYZER_INPUT_BYTES);
		addWarning(result, "Message exceeded the analyzer input limit and was truncated.", true);
	}
	result.safeMessage = sanitize(raw, MAX_ANALYZER_INPUT_BYTES);
	return result;
}

void appendBounded(string& target, string_view value) {
	if(target.size() >= MAX_DETAIL_BYTES) {
		return;
	}
	const auto available = MAX_DETAIL_BYTES - target.size();
	const auto maximum = std::min(available, value.size());
	size_t prefix = 0;
	while(prefix < maximum) {
		const auto ch = static_cast<unsigned char>(value[prefix]);
		size_t length = ch < 0x80U ? 1U :
			validUtf8SequenceLength(value, prefix);
		if(length == 0) {
			// All analyzer-owned strings are sanitized before this point. Keep
			// this fallback bounded if a caller constructs a Result manually.
			length = 1;
		}
		if(prefix + length > maximum) {
			break;
		}
		prefix += length;
	}
	target.append(value.data(), prefix);
}

} // unnamed namespace

Result analyze(const std::string& displayedProtocol, const std::string& raw) {
	const bool nmdc = asciiEqualNoCase(displayedProtocol, "NMDC") ||
		(asciiEqualNoCase(displayedProtocol, "UDP") && !raw.empty() &&
			(raw.front() == '$' || raw.front() == '<')) ||
		(!raw.empty() && (raw.front() == '$' || raw.front() == '<') &&
			!asciiEqualNoCase(displayedProtocol, "ADC"));
	if(nmdc) {
		return analyzeNmdc(raw);
	}
	if(asciiEqualNoCase(displayedProtocol, "ADC") ||
		asciiEqualNoCase(displayedProtocol, "UDP"))
	{
		return analyzeAdc(raw);
	}
	return analyzeOpaque(displayedProtocol.empty() ? "Unknown" : displayedProtocol, raw);
}

namespace {

Result makeBinaryPayloadResult(const std::string& displayedProtocol,
	const std::string& transferType, bool observedSizeKnown,
	std::size_t observedBytes, std::size_t expectedBytes)
{
	Result result;
	result.family = sanitize(displayedProtocol.empty() ? "ADC" :
		string_view(displayedProtocol), 32);
	result.binaryPayload = true;
	result.observedBinaryPayloadBytesKnown = observedSizeKnown;
	result.binaryPayloadType = sanitize(transferType.empty() ? "binary" :
		string_view(transferType), 64);
	result.expectedBinaryPayloadBytes = expectedBytes;
	result.observedBinaryPayloadBytes = observedBytes;
	result.command = result.binaryPayloadType == "blom" ?
		"BLOM-DATA" : "BINARY-DATA";
	result.action = result.command;
	result.name = result.binaryPayloadType == "blom" ?
		"Bloom filter binary payload" : "Opaque binary transfer payload";
	result.category = "Transfer";
	result.routing = "Binary";

	addField(result, "type", "Transfer type", result.binaryPayloadType);
	addField(result, "expected", "Expected byte count",
		std::to_string(expectedBytes));
	addField(result, "observed", "Observed byte count",
		observedSizeKnown ? std::to_string(observedBytes) :
			"Unavailable from host hook");
	addField(result, "encoding", "Payload encoding",
		"Opaque binary (not decoded as text)");
	if(observedSizeKnown && observedBytes != expectedBytes) {
		addWarning(result,
			"Observed binary payload size differs from the preceding SND byte count.");
	}
	if(observedSizeKnown) {
		setSummary(result, result.name + ": " + formatBytes(observedBytes) +
			" (contents omitted)");
		result.safeMessage = "<" + std::to_string(observedBytes) + "-byte " +
			(result.binaryPayloadType == "blom" ? "BLOM" : "binary") +
			" payload omitted>";
	} else {
		setSummary(result, result.name + ": " + formatBytes(expectedBytes) +
			" announced (contents omitted; observed size unavailable)");
		result.safeMessage = "<announced " + std::to_string(expectedBytes) +
			"-byte " +
			(result.binaryPayloadType == "blom" ? "BLOM" : "binary") +
			" payload omitted; observed size unavailable>";
	}
	return result;
}

} // unnamed namespace

Result analyzeBinaryPayload(const std::string& displayedProtocol,
	const std::string& transferType, std::size_t observedBytes,
	std::size_t expectedBytes)
{
	return makeBinaryPayloadResult(displayedProtocol, transferType, true,
		observedBytes, expectedBytes);
}

Result analyzeBinaryPayload(const std::string& displayedProtocol,
	const std::string& transferType, std::size_t expectedBytes)
{
	return makeBinaryPayloadResult(displayedProtocol, transferType, false,
		0, expectedBytes);
}

const char* statusName(Status status) noexcept {
	switch(status) {
	case Status::Valid: return "Valid";
	case Status::Warning: return "Warning";
	case Status::Invalid: return "Invalid";
	default: return "Unknown";
	}
}

std::string formatDetails(const Result& result) {
	string details;
	details.reserve(2048);
	appendBounded(details, "Protocol: ");
	appendBounded(details, sanitize(result.family, 128));
	appendBounded(details, "\r\nCommand: ");
	appendBounded(details, sanitize(result.command, 128));
	if(!result.action.empty() && result.action != result.command) {
		appendBounded(details, " (action ");
		appendBounded(details, sanitize(result.action, 128));
		appendBounded(details, ")");
	}
	appendBounded(details, "\r\nName: ");
	appendBounded(details, sanitize(result.name, 256));
	appendBounded(details, "\r\nCategory: ");
	appendBounded(details, sanitize(result.category, 128));
	appendBounded(details, "\r\nRouting: ");
	appendBounded(details, sanitize(result.routing, 128));
	appendBounded(details, "\r\nValidation: ");
	appendBounded(details, statusName(result.status));
	appendBounded(details, "\r\nSummary: ");
	appendBounded(details, sanitize(result.summary, MAX_SUMMARY_BYTES));

	if(!result.fields.empty()) {
		appendBounded(details, "\r\n\r\nFields:");
		for(const auto& field : result.fields) {
			appendBounded(details, "\r\n  ");
			if(!field.code.empty()) {
				appendBounded(details, sanitize(field.code, 128));
				appendBounded(details, " \xE2\x80\x94 ");
			}
			appendBounded(details, sanitize(field.name, 256));
			appendBounded(details, ": ");
			appendBounded(details, sanitize(field.value, MAX_FIELD_VALUE_BYTES));
		}
	}
	if(!result.warnings.empty()) {
		appendBounded(details, "\r\n\r\nWarnings:");
		for(const auto& warning : result.warnings) {
			appendBounded(details, "\r\n  \xE2\x80\xA2 ");
			appendBounded(details, sanitize(warning, 256));
		}
	}
	appendBounded(details, "\r\n\r\nRaw (sensitive values redacted):\r\n");
	appendBounded(details, sanitize(result.safeMessage,
		MAX_ANALYZER_INPUT_BYTES + 1024));
	if(details.size() == MAX_DETAIL_BYTES) {
		details += "\r\n[Inspector output truncated at safety limit]";
	}
	return details;
}

}// namespace protocol_analyzer
