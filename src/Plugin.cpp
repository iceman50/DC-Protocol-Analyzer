/*
 * Copyright (C) 2012-2013 Jacek Sieka, arnetheduck on gmail point com
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

#include "stdafx.h"
#include "Plugin.h"

/* Include plugin SDK helpers. There are more interfaces available that can be included in the same
fashion (check the pluginsdk directory). */
#include <pluginsdk/Config.h>
#include <pluginsdk/Connections.h>
#include <pluginsdk/Core.h>
#include <pluginsdk/DataAccess.h>
#include <pluginsdk/Hooks.h>
#include <pluginsdk/Hubs.h>
#include <pluginsdk/Logger.h>
#include <pluginsdk/Queue.h>
#include <pluginsdk/Tagger.h>
#include <pluginsdk/UI.h>
#include <pluginsdk/Util.h>

#include <algorithm>
#include <array>
#include <exception>
#include <limits>
#include <mutex>
#include <string_view>
#include <utility>

/* Plugin SDK helpers are in the "dcapi" namespace; ease their calling. */
using dcapi::Config;
using dcapi::Connections;
using dcapi::Core;
using dcapi::DataAccess;
using dcapi::Hooks;
using dcapi::Hubs;
using dcapi::Logger;
using dcapi::Queue;
using dcapi::Tagger;
using dcapi::UI;
using dcapi::Util;

namespace {

const string showCommand = "Show the dialog";
const string hideCommand = "Hide the dialog";

constexpr size_t MAX_COMMAND_NAME_LENGTH = 64;
constexpr size_t MAX_COMMAND_PARAMETER_LENGTH = 64 * 1024;
constexpr size_t MAX_HTTP_URI_LENGTH = 4096;
constexpr size_t MAX_LOCAL_PATH_LENGTH = 32767;
constexpr size_t MAX_ACTIVE_DOWNLOADS = 16;
constexpr size_t MAX_NETWORK_ADDRESS_LENGTH = 256;
constexpr size_t MAX_PEER_FIELD_LENGTH = 4096;
constexpr size_t MAX_CAPTURE_MESSAGE_LENGTH = 64 * 1024;
constexpr size_t MAX_DIAGNOSTIC_LENGTH = 1024;
constexpr size_t MAX_PENDING_BLOOM_REQUESTS = 32;
constexpr size_t MAX_PENDING_BLOOM_PAYLOADS = 32;
constexpr auto BLOOM_REQUEST_LIFETIME = std::chrono::seconds(30);
constexpr auto BLOOM_PAYLOAD_LIFETIME = std::chrono::seconds(5);
constexpr uint64_t MAX_ACCOUNTED_DOWNLOAD_BYTES = uint64_t { 1 } << 40;

enum class BloomHookHeaderKind {
	None,
	Get,
	Send
};

struct BloomHookHeader {
	BloomHookHeaderKind kind = BloomHookHeaderKind::None;
	uint64_t bytes = 0;
	uint32_t k = 0;
	uint32_t h = 0;
	bool hasK = false;
	bool hasH = false;
};

bool parseUnsigned(std::string_view value, uint64_t& parsed) noexcept {
	if(value.empty()) {
		return false;
	}
	uint64_t result = 0;
	for(const auto character : value) {
		if(character < '0' || character > '9') {
			return false;
		}
		const auto digit = static_cast<uint64_t>(character - '0');
		if(result > ((std::numeric_limits<uint64_t>::max)() - digit) / 10) {
			return false;
		}
		result = result * 10 + digit;
	}
	parsed = result;
	return true;
}

bool isAdcFieldCode(std::string_view token) noexcept {
	return token.size() > 2 &&
		token[0] >= 'A' && token[0] <= 'Z' &&
		((token[1] >= 'A' && token[1] <= 'Z') ||
			(token[1] >= '0' && token[1] <= '9'));
}

bool parseBloomHookHeader(
	const string& message, BloomHookHeader& result) noexcept
{
	result = BloomHookHeader {};
	std::string_view frame(message);
	if(!frame.empty() && frame.back() == '\n') {
		frame.remove_suffix(1);
		if(!frame.empty() && frame.back() == '\r') {
			frame.remove_suffix(1);
		}
	}
	if(frame.size() < 15 || frame.find_first_of("\r\n") !=
		std::string_view::npos)
	{
		return false;
	}
	if(frame.front() == ' ' || frame.back() == ' ') {
		return false;
	}
	for(const auto character : frame) {
		const auto byte = static_cast<unsigned char>(character);
		if(byte < 0x20 || byte > 0x7e) {
			return false;
		}
	}

	std::array<std::string_view, 16> tokens {};
	size_t tokenCount = 0;
	size_t position = 0;
	while(position < frame.size()) {
		const auto end = frame.find(' ', position);
		const auto tokenEnd =
			end == std::string_view::npos ? frame.size() : end;
		if(tokenEnd == position || tokenCount == tokens.size()) {
			return false;
		}
		tokens[tokenCount++] = frame.substr(position, tokenEnd - position);
		if(end == std::string_view::npos) {
			break;
		}
		position = end + 1;
	}

	if(tokenCount < 5 ||
		(tokens[0] != "IGET" && tokens[0] != "HSND") ||
		tokens[1] != "blom" || tokens[2] != "/" || tokens[3] != "0")
	{
		return false;
	}

	if(!parseUnsigned(tokens[4], result.bytes) ||
		result.bytes > (std::numeric_limits<uint64_t>::max)() / 8 ||
		result.bytes % 8 != 0)
	{
		return false;
	}
	result.kind = tokens[0] == "IGET" ?
		BloomHookHeaderKind::Get : BloomHookHeaderKind::Send;

	for(size_t i = 5; i < tokenCount; ++i) {
		const auto token = tokens[i];
		if(!isAdcFieldCode(token)) {
			return false;
		}
		uint64_t value = 0;
		const auto code = token.substr(0, 2);
		if(code == "BK") {
			if(result.hasK || !parseUnsigned(token.substr(2), value) ||
				value == 0 || value > 192)
			{
				return false;
			}
			result.k = static_cast<uint32_t>(value);
			result.hasK = true;
		} else if(code == "BH") {
			if(result.hasH || !parseUnsigned(token.substr(2), value) ||
				value == 0 || value > 64)
			{
				return false;
			}
			result.h = static_cast<uint32_t>(value);
			result.hasH = true;
		}
	}

	if(result.kind == BloomHookHeaderKind::Get &&
		(!result.hasK || !result.hasH))
	{
		return false;
	}
	if(result.hasK && result.hasH &&
		static_cast<uint64_t>(result.k) * result.h > 192)
	{
		return false;
	}
	const auto bitCount = result.bytes * 8;
	if(result.hasH && result.h < 64 &&
		bitCount >= (uint64_t { 1 } << result.h))
	{
		return false;
	}
	return true;
}

Plugin* instance = nullptr;
std::mutex lifecycleMutex;

size_t boundedLength(const char* value, size_t maximum) noexcept {
	if(!value) {
		return 0;
	}
	size_t length = 0;
	while(length <= maximum && value[length] != '\0') {
		++length;
	}
	return length;
}

bool copyBounded(const char* value, size_t maximum, string& result, bool allowEmpty = false) {
	result.clear();
	if(!value) {
		return allowEmpty;
	}
	const auto length = boundedLength(value, maximum);
	if(length > maximum || (!allowEmpty && length == 0)) {
		return false;
	}
	result.assign(value, length);
	return true;
}

bool isAsciiSpace(char value) noexcept {
	return value == ' ' || value == '\t';
}

char asciiLower(char value) noexcept {
	return value >= 'A' && value <= 'Z' ? static_cast<char>(value - 'A' + 'a') : value;
}

bool equalsNoCase(const string& left, const char* right) noexcept {
	if(!right) {
		return false;
	}
	size_t i = 0;
	for(; i < left.size() && right[i] != '\0'; ++i) {
		if(asciiLower(left[i]) != asciiLower(right[i])) {
			return false;
		}
	}
	return i == left.size() && right[i] == '\0';
}

string boundedDiagnostic(const char* value) {
	string result;
	if(!value) {
		return result;
	}
	result.reserve(MAX_DIAGNOSTIC_LENGTH);
	size_t length = 0;
	while(length < MAX_DIAGNOSTIC_LENGTH && value[length] != '\0') {
		const auto ch = static_cast<unsigned char>(value[length++]);
		result.push_back(ch >= 0x20 && ch != 0x7f ?
			static_cast<char>(ch) : ' ');
	}
	if(length == MAX_DIAGNOSTIC_LENGTH && value[length] != '\0') {
		result += " [truncated]";
	}
	return result;
}

void logGuiFailure(const char* source, const char* detail) noexcept {
	try {
		string message = "[Protocol Analyzer] unable to open the protocol monitor";
		const auto safeSource = boundedDiagnostic(source);
		const auto safeDetail = boundedDiagnostic(detail);
		if(!safeSource.empty()) {
			message += " during ";
			message += safeSource;
		}
		if(!safeDetail.empty()) {
			message += ": ";
			message += safeDetail;
		}
		Logger::log(message);
	} catch(...) {
		Logger::log("[Protocol Analyzer] unable to open the protocol monitor");
	}
}

bool startsWithNoCase(const string& value, const char* prefix) noexcept {
	if(!prefix) {
		return false;
	}
	size_t i = 0;
	for(; prefix[i] != '\0'; ++i) {
		if(i >= value.size() || asciiLower(value[i]) != asciiLower(prefix[i])) {
			return false;
		}
	}
	return true;
}

void trimAscii(string& value) {
	auto first = std::find_if_not(value.begin(), value.end(), isAsciiSpace);
	auto last = std::find_if_not(value.rbegin(), value.rend(), isAsciiSpace).base();
	if(first >= last) {
		value.clear();
		return;
	}
	value.assign(first, last);
}

bool hasUnsafeControl(const string& value) noexcept {
	return std::any_of(value.begin(), value.end(), [](unsigned char c) {
		return c < 0x20 && c != '\t';
	});
}

bool parseFetchArguments(const char* params, string& uri, string& localPath, string& error) {
	string input;
	if(!copyBounded(params, MAX_COMMAND_PARAMETER_LENGTH, input, true)) {
		error = "The /fetch command is too long.";
		return false;
	}
	trimAscii(input);
	if(input.empty()) {
		error = "Usage: /fetch <http-or-https-url> [localpath]";
		return false;
	}

	size_t position = 0;
	if(input[position] == '"' || input[position] == '\'') {
		const char quote = input[position++];
		const auto end = input.find(quote, position);
		if(end == string::npos) {
			error = "The URL has an unterminated quote.";
			return false;
		}
		uri = input.substr(position, end - position);
		position = end + 1;
		if(position < input.size() && !isAsciiSpace(input[position])) {
			error = "Separate the URL and local path with a space.";
			return false;
		}
	} else {
		const auto end = std::find_if(input.begin(), input.end(), isAsciiSpace);
		position = static_cast<size_t>(end - input.begin());
		uri.assign(input.begin(), end);
	}

	while(position < input.size() && isAsciiSpace(input[position])) {
		++position;
	}
	localPath = position < input.size() ? input.substr(position) : string();
	trimAscii(localPath);
	if(localPath.size() >= 2 &&
		((localPath.front() == '"' && localPath.back() == '"') ||
		 (localPath.front() == '\'' && localPath.back() == '\'')))
	{
		localPath = localPath.substr(1, localPath.size() - 2);
	} else if(!localPath.empty() &&
		(localPath.front() == '"' || localPath.front() == '\''))
	{
		error = "The local path has an unterminated quote.";
		return false;
	}

	if(uri.empty() || uri.size() > MAX_HTTP_URI_LENGTH ||
		(!startsWithNoCase(uri, "http://") && !startsWithNoCase(uri, "https://")))
	{
		error = "Only non-empty http:// and https:// URLs are accepted.";
		return false;
	}
	if(std::any_of(uri.begin(), uri.end(), [](unsigned char c) {
		return c <= 0x20 || c == 0x7f;
	})) {
		error = "The URL contains whitespace or control characters.";
		return false;
	}
	if(localPath.size() > MAX_LOCAL_PATH_LENGTH || hasUnsafeControl(localPath)) {
		error = "The local path is invalid or too long.";
		return false;
	}
	return true;
}

void localMessage(HubDataPtr hub, const char* message) noexcept {
	auto api = Hubs::handle();
	if(!hub || !message || !api || !api->local_message) {
		return;
	}
	try {
		api->local_message(hub, message, MSG_SYSTEM);
	} catch(...) {
	}
}

void releaseSdkInterfaces() noexcept {
	// Callback registries must be disabled and drained before their interfaces
	// or any interfaces used by callbacks are released.
	Hooks::reset();
	UI::reset();
	DataAccess::reset();
	Util::reset();
	Logger::reset();
	Hubs::reset();
	Connections::reset();
	Queue::reset();
	Tagger::reset();
	Config::reset();
	Core::reset();
}

class UserReleaseGuard {
public:
	explicit UserReleaseGuard(UserDataPtr user_) noexcept : user(user_) {
	}

	~UserReleaseGuard() noexcept {
		if(!user || user->isManaged != False) {
			return;
		}
		auto api = Hubs::handle();
		if(api && api->release_user) {
			try {
				api->release_user(user);
			} catch(...) {
			}
		}
	}

private:
	UserDataPtr user;
};

string boundedString(const char* value, size_t maximum) {
	if(!value || maximum == 0) {
		return string();
	}
	size_t length = 0;
	while(length < maximum && value[length] != '\0') {
		++length;
	}
	string result(value, length);
	if(length == maximum) {
		result += " [truncated]";
	}
	return result;
}

} // unnamed namespace

void Plugin::observeBloomHeader(
	HubDataPtr hub, bool sending, const std::string& message)
{
	if(!hub || hub->protocol != PROTOCOL_ADC) {
		return;
	}

	BloomHookHeader header;
	if(!parseBloomHookHeader(message, header) ||
		(header.kind == BloomHookHeaderKind::Get && sending) ||
		(header.kind == BloomHookHeaderKind::Send && !sending) ||
		header.bytes == 0)
	{
		return;
	}

	BloomHookEndpoint endpoint {
		hub->object, string(), string(), hub->port, hub->protocol, sending
	};
	if(!copyBounded(hub->url, MAX_PEER_FIELD_LENGTH, endpoint.url, true) ||
		!copyBounded(hub->ip, MAX_NETWORK_ADDRESS_LENGTH, endpoint.ip, true))
	{
		return;
	}

	const auto now = std::chrono::steady_clock::now();
	const auto sameEndpoint = [](const BloomHookEndpoint& left,
		const BloomHookEndpoint& right)
	{
		return left.object == right.object && left.url == right.url &&
			left.ip == right.ip && left.port == right.port &&
			left.protocol == right.protocol;
	};

	std::lock_guard<std::mutex> lock(bloomHookMutex);
	pendingBloomRequests.erase(std::remove_if(
		pendingBloomRequests.begin(), pendingBloomRequests.end(),
		[&](const PendingBloomRequest& state) {
			return state.expires <= now;
		}), pendingBloomRequests.end());
	pendingBloomPayloads.erase(std::remove_if(
		pendingBloomPayloads.begin(), pendingBloomPayloads.end(),
		[&](const PendingBloomPayload& state) {
			return state.expires <= now;
		}), pendingBloomPayloads.end());

	if(header.kind == BloomHookHeaderKind::Get) {
		pendingBloomRequests.erase(std::remove_if(
			pendingBloomRequests.begin(), pendingBloomRequests.end(),
			[&](const PendingBloomRequest& state) {
				return state.endpoint.sending == endpoint.sending &&
					sameEndpoint(state.endpoint, endpoint);
			}), pendingBloomRequests.end());
		if(pendingBloomRequests.size() >= MAX_PENDING_BLOOM_REQUESTS) {
			pendingBloomRequests.pop_front();
		}
		pendingBloomRequests.push_back(PendingBloomRequest {
			std::move(endpoint), header.bytes, header.k, header.h,
			now + BLOOM_REQUEST_LIFETIME
		});
		return;
	}

	auto request = std::find_if(
		pendingBloomRequests.begin(), pendingBloomRequests.end(),
		[&](const PendingBloomRequest& state) {
			return state.endpoint.sending != endpoint.sending &&
				sameEndpoint(state.endpoint, endpoint) &&
				state.bytes == header.bytes &&
				(!header.hasK || state.k == header.k) &&
				(!header.hasH || state.h == header.h);
		});
	if(request == pendingBloomRequests.end()) {
		return;
	}
	pendingBloomRequests.erase(request);

	pendingBloomPayloads.erase(std::remove_if(
		pendingBloomPayloads.begin(), pendingBloomPayloads.end(),
		[&](const PendingBloomPayload& state) {
			return state.endpoint.sending == endpoint.sending &&
				sameEndpoint(state.endpoint, endpoint);
		}), pendingBloomPayloads.end());
	if(pendingBloomPayloads.size() >= MAX_PENDING_BLOOM_PAYLOADS) {
		pendingBloomPayloads.pop_front();
	}
	pendingBloomPayloads.push_back(PendingBloomPayload {
		std::move(endpoint), header.bytes, now + BLOOM_PAYLOAD_LIFETIME
	});
}

bool Plugin::consumeExpectedBloomPayload(
	HubDataPtr hub, bool sending) noexcept
{
	if(!hub || hub->protocol != PROTOCOL_ADC) {
		return false;
	}

	try {
		const auto now = std::chrono::steady_clock::now();
		const auto matchesString = [](const char* actual,
			const std::string& expected) noexcept
		{
			if(!actual) {
				return expected.empty();
			}
			for(size_t i = 0; i < expected.size(); ++i) {
				if(actual[i] == '\0' || actual[i] != expected[i]) {
					return false;
				}
			}
			return actual[expected.size()] == '\0';
		};
		const auto matchesEndpoint = [&](const BloomHookEndpoint& endpoint) {
			return endpoint.sending == sending &&
				endpoint.object == hub->object &&
				endpoint.port == hub->port &&
				endpoint.protocol == hub->protocol &&
				matchesString(hub->url, endpoint.url) &&
				matchesString(hub->ip, endpoint.ip);
		};

		std::lock_guard<std::mutex> lock(bloomHookMutex);
		pendingBloomPayloads.erase(std::remove_if(
			pendingBloomPayloads.begin(), pendingBloomPayloads.end(),
			[&](const PendingBloomPayload& state) {
				return state.expires <= now;
			}), pendingBloomPayloads.end());
		const auto payload = std::find_if(
			pendingBloomPayloads.begin(), pendingBloomPayloads.end(),
			[&](const PendingBloomPayload& state) {
				return matchesEndpoint(state.endpoint);
			});
		if(payload == pendingBloomPayloads.end()) {
			return false;
		}
		pendingBloomPayloads.erase(payload);
		return true;
	} catch(...) {
		return false;
	}
}

void Plugin::clearBloomHookState() noexcept {
	try {
		std::lock_guard<std::mutex> lock(bloomHookMutex);
		pendingBloomRequests.clear();
		pendingBloomPayloads.clear();
	} catch(...) {
	}
}

Plugin::Plugin() :
	stopping(false),
	nextDownloadId(1)
{
}

Plugin::~Plugin() {
	shutdownCallbacks();
}

void Plugin::shutdownCallbacks() noexcept {
	if(stopping.exchange(true)) {
		return;
	}

	GUI::unloading = true;
	Hooks::clear();
	UI::clearCommands();
	clearBloomHookState();
	try {
		std::lock_guard<std::mutex> lock(downloadMutex);
		downloadRequests.clear();
	} catch(...) {
	}
}

Bool DCAPI Plugin::main(PluginState state, DCCorePtr core, dcptr_t) {
	try {
		std::unique_lock<std::mutex> lifecycleLock(
			lifecycleMutex, std::try_to_lock);
		if(!lifecycleLock.owns_lock()) {
			return False;
		}
		switch(state) {
		case ON_INSTALL:
		case ON_LOAD:
		case ON_LOAD_RUNTIME:
			{
				if(instance) {
					return False;
				}

				// Clear any state retained after an earlier rejected load.
				releaseSdkInterfaces();
				Plugin* candidate = nullptr;
				try {
					candidate = new Plugin();
					if(!candidate->onLoad(core, state == ON_INSTALL,
						state == ON_INSTALL || state == ON_LOAD_RUNTIME))
					{
						delete candidate;
						releaseSdkInterfaces();
						return False;
					}
					instance = candidate;
					return True;
				} catch(...) {
					delete candidate;
					releaseSdkInterfaces();
					return False;
				}
			}

		case ON_UNINSTALL:
		case ON_UNLOAD:
			{
				if(Hooks::inCallback() || UI::inCallback()) {
					// The host must retry outside the callback; teardown waits
					// for all callbacks and cannot wait for its own stack frame.
					return False;
				}
				auto old = instance;
				instance = nullptr;
				if(old) {
					old->shutdownCallbacks();
					delete old;
				}
				releaseSdkInterfaces();
				return True;
			}

		default:
			return False;
		}
	} catch(...) {
		// Never unwind through the host's plugin-main ABI.
		return False;
	}
}

bool Plugin::onLoad(DCCorePtr core, bool install, bool runtime) {
	if(!Core::init(core)) {
		return false;
	}

	GUI::unloading = false;
	if(!Config::init(PLUGIN_GUID) || !Connections::init() || !Hooks::init() ||
		!Hubs::init() || !Logger::init() || !UI::init(PLUGIN_GUID) ||
		!Util::init() || !DataAccess::init())
	{
		return false;
	}

	if(install) {
		Config::setConfig("Dialog", true);
		Config::setConfig("FirstRun", true);
		Logger::log("Protocol Analyzer has been installed; check the plugins menu and the /raw chat command.");
	}
	gui.loadCaptureQueueCapacity();

	if(!Hooks::Network::onHubDataIn(
			[this](HubDataPtr hHub, char* message, bool&) {
				return onHubDataIn(hHub, message);
			}) ||
		!Hooks::Network::onHubDataOut(
			[this](HubDataPtr hHub, char* message, bool&) {
				return onHubDataOut(hHub, message);
			}) ||
		!Hooks::Network::onClientDataIn(
			[this](ConnectionDataPtr hConn, char* message, bool&) {
				return onClientDataIn(hConn, message);
			}) ||
		!Hooks::Network::onClientDataOut(
			[this](ConnectionDataPtr hConn, char* message, bool&) {
				return onClientDataOut(hConn, message);
			}) ||
		!Hooks::Network::onUDPDataIn(
			[this](UDPDataPtr data, char* message, bool&) {
				return onUDPDataIn(data, message);
			}) ||
		!Hooks::Network::onUDPDataOut(
			[this](UDPDataPtr data, char* message, bool&) {
				return onUDPDataOut(data, message);
			}) ||
		!Hooks::UI::onChatCommand(
			[this](HubDataPtr hHub, CommandDataPtr cmd, bool&) {
				return onChatCommand(hHub, cmd);
			}))
	{
		return false;
	}

	if(!Hooks::DataAccessor::onHTTPResourceStream(
			[this](char* resource, DataArrayPtr data, bool&) -> bool {
				if(stopping.load() || !resource || !data || !data->pData || data->size == 0) {
					return false;
				}

				string key;
				if(!copyBounded(resource, MAX_HTTP_URI_LENGTH, key)) {
					return false;
				}
				std::lock_guard<std::mutex> lock(downloadMutex);
				auto request = downloadRequests.find(key);
				if(request == downloadRequests.end()) {
					return false;
				}
				const auto remaining =
					MAX_ACCOUNTED_DOWNLOAD_BYTES - request->second.bytes;
				if(data->size > remaining) {
					request->second.bytes = MAX_ACCOUNTED_DOWNLOAD_BYTES;
					request->second.byteCountSaturated = true;
				} else {
					request->second.bytes += data->size;
				}
				return false;
			}) ||
		!Hooks::DataAccessor::onHTTPResourceNotification(
			[this](char* resource, bool&) -> bool {
				if(stopping.load() || !resource) {
					return false;
				}

				string key;
				if(!copyBounded(resource, MAX_HTTP_URI_LENGTH, key)) {
					return false;
				}
				DownloadRequest request {};
				bool found = false;
				{
					std::lock_guard<std::mutex> lock(downloadMutex);
					auto i = downloadRequests.find(key);
					if(i != downloadRequests.end()) {
						request = i->second;
						downloadRequests.erase(i);
						found = true;
					}
				}
				if(found) {
					const auto sizeText = request.byteCountSaturated ?
						string("at least ") + std::to_string(request.bytes) :
						std::to_string(request.bytes);
					Logger::log("[Protocol Analyzer] fetch #" + std::to_string(request.id) +
						" complete: " + key + " (" + sizeText + " bytes" +
						(request.toFile ? ", saved to file)" : ")"));
				}
				return false;
			}) ||
		!Hooks::DataAccessor::onHTTPResourceNotificationFailed(
			[this](char* resource, bool&) -> bool {
				if(!resource) {
					return false;
				}

				string key;
				if(!copyBounded(resource, MAX_HTTP_URI_LENGTH, key)) {
					return false;
				}
				uint64_t requestId = 0;
				{
					std::lock_guard<std::mutex> lock(downloadMutex);
					auto i = downloadRequests.find(key);
					if(i != downloadRequests.end()) {
						requestId = i->second.id;
						downloadRequests.erase(i);
					}
				}
				if(requestId != 0) {
					Logger::log("[Protocol Analyzer] fetch #" + std::to_string(requestId) +
						" failed: " + key);
				}
				return false;
			}))
	{
		return false;
	}

	if(!Hooks::UI::onCreated([this](dcptr_t, bool&) -> bool {
			if(!stopping.load() && Config::getBoolConfig("Dialog")) {
				showGui("host UI creation");
			}
			return false;
		}) ||
		!UI::addCommand(showCommand, [this] {
			if(!stopping.load()) {
				showGui("the Show command");
			}
		}, string()) ||
		!UI::addCommand(hideCommand, [this] {
			if(!stopping.load()) {
				gui.close();
			}
		}, string()))
	{
		return false;
	}

	// DCPlusPlus-No-MDI fires HOOK_UI_CREATED once while MainWindow is being
	// initialized. ON_INSTALL and ON_LOAD_RUNTIME happen later on the UI
	// thread, so a runtime-loaded plugin must not wait for that past event.
	if(runtime && Config::getBoolConfig("Dialog")) {
		showGui(install ? "runtime installation" : "runtime activation");
	}

	return true;
}

void Plugin::showGui(const char* source) noexcept {
	if(stopping.load()) {
		return;
	}
	try {
		gui.create();
	} catch(const std::exception& error) {
		logGuiFailure(source, error.what());
	} catch(...) {
		logGuiFailure(source, "unknown GUI exception");
	}
}

bool Plugin::onHubDataIn(HubDataPtr hHub, char* message) {
	if(stopping.load() || !hHub || !message) {
		return false;
	}
	auto capturedMessage =
		boundedString(message, MAX_CAPTURE_MESSAGE_LENGTH);
	observeBloomHeader(hHub, false, capturedMessage);
	gui.write(false, hHub->protocol,
		boundedString(hHub->ip, MAX_NETWORK_ADDRESS_LENGTH), hHub->port,
		"Hub <" + boundedString(hHub->url, MAX_PEER_FIELD_LENGTH) + ">",
		std::move(capturedMessage));
	return false;
}

bool Plugin::onHubDataOut(HubDataPtr hHub, char* message) {
	if(stopping.load() || !hHub) {
		return false;
	}
	if(consumeExpectedBloomPayload(hHub, true)) {
		// The legacy network-hook ABI exposes binary sends as `char*` without
		// their length. Never inspect or copy this pointer: the correlated SND
		// header already supplied all metadata needed by the GUI.
		gui.write(true, hHub->protocol,
			boundedString(hHub->ip, MAX_NETWORK_ADDRESS_LENGTH), hHub->port,
			"Hub <" + boundedString(hHub->url, MAX_PEER_FIELD_LENGTH) + ">",
			string());
		return false;
	}
	if(!message) {
		return false;
	}
	auto capturedMessage =
		boundedString(message, MAX_CAPTURE_MESSAGE_LENGTH);
	observeBloomHeader(hHub, true, capturedMessage);
	gui.write(true, hHub->protocol,
		boundedString(hHub->ip, MAX_NETWORK_ADDRESS_LENGTH), hHub->port,
		"Hub <" + boundedString(hHub->url, MAX_PEER_FIELD_LENGTH) + ">",
		std::move(capturedMessage));
	return false;
}

namespace {

string userInfo(ConnectionDataPtr connection) {
	if(!connection) {
		return "[unknown]";
	}
	auto api = Connections::handle();
	if(!api || !api->get_user) {
		return "[unknown]";
	}

	UserDataPtr user = api->get_user(connection);
	if(!user) {
		return "[unknown]";
	}
	UserReleaseGuard release(user);
	const auto nick = boundedString(user->nick, MAX_PEER_FIELD_LENGTH);
	const auto hubHint = boundedString(user->hubHint, MAX_PEER_FIELD_LENGTH);
	return (nick.empty() ? string("[unknown]") : nick) +
		(hubHint.empty() ? string() : " <" + hubHint + ">");
}

} // unnamed namespace

bool Plugin::onClientDataIn(ConnectionDataPtr hConn, char* message) {
	if(stopping.load() || !hConn || !message) {
		return false;
	}
	gui.write(false, hConn->protocol,
		boundedString(hConn->ip, MAX_NETWORK_ADDRESS_LENGTH), hConn->port,
		"User " + userInfo(hConn),
		boundedString(message, MAX_CAPTURE_MESSAGE_LENGTH));
	return false;
}

bool Plugin::onClientDataOut(ConnectionDataPtr hConn, char* message) {
	if(stopping.load() || !hConn || !message) {
		return false;
	}
	gui.write(true, hConn->protocol,
		boundedString(hConn->ip, MAX_NETWORK_ADDRESS_LENGTH), hConn->port,
		"User " + userInfo(hConn),
		boundedString(message, MAX_CAPTURE_MESSAGE_LENGTH));
	return false;
}

bool Plugin::onUDPDataIn(UDPDataPtr data, char* message) {
	if(stopping.load() || !data || !message || !message[0]) {
		return false;
	}
	const string proto = message[0] == '$' ? "NMDC Search" : "ADC Search";
	gui.write(false, PROTOCOL_UDP,
		boundedString(data->ip, MAX_NETWORK_ADDRESS_LENGTH), data->port, proto,
		boundedString(message, MAX_CAPTURE_MESSAGE_LENGTH));
	return false;
}

bool Plugin::onUDPDataOut(UDPDataPtr data, char* message) {
	if(stopping.load() || !data || !message || !message[0]) {
		return false;
	}
	const string proto = message[0] == '$' ? "NMDC Search" : "ADC Search";
	gui.write(true, PROTOCOL_UDP,
		boundedString(data->ip, MAX_NETWORK_ADDRESS_LENGTH), data->port, proto,
		boundedString(message, MAX_CAPTURE_MESSAGE_LENGTH));
	return false;
}

bool Plugin::onChatCommand(HubDataPtr hub, CommandDataPtr cmd) {
	if(stopping.load() || !hub || !cmd || !cmd->command) {
		return false;
	}

	string command;
	if(!copyBounded(cmd->command, MAX_COMMAND_NAME_LENGTH, command)) {
		return false;
	}
	const char* params = cmd->params ? cmd->params : "";

	if(equalsNoCase(command, "help")) {
		localMessage(hub, "/raw <message>");
		localMessage(hub, "/fetch <http-or-https-url> [localpath]");
		// Allow the host to append its own general help.
		return false;
	}

	if(equalsNoCase(command, "fetch")) {
		string uri;
		string localPath;
		string error;
		if(!parseFetchArguments(params, uri, localPath, error)) {
			localMessage(hub, error.c_str());
			return true;
		}

		auto accessor = DataAccess::handle();
		if(!accessor || !accessor->get_http_resource) {
			localMessage(hub, "HTTP data access is unavailable.");
			return true;
		}

		uint64_t requestId = 0;
		const char* refusal = nullptr;
		{
			std::lock_guard<std::mutex> lock(downloadMutex);
			if(downloadRequests.size() >= MAX_ACTIVE_DOWNLOADS) {
				refusal = "Too many fetch requests are already active.";
			} else if(downloadRequests.find(uri) != downloadRequests.end()) {
				refusal = "A fetch for this URL is already active; wait for it to finish.";
			} else {
				requestId = nextDownloadId++;
				if(nextDownloadId == 0) {
					nextDownloadId = 1;
				}
				downloadRequests.emplace(uri, DownloadRequest {
					requestId, 0, false, !localPath.empty()
				});
			}
		}
		if(refusal) {
			localMessage(hub, refusal);
			return true;
		}

		Logger::log("[Protocol Analyzer] fetching #" + std::to_string(requestId) + ": " + uri);
		try {
			accessor->get_http_resource(uri.c_str(), localPath.c_str());
		} catch(...) {
			{
				std::lock_guard<std::mutex> lock(downloadMutex);
				auto i = downloadRequests.find(uri);
				if(i != downloadRequests.end() && i->second.id == requestId) {
					downloadRequests.erase(i);
				}
			}
			localMessage(hub, "The fetch request could not be started.");
		}
		return true;
	}

	if(equalsNoCase(command, "raw")) {
		string raw;
		if(!copyBounded(params, MAX_COMMAND_PARAMETER_LENGTH, raw, true) ||
			raw.find_first_not_of(" \t") == string::npos)
		{
			localMessage(hub, "Specify a protocol message to send.");
			return true;
		}
		if(hasUnsafeControl(raw)) {
			localMessage(hub, "Raw commands may not contain CR, LF, or other control characters.");
			return true;
		}

		auto api = Hubs::handle();
		if(!api || !api->send_protocol_cmd) {
			localMessage(hub, "Hub protocol access is unavailable.");
			return true;
		}
		try {
			api->send_protocol_cmd(hub, raw.c_str());
		} catch(...) {
			localMessage(hub, "The raw protocol command could not be sent.");
		}
		return true;
	}

	return false;
}
