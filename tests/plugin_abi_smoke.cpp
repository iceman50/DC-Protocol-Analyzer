/*
 * Headless ABI/lifecycle smoke test for the Protocol Analyzer DLL.
 *
 * This executable acts as a minimal DC++ host. It loads the built plugin,
 * supplies mock interfaces, drives representative hooks and commands, and
 * verifies that load, failure rollback, concurrent callback draining, and
 * unload complete without leaving registrations behind.
 */

#include <pluginsdk/PluginDefs.h>
#include <src/version.h>

#include <windows.h>
#include <commctrl.h>
#include <richedit.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iostream>
#include <iterator>
#include <limits>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

namespace {

using std::string;

struct HookRecord {
	string id;
	DCHOOK callback = nullptr;
	void* common = nullptr;
	bool active = true;
};

struct UiCommandRecord {
	const char* callbackName = nullptr;
	DCCommandFunc callback = nullptr;
};

std::mutex stateMutex;
std::vector<std::unique_ptr<HookRecord>> hookRecords;
std::unordered_map<string, UiCommandRecord> uiCommands;
std::unordered_map<string, string> stringConfig;
std::unordered_map<string, int32_t> intConfig;
std::unordered_map<string, Bool> boolConfig;
std::unordered_map<string, int64_t> int64Config;
std::vector<string> logMessages;
std::vector<std::pair<string, string>> fetchRequests;
std::vector<string> rawCommands;

string failedInterface;
unsigned releasedInterfaces = 0;
unsigned releasedUsers = 0;
unsigned failures = 0;

UserData mockUser {};

string configKey(const char* guid, const char* setting) {
	return string(guid ? guid : "") + '\n' + (setting ? setting : "");
}

char* duplicate(const string& value) {
	auto result = new char[value.size() + 1];
	std::memcpy(result, value.c_str(), value.size() + 1);
	return result;
}

ConfigStrPtr makeStringConfig(const string& value) {
	auto result = new ConfigStr;
	result->type = CFG_TYPE_STRING;
	result->value = duplicate(value);
	return result;
}

ConfigValuePtr DCAPI configGet(const char* guid, const char* setting, ConfigType type) {
	const auto key = configKey(guid, setting);
	std::lock_guard<std::mutex> lock(stateMutex);
	switch(type) {
	case CFG_TYPE_STRING: {
		auto i = stringConfig.find(key);
		return reinterpret_cast<ConfigValuePtr>(
			makeStringConfig(i == stringConfig.end() ? string() : i->second));
	}
	case CFG_TYPE_INT: {
		auto result = new ConfigInt;
		result->type = CFG_TYPE_INT;
		auto i = intConfig.find(key);
		result->value = i == intConfig.end() ? 0 : i->second;
		return reinterpret_cast<ConfigValuePtr>(result);
	}
	case CFG_TYPE_BOOL: {
		auto result = new ConfigBool;
		result->type = CFG_TYPE_BOOL;
		auto i = boolConfig.find(key);
		result->value = i == boolConfig.end() ? False : i->second;
		return reinterpret_cast<ConfigValuePtr>(result);
	}
	case CFG_TYPE_INT64: {
		auto result = new ConfigInt64;
		result->type = CFG_TYPE_INT64;
		auto i = int64Config.find(key);
		result->value = i == int64Config.end() ? 0 : i->second;
		return reinterpret_cast<ConfigValuePtr>(result);
	}
	default:
		return nullptr;
	}
}

void DCAPI configSet(const char* guid, const char* setting, ConfigValuePtr value) {
	if(!setting || !value) {
		return;
	}
	const auto key = configKey(guid, setting);
	std::lock_guard<std::mutex> lock(stateMutex);
	switch(value->type) {
	case CFG_TYPE_REMOVE:
		stringConfig.erase(key);
		intConfig.erase(key);
		boolConfig.erase(key);
		int64Config.erase(key);
		break;
	case CFG_TYPE_STRING: {
		auto typed = reinterpret_cast<ConfigStrPtr>(value);
		stringConfig[key] = typed->value ? typed->value : "";
		break;
	}
	case CFG_TYPE_INT:
		intConfig[key] = reinterpret_cast<ConfigIntPtr>(value)->value;
		break;
	case CFG_TYPE_BOOL:
		boolConfig[key] = reinterpret_cast<ConfigBoolPtr>(value)->value;
		break;
	case CFG_TYPE_INT64:
		int64Config[key] = reinterpret_cast<ConfigInt64Ptr>(value)->value;
		break;
	default:
		break;
	}
}

ConfigStrPtr DCAPI configPath(PathType) {
	return makeStringConfig("");
}

ConfigStrPtr DCAPI configInstallPath(const char*) {
	return makeStringConfig("");
}

ConfigStrPtr DCAPI configLanguage() {
	return makeStringConfig("en-US");
}

ConfigValuePtr DCAPI configCopy(const ConfigValuePtr value) {
	if(!value) {
		return nullptr;
	}
	switch(value->type) {
	case CFG_TYPE_STRING:
		return reinterpret_cast<ConfigValuePtr>(makeStringConfig(
			reinterpret_cast<ConfigStrPtr>(value)->value ?
				reinterpret_cast<ConfigStrPtr>(value)->value : ""));
	case CFG_TYPE_INT: {
		auto result = new ConfigInt(*reinterpret_cast<ConfigIntPtr>(value));
		return reinterpret_cast<ConfigValuePtr>(result);
	}
	case CFG_TYPE_BOOL: {
		auto result = new ConfigBool(*reinterpret_cast<ConfigBoolPtr>(value));
		return reinterpret_cast<ConfigValuePtr>(result);
	}
	case CFG_TYPE_INT64: {
		auto result = new ConfigInt64(*reinterpret_cast<ConfigInt64Ptr>(value));
		return reinterpret_cast<ConfigValuePtr>(result);
	}
	default:
		return nullptr;
	}
}

void DCAPI configRelease(ConfigValuePtr value) {
	if(!value) {
		return;
	}
	if(value->type == CFG_TYPE_STRING) {
		auto typed = reinterpret_cast<ConfigStrPtr>(value);
		delete[] const_cast<char*>(typed->value);
		delete typed;
		return;
	}
	switch(value->type) {
	case CFG_TYPE_INT:
		delete reinterpret_cast<ConfigIntPtr>(value);
		break;
	case CFG_TYPE_BOOL:
		delete reinterpret_cast<ConfigBoolPtr>(value);
		break;
	case CFG_TYPE_INT64:
		delete reinterpret_cast<ConfigInt64Ptr>(value);
		break;
	default:
		delete value;
		break;
	}
}

hookHandle DCAPI createHook(const char*, DCHOOK) {
	return reinterpret_cast<hookHandle>(1);
}

Bool DCAPI destroyHook(hookHandle) {
	return True;
}

subsHandle DCAPI bindHook(const char* id, DCHOOK callback, void* common) {
	if(!id || !callback || failedInterface == id) {
		return nullptr;
	}
	auto record = std::make_unique<HookRecord>();
	record->id = id;
	record->callback = callback;
	record->common = common;
	auto handle = record.get();
	std::lock_guard<std::mutex> lock(stateMutex);
	hookRecords.emplace_back(std::move(record));
	return reinterpret_cast<subsHandle>(handle);
}

Bool DCAPI runHook(hookHandle, dcptr_t, dcptr_t) {
	return False;
}

size_t DCAPI releaseHook(subsHandle handle) {
	std::lock_guard<std::mutex> lock(stateMutex);
	for(auto& record : hookRecords) {
		if(record.get() == handle && record->active) {
			record->active = false;
			return 0;
		}
	}
	return 0;
}

struct HookSnapshot {
	DCHOOK callback = nullptr;
	void* common = nullptr;
};

HookSnapshot findHook(const string& id) {
	std::lock_guard<std::mutex> lock(stateMutex);
	for(auto i = hookRecords.rbegin(); i != hookRecords.rend(); ++i) {
		if((*i)->active && (*i)->id == id) {
			return { (*i)->callback, (*i)->common };
		}
	}
	return {};
}

Bool fireHook(const string& id, dcptr_t object, dcptr_t data) {
	const auto hook = findHook(id);
	if(!hook.callback) {
		return False;
	}
	Bool shouldBreak = False;
	return hook.callback(object, data, hook.common, &shouldBreak);
}

size_t activeHookCount() {
	std::lock_guard<std::mutex> lock(stateMutex);
	return static_cast<size_t>(std::count_if(
		hookRecords.begin(), hookRecords.end(),
		[](const std::unique_ptr<HookRecord>& value) { return value->active; }));
}

void DCAPI addCommand(const char*, const char* name, DCCommandFunc callback, const char*) {
	if(!name || !callback) {
		return;
	}
	std::lock_guard<std::mutex> lock(stateMutex);
	// Match DC++ PluginApiWin: copy the menu label, but retain the plugin's raw
	// name pointer in the callback for invocation after add_command returns.
	uiCommands[name] = UiCommandRecord { name, callback };
}

void DCAPI removeCommand(const char*, const char* name) {
	if(!name) {
		return;
	}
	std::lock_guard<std::mutex> lock(stateMutex);
	uiCommands.erase(name);
}

void DCAPI playSound(const char*) { }
void DCAPI notify(const char*, const char*) { }

DCCommandFunc findUiCommand(const string& name) {
	std::lock_guard<std::mutex> lock(stateMutex);
	auto i = uiCommands.find(name);
	return i == uiCommands.end() ? nullptr : i->second.callback;
}

bool invokeUiCommand(const string& name) {
	UiCommandRecord command;
	{
		std::lock_guard<std::mutex> lock(stateMutex);
		auto i = uiCommands.find(name);
		if(i == uiCommands.end()) {
			return false;
		}
		command = i->second;
	}
	if(!command.callback || !command.callbackName) {
		return false;
	}
	command.callback(command.callbackName);
	return true;
}

size_t uiCommandCount() {
	std::lock_guard<std::mutex> lock(stateMutex);
	return uiCommands.size();
}

bool uiCommandCallbackNamesAreDistinct() {
	std::lock_guard<std::mutex> lock(stateMutex);
	const auto show = uiCommands.find("Show the dialog");
	const auto hide = uiCommands.find("Hide the dialog");
	return show != uiCommands.end() && hide != uiCommands.end() &&
		show->second.callbackName && hide->second.callbackName &&
		show->second.callbackName != hide->second.callbackName;
}

void DCAPI logMessage(const char* message) {
	std::lock_guard<std::mutex> lock(stateMutex);
	logMessages.emplace_back(message ? message : "");
}

void DCAPI sendUdp(const char*, uint32_t, dcptr_t, size_t) { }
void DCAPI sendConnectionCommand(ConnectionDataPtr, const char*) { }
void DCAPI terminateConnection(ConnectionDataPtr, Bool) { }

UserDataPtr DCAPI getUser(ConnectionDataPtr) {
	return &mockUser;
}

HubDataPtr DCAPI addHub(const char*, const char*, const char*) { return nullptr; }
HubDataPtr DCAPI findHub(const char*) { return nullptr; }
void DCAPI removeHub(HubDataPtr) { }
void DCAPI emulateHubCommand(HubDataPtr, const char*) { }

void DCAPI sendHubCommand(HubDataPtr, const char* command) {
	std::lock_guard<std::mutex> lock(stateMutex);
	rawCommands.emplace_back(command ? command : "");
}

void DCAPI sendHubMessage(HubDataPtr, const char*, Bool) { }
void DCAPI localHubMessage(HubDataPtr, const char*, MsgType) { }
Bool DCAPI sendPrivateMessage(UserDataPtr, const char*, Bool) { return True; }
UserDataPtr DCAPI findUser(const char*, const char*) { return nullptr; }
UserDataPtr DCAPI copyUser(const UserDataPtr user) { return const_cast<UserDataPtr>(user); }

void DCAPI releaseUser(UserDataPtr) {
	++releasedUsers;
}

HubDataPtr DCAPI copyHub(const HubDataPtr hub) { return const_cast<HubDataPtr>(hub); }
void DCAPI releaseHub(HubDataPtr) { }

size_t copyBytes(char* destination, const char* source, size_t capacity) {
	if(!source) {
		return 0;
	}
	const auto required = std::strlen(source);
	if(destination && capacity >= required) {
		std::memcpy(destination, source, required);
	}
	return required;
}

size_t DCAPI toUtf8(char* destination, const char* source, size_t capacity) {
	return copyBytes(destination, source, capacity);
}

size_t DCAPI fromUtf8(char* destination, const char* source, size_t capacity) {
	return copyBytes(destination, source, capacity);
}

size_t DCAPI utf8ToWide(wchar_t* destination, const char* source, size_t capacity) {
	if(!source) {
		return 0;
	}
	const int sourceLength = static_cast<int>(std::strlen(source));
	const int required = ::MultiByteToWideChar(CP_UTF8, 0, source, sourceLength, nullptr, 0);
	const size_t result = required > 0 ? static_cast<size_t>(required) : 0;
	if(destination && capacity >= result && required > 0) {
		::MultiByteToWideChar(
			CP_UTF8, 0, source, sourceLength, destination, static_cast<int>(capacity));
	}
	return result;
}

size_t DCAPI wideToUtf8(char* destination, const wchar_t* source, size_t capacity) {
	if(!source) {
		return 0;
	}
	const int sourceLength = static_cast<int>(std::wcslen(source));
	const int required = ::WideCharToMultiByte(
		CP_UTF8, 0, source, sourceLength, nullptr, 0, nullptr, nullptr);
	const size_t result = required > 0 ? static_cast<size_t>(required) : 0;
	if(destination && capacity >= result && required > 0) {
		::WideCharToMultiByte(
			CP_UTF8, 0, source, sourceLength, destination, static_cast<int>(capacity),
			nullptr, nullptr);
	}
	return result;
}

size_t DCAPI toBase32(char*, const uint8_t*, size_t) { return 0; }
size_t DCAPI fromBase32(uint8_t*, const char*, size_t) { return 0; }

void DCAPI getHttpResource(const char* uri, const char* path) {
	std::lock_guard<std::mutex> lock(stateMutex);
	fetchRequests.emplace_back(uri ? uri : "", path ? path : "");
}

DataArrayPtr DCAPI copyData(const DataArrayPtr value) {
	return const_cast<DataArrayPtr>(value);
}

void DCAPI releaseData(DataArrayPtr) { }

DCHooks hooksInterface {};
DCConfig configInterface {};
DCLog logInterface {};
DCConnection connectionInterface {};
DCHub hubInterface {};
DCUtils utilInterface {};
DCUI uiInterface {};
DCDataAccess dataAccessInterface {};

DCInterfacePtr DCAPI queryInterface(const char* id, uint32_t) {
	if(!id || (!failedInterface.empty() && failedInterface == id)) {
		return nullptr;
	}
	if(std::strcmp(id, DCINTF_HOOKS) == 0)
		return reinterpret_cast<DCInterfacePtr>(&hooksInterface);
	if(std::strcmp(id, DCINTF_CONFIG) == 0)
		return reinterpret_cast<DCInterfacePtr>(&configInterface);
	if(std::strcmp(id, DCINTF_LOGGING) == 0)
		return reinterpret_cast<DCInterfacePtr>(&logInterface);
	if(std::strcmp(id, DCINTF_DCPP_CONNECTIONS) == 0)
		return reinterpret_cast<DCInterfacePtr>(&connectionInterface);
	if(std::strcmp(id, DCINTF_DCPP_HUBS) == 0)
		return reinterpret_cast<DCInterfacePtr>(&hubInterface);
	if(std::strcmp(id, DCINTF_DCPP_UTILS) == 0)
		return reinterpret_cast<DCInterfacePtr>(&utilInterface);
	if(std::strcmp(id, DCINTF_DCPP_UI) == 0)
		return reinterpret_cast<DCInterfacePtr>(&uiInterface);
	if(std::strcmp(id, DCINTF_DCPP_DATAACCESSOR) == 0)
		return reinterpret_cast<DCInterfacePtr>(&dataAccessInterface);
	return nullptr;
}

intfHandle DCAPI registerInterface(const char*, dcptr_t) {
	return nullptr;
}

Bool DCAPI releaseInterface(intfHandle) {
	++releasedInterfaces;
	return True;
}

Bool DCAPI hasPlugin(const char*) {
	return False;
}

const char* DCAPI hostName() {
	return "Protocol Analyzer ABI smoke host";
}

DCCore coreInterface {};

void initializeInterfaces() {
	hooksInterface.apiVersion = DCINTF_HOOKS_VER;
	hooksInterface.create_hook = createHook;
	hooksInterface.destroy_hook = destroyHook;
	hooksInterface.bind_hook = bindHook;
	hooksInterface.run_hook = runHook;
	hooksInterface.release_hook = releaseHook;

	configInterface.apiVersion = DCINTF_CONFIG_VER;
	configInterface.get_path = configPath;
	configInterface.get_install_path = configInstallPath;
	configInterface.set_cfg = configSet;
	configInterface.get_cfg = configGet;
	configInterface.get_language = configLanguage;
	configInterface.copy = configCopy;
	configInterface.release = configRelease;

	logInterface.apiVersion = DCINTF_LOGGING_VER;
	logInterface.log = logMessage;

	connectionInterface.apiVersion = DCINTF_DCPP_CONNECTIONS_VER;
	connectionInterface.send_udp_data = sendUdp;
	connectionInterface.send_protocol_cmd = sendConnectionCommand;
	connectionInterface.terminate_conn = terminateConnection;
	connectionInterface.get_user = getUser;

	hubInterface.apiVersion = DCINTF_DCPP_HUBS_VER;
	hubInterface.add_hub = addHub;
	hubInterface.find_hub = findHub;
	hubInterface.remove_hub = removeHub;
	hubInterface.emulate_protocol_cmd = emulateHubCommand;
	hubInterface.send_protocol_cmd = sendHubCommand;
	hubInterface.send_message = sendHubMessage;
	hubInterface.local_message = localHubMessage;
	hubInterface.send_private_message = sendPrivateMessage;
	hubInterface.find_user = findUser;
	hubInterface.copy_user = copyUser;
	hubInterface.release_user = releaseUser;
	hubInterface.copy = copyHub;
	hubInterface.release = releaseHub;

	utilInterface.apiVersion = DCINTF_DCPP_UTILS_VER;
	utilInterface.to_utf8 = toUtf8;
	utilInterface.from_utf8 = fromUtf8;
	utilInterface.utf8_to_wcs = utf8ToWide;
	utilInterface.wcs_to_utf8 = wideToUtf8;
	utilInterface.to_base32 = toBase32;
	utilInterface.from_base32 = fromBase32;

	uiInterface.apiVersion = DCINTF_DCPP_UI_VER;
	uiInterface.add_command = addCommand;
	uiInterface.remove_command = removeCommand;
	uiInterface.play_sound = playSound;
	uiInterface.notify = notify;

	dataAccessInterface.apiVersion = DCINTF_DCPP_DATAACCESSOR_VER;
	dataAccessInterface.get_http_resource = getHttpResource;
	dataAccessInterface.copy = copyData;
	dataAccessInterface.release = releaseData;

	coreInterface.apiVersion = DCAPI_CORE_VER;
	coreInterface.register_interface = registerInterface;
	coreInterface.query_interface = queryInterface;
	coreInterface.release_interface = releaseInterface;
	coreInterface.has_plugin = hasPlugin;
	coreInterface.host_name = hostName;

	mockUser.nick = "Smoke User";
	mockUser.hubHint = "adc://smoke.invalid";
	mockUser.cid = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	mockUser.object = nullptr;
	mockUser.sid = 1;
	mockUser.protocol = PROTOCOL_ADC;
	mockUser.isOp = False;
	mockUser.isManaged = True;
}

void expect(bool condition, const string& message) {
	if(condition) {
		std::cout << "PASS: " << message << '\n';
		return;
	}
	++failures;
	std::cerr << "FAIL: " << message << '\n';
}

bool logsContain(const string& needle) {
	std::lock_guard<std::mutex> lock(stateMutex);
	return std::any_of(logMessages.begin(), logMessages.end(), [&](const string& message) {
		return message.find(needle) != string::npos;
	});
}

void pumpMessages(std::chrono::milliseconds duration) {
	const auto deadline = std::chrono::steady_clock::now() + duration;
	do {
		MSG message {};
		while(::PeekMessageW(&message, nullptr, 0, 0, PM_REMOVE)) {
			if(message.message != WM_QUIT) {
				::TranslateMessage(&message);
				::DispatchMessageW(&message);
			}
		}
		::Sleep(1);
	} while(std::chrono::steady_clock::now() < deadline);
}

struct WindowSearch {
	DWORD processId = 0;
	const wchar_t* captionFragment = nullptr;
	HWND result = nullptr;
};

BOOL CALLBACK findTopLevelWindowProc(HWND windowHandle, LPARAM parameter) {
	auto search = reinterpret_cast<WindowSearch*>(parameter);
	if(!search || search->result) {
		return FALSE;
	}
	DWORD processId = 0;
	::GetWindowThreadProcessId(windowHandle, &processId);
	if(processId != search->processId) {
		return TRUE;
	}
	wchar_t caption[512] {};
	::GetWindowTextW(windowHandle, caption,
		static_cast<int>(sizeof(caption) / sizeof(caption[0])));
	if(search->captionFragment && std::wcsstr(caption, search->captionFragment)) {
		search->result = windowHandle;
		return FALSE;
	}
	return TRUE;
}

HWND findTopLevelWindow(const wchar_t* captionFragment) {
	WindowSearch search { ::GetCurrentProcessId(), captionFragment, nullptr };
	::EnumWindows(findTopLevelWindowProc, reinterpret_cast<LPARAM>(&search));
	return search.result;
}

struct ChildSearch {
	const wchar_t* className = nullptr;
	const wchar_t* caption = nullptr;
	HWND result = nullptr;
};

BOOL CALLBACK findChildWindowProc(HWND windowHandle, LPARAM parameter) {
	auto search = reinterpret_cast<ChildSearch*>(parameter);
	if(!search || search->result) {
		return FALSE;
	}
	wchar_t className[128] {};
	wchar_t caption[512] {};
	::RealGetWindowClassW(windowHandle, className,
		static_cast<UINT>(sizeof(className) / sizeof(className[0])));
	::GetWindowTextW(windowHandle, caption,
		static_cast<int>(sizeof(caption) / sizeof(caption[0])));
	const bool classMatches = !search->className ||
		std::wcscmp(className, search->className) == 0;
	const bool captionMatches = !search->caption ||
		std::wcscmp(caption, search->caption) == 0;
	if(classMatches && captionMatches) {
		search->result = windowHandle;
		return FALSE;
	}
	return TRUE;
}

HWND findChildWindow(
	HWND parent, const wchar_t* className, const wchar_t* caption = nullptr)
{
	ChildSearch search { className, caption, nullptr };
	if(parent) {
		::EnumChildWindows(parent, findChildWindowProc,
			reinterpret_cast<LPARAM>(&search));
	}
	return search.result;
}

struct TopmostChildSearch {
	const wchar_t* className = nullptr;
	const wchar_t* caption = nullptr;
	HWND parent = nullptr;
	HWND result = nullptr;
	LONG top = (std::numeric_limits<LONG>::max)();
};

BOOL CALLBACK findTopmostChildWindowProc(
	HWND windowHandle, LPARAM parameter)
{
	auto search = reinterpret_cast<TopmostChildSearch*>(parameter);
	if(!search) {
		return TRUE;
	}
	wchar_t className[128] {};
	wchar_t caption[512] {};
	::RealGetWindowClassW(windowHandle, className,
		static_cast<UINT>(sizeof(className) / sizeof(className[0])));
	::GetWindowTextW(windowHandle, caption,
		static_cast<int>(sizeof(caption) / sizeof(caption[0])));
	if((!search->className ||
			std::wcscmp(className, search->className) == 0) &&
		(!search->caption ||
			std::wcscmp(caption, search->caption) == 0))
	{
		RECT bounds {};
		if(::GetWindowRect(windowHandle, &bounds)) {
			::MapWindowPoints(HWND_DESKTOP, search->parent,
				reinterpret_cast<POINT*>(&bounds), 2);
			if(bounds.top < search->top) {
				search->top = bounds.top;
				search->result = windowHandle;
			}
		}
	}
	return TRUE;
}

HWND findTopmostChildWindow(
	HWND parent, const wchar_t* className, const wchar_t* caption)
{
	TopmostChildSearch search {
		className, caption, parent, nullptr,
		(std::numeric_limits<LONG>::max)()
	};
	if(parent) {
		::EnumChildWindows(parent, findTopmostChildWindowProc,
			reinterpret_cast<LPARAM>(&search));
	}
	return search.result;
}

BOOL CALLBACK findListViewProc(HWND windowHandle, LPARAM parameter) {
	auto result = reinterpret_cast<HWND*>(parameter);
	if(!result || *result) {
		return FALSE;
	}
	const auto header = reinterpret_cast<HWND>(
		::SendMessageW(windowHandle, LVM_GETHEADER, 0, 0));
	if(header && ::IsWindow(header)) {
		wchar_t className[32] {};
		::RealGetWindowClassW(header, className,
			static_cast<UINT>(sizeof(className) / sizeof(className[0])));
		if(std::wcscmp(className, WC_HEADERW) == 0) {
			*result = windowHandle;
			return FALSE;
		}
	}
	return TRUE;
}

HWND findListView(HWND parent) {
	HWND result = nullptr;
	if(parent) {
		::EnumChildWindows(parent, findListViewProc,
			reinterpret_cast<LPARAM>(&result));
	}
	return result;
}

void clickButton(HWND button) {
	if(!button) {
		return;
	}
	const auto parent = ::GetParent(button);
	if(parent) {
		::SendMessageW(parent, WM_COMMAND, MAKEWPARAM(0, BN_CLICKED),
			reinterpret_cast<LPARAM>(button));
	}
}

BOOL CALLBACK describeChildWindowProc(HWND windowHandle, LPARAM) {
	wchar_t className[128] {};
	::RealGetWindowClassW(windowHandle, className,
		static_cast<UINT>(sizeof(className) / sizeof(className[0])));
	std::wcerr << L"  child class=\"" << className << L"\"" << std::endl;
	return TRUE;
}

BOOL CALLBACK findReadOnlyMultilineEditProc(HWND windowHandle, LPARAM parameter) {
	auto result = reinterpret_cast<HWND*>(parameter);
	if(!result || *result) {
		return FALSE;
	}
	wchar_t className[32] {};
	::RealGetWindowClassW(windowHandle, className,
		static_cast<UINT>(sizeof(className) / sizeof(className[0])));
	const auto style = static_cast<DWORD_PTR>(::GetWindowLongPtrW(windowHandle, GWL_STYLE));
	const bool supportedClass = std::wcscmp(className, L"Edit") == 0 ||
		_wcsnicmp(className, L"RichEdit", 8) == 0 ||
		std::wcsstr(className, L"RichTextBox") != nullptr;
	if(supportedClass &&
		(style & ES_MULTILINE) != 0 && (style & ES_READONLY) != 0)
	{
		*result = windowHandle;
		return FALSE;
	}
	return TRUE;
}

HWND findInspector(HWND parent) {
	HWND result = nullptr;
	if(parent) {
		::EnumChildWindows(parent, findReadOnlyMultilineEditProc,
			reinterpret_cast<LPARAM>(&result));
	}
	return result;
}

std::wstring listViewText(HWND list, int row, int column) {
	wchar_t buffer[512] {};
	LVITEMW item {};
	item.iSubItem = column;
	item.pszText = buffer;
	item.cchTextMax = static_cast<int>(sizeof(buffer) / sizeof(buffer[0]));
	::SendMessageW(list, LVM_GETITEMTEXTW, static_cast<WPARAM>(row),
		reinterpret_cast<LPARAM>(&item));
	return buffer;
}

std::wstring windowText(HWND windowHandle) {
	if(!windowHandle) {
		return {};
	}
	const int length = ::GetWindowTextLengthW(windowHandle);
	if(length <= 0 || length > 32768) {
		return {};
	}
	std::vector<wchar_t> buffer(static_cast<size_t>(length) + 1, L'\0');
	const int copied = ::GetWindowTextW(
		windowHandle, buffer.data(), static_cast<int>(buffer.size()));
	return copied > 0 ? std::wstring(buffer.data(), static_cast<size_t>(copied)) :
		std::wstring();
}

bool isRichEdit(HWND windowHandle) {
	if(!windowHandle) {
		return false;
	}
	wchar_t className[32] {};
	::RealGetWindowClassW(windowHandle, className,
		static_cast<UINT>(sizeof(className) / sizeof(className[0])));
	return _wcsnicmp(className, L"RichEdit", 8) == 0 ||
		std::wcsstr(className, L"RichTextBox") != nullptr;
}

COLORREF characterColor(HWND windowHandle, LONG offset) {
	if(!windowHandle || offset < 0) {
		return CLR_INVALID;
	}
	CHARRANGE previous {};
	::SendMessageW(windowHandle, EM_EXGETSEL, 0,
		reinterpret_cast<LPARAM>(&previous));
	CHARRANGE selected { offset, offset + 1 };
	::SendMessageW(windowHandle, EM_EXSETSEL, 0,
		reinterpret_cast<LPARAM>(&selected));
	CHARFORMAT2W format {};
	format.cbSize = sizeof(format);
	::SendMessageW(windowHandle, EM_GETCHARFORMAT, SCF_SELECTION,
		reinterpret_cast<LPARAM>(&format));
	::SendMessageW(windowHandle, EM_EXSETSEL, 0,
		reinterpret_cast<LPARAM>(&previous));
	return (format.dwMask & CFM_COLOR) != 0 ?
		format.crTextColor : CLR_INVALID;
}

bool fillsParentClient(HWND child, LONG tolerance = 2) {
	if(!child) {
		return false;
	}
	const auto parent = ::GetParent(child);
	if(!parent) {
		return false;
	}

	RECT parentClient {};
	RECT childBounds {};
	if(!::GetClientRect(parent, &parentClient) ||
		!::GetWindowRect(child, &childBounds))
	{
		return false;
	}
	::MapWindowPoints(HWND_DESKTOP, parent,
		reinterpret_cast<POINT*>(&childBounds), 2);
	return childBounds.left <= parentClient.left + tolerance &&
		childBounds.top <= parentClient.top + tolerance &&
		childBounds.right >= parentClient.right - tolerance &&
		childBounds.bottom >= parentClient.bottom - tolerance;
}

bool clientFillsWindow(HWND windowHandle, LONG tolerance = 0) {
	if(!windowHandle) {
		return false;
	}
	RECT windowBounds {};
	RECT clientBounds {};
	if(!::GetWindowRect(windowHandle, &windowBounds) ||
		!::GetClientRect(windowHandle, &clientBounds))
	{
		return false;
	}
	::MapWindowPoints(windowHandle, HWND_DESKTOP,
		reinterpret_cast<POINT*>(&clientBounds), 2);
	auto closeEnough = [tolerance](LONG left, LONG right) {
		return left >= right - tolerance && left <= right + tolerance;
	};
	return closeEnough(clientBounds.left, windowBounds.left) &&
		closeEnough(clientBounds.top, windowBounds.top) &&
		closeEnough(clientBounds.right, windowBounds.right) &&
		closeEnough(clientBounds.bottom, windowBounds.bottom);
}

std::wstring requestInfoTip(HWND list, int row, int column) {
	if(!list) {
		return {};
	}
	wchar_t buffer[512] {};
	std::wcscpy(buffer, L"<notification not handled>");
	NMLVGETINFOTIPW tip {};
	tip.hdr.hwndFrom = list;
	tip.hdr.idFrom = static_cast<UINT_PTR>(::GetDlgCtrlID(list));
	tip.hdr.code = LVN_GETINFOTIPW;
	tip.pszText = buffer;
	tip.cchTextMax = static_cast<int>(sizeof(buffer) / sizeof(buffer[0]));
	tip.iItem = row;
	tip.iSubItem = column;
	const auto parent = ::GetParent(list);
	if(parent) {
		::SendMessageW(parent, WM_NOTIFY, tip.hdr.idFrom,
			reinterpret_cast<LPARAM>(&tip));
	}
	return buffer;
}

typedef DCMAIN (DCAPI *PluginInitFunction)(MetaDataPtr);

} // namespace

int main(int argc, char** argv) {
	if(argc != 2) {
		std::cerr << "Usage: plugin_abi_smoke.exe <ProtocolAnalyzer.dll>\n";
		return 2;
	}

	initializeInterfaces();
	const auto module = ::LoadLibraryA(argv[1]);
	if(!module) {
		std::cerr << "Unable to load plugin DLL, Win32 error " << ::GetLastError() << '\n';
		return 2;
	}

	const auto symbol = ::GetProcAddress(module, "pluginInit");
	PluginInitFunction init = nullptr;
	static_assert(sizeof(init) == sizeof(symbol), "function pointer size mismatch");
	std::memcpy(&init, &symbol, sizeof(init));
	if(!init) {
		std::cerr << "pluginInit export missing\n";
		::FreeLibrary(module);
		return 2;
	}

	expect(init(nullptr) == nullptr, "pluginInit rejects null metadata");

	MetaData metadata;
	std::memset(&metadata, 0xA5, sizeof(metadata));
	const auto pluginMain = init(&metadata);
	expect(pluginMain != nullptr, "pluginInit returns a main callback");
	expect(metadata.name && std::strlen(metadata.name) != 0, "metadata name initialized");
	expect(metadata.guid && std::strlen(metadata.guid) != 0, "metadata GUID initialized");
	expect(metadata.guid && std::strcmp(metadata.guid, PLUGIN_GUID) == 0,
		"runtime metadata uses the Protocol Analyzer GUID");
	expect(metadata.dependencies == nullptr, "metadata dependency pointer initialized");
	expect(metadata.numDependencies == 0, "metadata dependency count initialized");

	if(!pluginMain) {
		::FreeLibrary(module);
		return 1;
	}

	char temporaryDirectory[MAX_PATH + 1] {};
	const DWORD temporaryLength = ::GetTempPathA(
		static_cast<DWORD>(sizeof(temporaryDirectory)), temporaryDirectory);
	const string protocolLogPath =
		temporaryLength > 0 && temporaryLength < sizeof(temporaryDirectory) ?
			string(temporaryDirectory) + "ProtocolAnalyzer-smoke-" +
				std::to_string(::GetCurrentProcessId()) + ".log" :
			string();
	if(!protocolLogPath.empty()) {
		::DeleteFileA(protocolLogPath.c_str());
		std::lock_guard<std::mutex> lock(stateMutex);
		stringConfig[configKey(metadata.guid, "Log")] = protocolLogPath;
	}
	{
		std::lock_guard<std::mutex> lock(stateMutex);
		// Exercise normalization of an unsafe persisted value while keeping the
		// smoke test small enough to saturate the configured queue.
		intConfig[configKey(metadata.guid, "CaptureQueueCapacity")] = 1;
	}

	expect(pluginMain(ON_LOAD_RUNTIME, nullptr, nullptr) == False,
		"load rejects a null core");
	expect(pluginMain(ON_INSTALL, &coreInterface, nullptr) == True,
		"runtime installation succeeds");
	{
		std::lock_guard<std::mutex> lock(stateMutex);
		const auto configured =
			intConfig.find(configKey(metadata.guid, "CaptureQueueCapacity"));
		expect(configured != intConfig.end() && configured->second == 64,
			"capture queue capacity is clamped to its secure minimum");
	}
	expect(activeHookCount() >= 10, "runtime load registers expected hooks");
	expect(uiCommandCount() == 2, "runtime load registers both UI commands");
	expect(uiCommandCallbackNamesAreDistinct(),
		"UI commands expose distinct persistent names to the host callbacks");
	pumpMessages(std::chrono::milliseconds(50));
	const auto installedWindow = findTopLevelWindow(L"Protocol Analyzer");
	expect(installedWindow != nullptr && ::IsWindowVisible(installedWindow),
		"runtime installation opens the protocol-monitor window");
	expect(pluginMain(ON_LOAD_RUNTIME, &coreInterface, nullptr) == False,
		"duplicate load is rejected without replacing the active instance");

	HubData hub {};
	hub.url = "adc://smoke.invalid";
	hub.ip = "127.0.0.1";
	hub.port = 411;
	hub.protocol = PROTOCOL_ADC;
	hub.isManaged = True;

	char hubMessage[] = "ISUP ADBASE";
	expect(fireHook(HOOK_NETWORK_HUB_IN, &hub, hubMessage) == False,
		"network capture hook remains observational");
	char adcKeepAlive[] = "\n";
	expect(fireHook(HOOK_NETWORK_HUB_OUT, &hub, adcKeepAlive) == False,
		"ADC keep-alive capture remains observational");

	ConnectionData connection {};
	connection.ip = "127.0.0.2";
	connection.port = 412;
	connection.protocol = PROTOCOL_ADC;
	connection.isManaged = True;
	char clientMessage[] = "CSUP ADBASE";
	const auto releaseBefore = releasedUsers;
	mockUser.isManaged = True;

	HubData nmdcHub = hub;
	nmdcHub.url = "dchub://smoke.invalid";
	nmdcHub.protocol = PROTOCOL_NMDC;
	const string passwordSecret = "SMOKE_PASSWORD_MUST_NOT_LEAK";
	const string diagnosticPasswordSecret = "SMOKE_PASSWORD_VISIBLE_FOR_DEBUG";
	string passwordCommandText = "$MyPass " + passwordSecret + "|";
	std::vector<char> passwordCommand(
		passwordCommandText.begin(), passwordCommandText.end());
	passwordCommand.push_back('\0');
	fireHook(HOOK_NETWORK_HUB_OUT, &nmdcHub, passwordCommand.data());
	char richEditLiteralMessage[] =
		"IINF NIbrace{value} DEpath\\\\folder";
	fireHook(HOOK_NETWORK_HUB_IN, &hub, richEditLiteralMessage);
	fireHook(HOOK_NETWORK_CONN_IN, &connection, clientMessage);
	expect(releasedUsers == releaseBefore, "managed user data is not released");
	mockUser.isManaged = False;
	fireHook(HOOK_NETWORK_CONN_IN, &connection, clientMessage);
	expect(releasedUsers == releaseBefore + 1, "unmanaged user data is released once");
	mockUser.isManaged = True;

	char bloomGet[] = "IGET blom / 0 92408 BK8 BH24";
	char bloomSend[] = "HSND blom / 0 92408 BK8\n";
	fireHook(HOOK_NETWORK_HUB_IN, &hub, bloomGet);
	fireHook(HOOK_NETWORK_HUB_OUT, &hub, bloomSend);
	auto inaccessibleBloomBody = ::VirtualAlloc(
		nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	expect(inaccessibleBloomBody != nullptr,
		"BLOM early-guard test allocates a sentinel page");
	if(inaccessibleBloomBody) {
		DWORD previousProtection = 0;
		const bool protectedBody = ::VirtualProtect(
			inaccessibleBloomBody, 4096, PAGE_NOACCESS,
			&previousProtection) != FALSE;
		expect(protectedBody,
			"BLOM early-guard test makes the body unreadable");
		expect(fireHook(HOOK_NETWORK_HUB_OUT, &hub,
				inaccessibleBloomBody) == False,
			"BLOM payload hook remains observational without reading its body");
		if(protectedBody) {
			DWORD ignoredProtection = 0;
			::VirtualProtect(inaccessibleBloomBody, 4096,
				previousProtection, &ignoredProtection);
		}
		::VirtualFree(inaccessibleBloomBody, 0, MEM_RELEASE);
	}
	char afterBloom[] = "HINF NIAfterBinaryBloom";
	fireHook(HOOK_NETWORK_HUB_OUT, &hub, afterBloom);

	// A zero-byte SND has no body. Its successor must remain ordinary ADC
	// traffic rather than being consumed as an empty bloom payload.
	char emptyBloomGet[] = "IGET blom / 0 0 BK8 BH24";
	char emptyBloomSend[] = "HSND blom / 0 0 BK8\n";
	char afterEmptyBloom[] = "HINF NIZeroByteBloomFollowup";
	fireHook(HOOK_NETWORK_HUB_IN, &hub, emptyBloomGet);
	fireHook(HOOK_NETWORK_HUB_OUT, &hub, emptyBloomSend);
	fireHook(HOOK_NETWORK_HUB_OUT, &hub, afterEmptyBloom);

	const string bloomSecret = "BLOOM_BODY_MUST_NOT_REACH_RICHEDIT";
	char smallBloomGet[] = "IGET blom / 0 16 BK1 BH8";
	char smallBloomSend[] = "HSND blom / 0 16 BK1\n";
	fireHook(HOOK_NETWORK_HUB_IN, &hub, smallBloomGet);
	fireHook(HOOK_NETWORK_HUB_OUT, &hub, smallBloomSend);
	std::vector<char> smallBloomBody {
		static_cast<char>(0x01), static_cast<char>(0xfe)
	};
	smallBloomBody.insert(
		smallBloomBody.end(), bloomSecret.begin(), bloomSecret.end());
	smallBloomBody.push_back('\0');
	fireHook(HOOK_NETWORK_HUB_OUT, &hub, smallBloomBody.data());

	// A stand-alone HSND can be injected with /raw; without the matching IGET
	// it must not consume the next legitimate message.
	char uncorrelatedBloomSend[] = "HSND blom / 0 16 BK1\n";
	char afterUncorrelatedBloom[] = "HINF NIUncorrelatedBloomFollowup";
	fireHook(HOOK_NETWORK_HUB_OUT, &hub, uncorrelatedBloomSend);
	fireHook(HOOK_NETWORK_HUB_OUT, &hub, afterUncorrelatedBloom);

	HubData otherVirtualHub = hub;
	otherVirtualHub.url = "adc://other-virtual-hub.invalid";
	otherVirtualHub.object = &otherVirtualHub;
	char isolatedBloomGet[] = "IGET blom / 0 24 BK1 BH8";
	char isolatedBloomSend[] = "HSND blom / 0 24 BK1\n";
	char afterIsolatedBloom[] = "HINF NIVirtualHubIsolation";
	fireHook(HOOK_NETWORK_HUB_IN, &hub, isolatedBloomGet);
	fireHook(HOOK_NETWORK_HUB_OUT, &otherVirtualHub, isolatedBloomSend);
	fireHook(HOOK_NETWORK_HUB_OUT, &otherVirtualHub, afterIsolatedBloom);

	CommandData rawCommand { "raw", "BINF IDSMOKE" };
	expect(fireHook(HOOK_UI_CHAT_COMMAND, &hub, &rawCommand) == True,
		"/raw is reported as handled");
	expect(rawCommands.size() == 1 && rawCommands.back() == "BINF IDSMOKE",
		"/raw is sent exactly once");

	const auto fetchCount = fetchRequests.size();
	CommandData invalidFetch { "fetch", "file:///C:/Windows/win.ini" };
	expect(fireHook(HOOK_UI_CHAT_COMMAND, &hub, &invalidFetch) == True,
		"invalid /fetch input is still consumed");
	expect(fetchRequests.size() == fetchCount,
		"non-HTTP fetch schemes are rejected");

	CommandData fetchCommand { "fetch", "https://example.invalid/smoke.bin" };
	expect(fireHook(HOOK_UI_CHAT_COMMAND, &hub, &fetchCommand) == True,
		"/fetch is reported as handled");
	expect(fetchRequests.size() == fetchCount + 1,
		"valid HTTPS fetch reaches the data-access interface");
	expect(fireHook(HOOK_UI_CHAT_COMMAND, &hub, &fetchCommand) == True,
		"a duplicate in-flight /fetch is still consumed");
	expect(fetchRequests.size() == fetchCount + 1,
		"duplicate URI requests are not conflated");

	char resource[] = "https://example.invalid/smoke.bin";
	const char payload[] = "smoke";
	DataArray data { payload, sizeof(payload) - 1 };
	fireHook(HOOK_DATAACESSOR_HTTP_RESOURCE_STREAM, resource, &data);
	fireHook(HOOK_DATAACESSOR_HTTP_RESOURCE_NOTIFICATION, resource, nullptr);
	expect(logsContain(" complete: https://example.invalid/smoke.bin"),
		"fetch completion is logged");

	const auto hook = findHook(HOOK_NETWORK_HUB_IN);
	expect(hook.callback != nullptr, "network hook can be located for race test");
	if(hook.callback) {
		const char unknownKey[] = "smoke.invalid.hook";
		Bool shouldBreak = False;
		expect(hook.callback(&hub, hubMessage,
			const_cast<char*>(unknownKey), &shouldBreak) == False,
			"unknown hook callback key fails closed");
		expect(hook.callback(&hub, hubMessage, nullptr, &shouldBreak) == False,
			"null hook callback key fails closed");
	}

	for(unsigned i = 0; i < 80; ++i) {
		const auto queuedText = string("IINF NIQueueSmoke") + std::to_string(i);
		std::vector<char> queuedMessage(queuedText.begin(), queuedText.end());
		queuedMessage.push_back('\0');
		fireHook(HOOK_NETWORK_HUB_IN, &hub, queuedMessage.data());
	}

	const auto commandCallback = findUiCommand("Show the dialog");
	expect(commandCallback != nullptr, "UI command trampoline can be located");
	if(commandCallback) {
		commandCallback("not a registered command");
		expect(invokeUiCommand("Show the dialog"),
			"mock host invokes Show with its retained command-name pointer");
		pumpMessages(std::chrono::milliseconds(400));

		const auto pluginWindow = findTopLevelWindow(L"Protocol Analyzer");
		expect(pluginWindow != nullptr && ::IsWindowVisible(pluginWindow),
			"Show command creates a visible DWT protocol-monitor window");
		if(pluginWindow) {
			const auto windowStyle = static_cast<DWORD_PTR>(
				::GetWindowLongPtrW(pluginWindow, GWL_STYLE));
			expect((windowStyle & WS_CAPTION) == 0,
				"protocol monitor replaces the native caption");
			expect((windowStyle & WS_THICKFRAME) != 0,
				"custom caption retains the native sizing frame");
			expect(clientFillsWindow(pluginWindow),
				"custom frame paints through the complete restored window");

			RECT client {};
			::GetClientRect(pluginWindow, &client);
			POINT captionPoint {
				(client.right - client.left) / 2,
				20
			};
			::ClientToScreen(pluginWindow, &captionPoint);
			const auto hit = ::SendMessageW(pluginWindow, WM_NCHITTEST, 0,
				MAKELPARAM(captionPoint.x, captionPoint.y));
			expect(hit == HTCAPTION,
				"custom caption delegates native window dragging");

			POINT resizePoint { 1, 1 };
			::ClientToScreen(pluginWindow, &resizePoint);
			const auto resizeHit = ::SendMessageW(pluginWindow, WM_NCHITTEST, 0,
				MAKELPARAM(resizePoint.x, resizePoint.y));
			expect(resizeHit == HTTOPLEFT,
				"fully client-drawn frame retains corner resizing");

			const auto minimizeCaption =
				findChildWindow(pluginWindow, L"Button", L"Minimize");
			const auto maximizeCaption =
				findChildWindow(pluginWindow, L"Button", L"Maximize");
			expect(minimizeCaption != nullptr && maximizeCaption != nullptr,
				"custom caption exposes minimize and maximize controls");
			if(maximizeCaption) {
				clickButton(maximizeCaption);
				pumpMessages(std::chrono::milliseconds(20));
				expect(::IsZoomed(pluginWindow) &&
					windowText(maximizeCaption) == L"Restore",
					"custom caption maximizes and exposes restore state");
				clickButton(maximizeCaption);
				pumpMessages(std::chrono::milliseconds(20));
				expect(!::IsZoomed(pluginWindow) &&
					windowText(maximizeCaption) == L"Maximize",
					"custom caption restores the window");
			}
		}

		const auto listView = findListView(pluginWindow);
		if(pluginWindow && !listView) {
			std::wcerr << L"Protocol Monitor child-window diagnostic:" << std::endl;
			::EnumChildWindows(pluginWindow, describeChildWindowProc, 0);
		}
		const auto initialItemCount = listView ?
			static_cast<int>(::SendMessageW(listView, LVM_GETITEMCOUNT, 0, 0)) : 0;
		expect(listView != nullptr, "protocol table is a native DWT list view");
		expect(initialItemCount > 0,
			"captured traffic is drained into the visible table");
		expect(initialItemCount == 64,
			"configured capture queue capacity bounds pending traffic");
		if(listView && initialItemCount > 0) {
			const auto inspector = findInspector(pluginWindow);
			if(!inspector) {
				std::wcerr << L"Decoded inspector child-window diagnostic:"
					<< std::endl;
				::EnumChildWindows(pluginWindow, describeChildWindowProc, 0);
			}
			expect(inspector != nullptr && fillsParentClient(inspector),
				"decoded RichEdit fills its inspector grid cell");
			expect(inspector != nullptr && isRichEdit(inspector),
				"decoded inspector uses a Win7-compatible native RichEdit control");

			const auto timestamp = listViewText(listView, 0, 0);
			expect(!timestamp.empty() && timestamp.front() == L'[',
				"visible messages include a timestamp");
			int keepAliveRow = -1;
			for(int row = 0; row < initialItemCount; ++row) {
				if(listViewText(listView, row, 4) == L"KEEPALIVE") {
					keepAliveRow = row;
					break;
				}
			}
			expect(keepAliveRow >= 0 &&
				listViewText(listView, keepAliveRow, 5) == L"Control",
				"ADC line-feed keep-alive is displayed as valid control traffic");

			constexpr int summaryColumn = 9;
			const auto summary = listViewText(listView, 0, summaryColumn);
			const auto originalSummaryWidth = static_cast<int>(::SendMessageW(
				listView, LVM_GETCOLUMNWIDTH, summaryColumn, 0));
			::SendMessageW(listView, LVM_SETCOLUMNWIDTH, summaryColumn, 24);
			const auto truncatedTip =
				requestInfoTip(listView, 0, summaryColumn);
			if(summary.empty() || truncatedTip != summary) {
				std::wcerr << L"Tooltip diagnostic: expected=\"" << summary
					<< L"\" actual=\"" << truncatedTip << L"\" width="
					<< ::SendMessageW(listView, LVM_GETCOLUMNWIDTH,
						summaryColumn, 0) << std::endl;
			}
			expect(!summary.empty() && truncatedTip == summary,
				"truncated table data exposes its complete text in a cell tooltip");
			::SendMessageW(listView, LVM_SETCOLUMNWIDTH, summaryColumn, 4096);
			expect(requestInfoTip(listView, 0, summaryColumn).empty(),
				"table tooltips remain hidden when the complete cell text fits");
			::SendMessageW(listView, LVM_SETCOLUMNWIDTH, summaryColumn,
				originalSummaryWidth);

			LVITEMW selection {};
			selection.stateMask = LVIS_SELECTED | LVIS_FOCUSED;
			selection.state = LVIS_SELECTED | LVIS_FOCUSED;
			::SendMessageW(listView, LVM_SETITEMSTATE, 0,
				reinterpret_cast<LPARAM>(&selection));
			expect(::SendMessageW(listView, LVM_GETSELECTEDCOUNT, 0, 0) == 1,
				"table rows can be selected independently");

			int passwordRow = -1;
			for(int row = 0; row < initialItemCount; ++row) {
				if(listViewText(listView, row, 4) == L"$MyPass") {
					passwordRow = row;
					break;
				}
			}
			expect(passwordRow >= 0, "NMDC commands populate the decoded Command column");
			if(passwordRow >= 0) {
				const auto renderedRaw = listViewText(listView, passwordRow, 10);
				expect(renderedRaw.find(L"<redacted>") != std::wstring::npos &&
					renderedRaw.find(L"SMOKE_PASSWORD") == std::wstring::npos,
					"credential material is redacted in the raw-message column");

				ListView_SetItemState(listView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
				ListView_SetItemState(listView, passwordRow,
					LVIS_SELECTED | LVIS_FOCUSED, LVIS_SELECTED | LVIS_FOCUSED);
				pumpMessages(std::chrono::milliseconds(20));
				const auto inspected = windowText(inspector);
				expect(inspected.find(L"SMOKE_PASSWORD") == std::wstring::npos,
					"decoded inspector does not expose credential material");
				const auto firstColon = inspected.find(L':');
				if(firstColon != std::wstring::npos && firstColon + 2 < inspected.size()) {
					const auto labelColor = characterColor(inspector, 0);
					const auto valueColor = characterColor(
						inspector, static_cast<LONG>(firstColon + 2));
					expect(labelColor != CLR_INVALID && valueColor != CLR_INVALID &&
						labelColor != valueColor,
						"decoded inspector applies distinct syntax-highlight colors");
				}
			}

			{
				std::lock_guard<std::mutex> lock(stateMutex);
				boolConfig[configKey(metadata.guid, "DisableRedaction")] = True;
			}
			const auto diagnosticCommandText =
				string("$MyPass ") + diagnosticPasswordSecret + "|";
			std::vector<char> diagnosticCommand(
				diagnosticCommandText.begin(), diagnosticCommandText.end());
			diagnosticCommand.push_back('\0');
			fireHook(HOOK_NETWORK_HUB_IN, &nmdcHub, diagnosticCommand.data());
			pumpMessages(std::chrono::milliseconds(400));
			int diagnosticPasswordRow = -1;
			const auto diagnosticItemCount = static_cast<int>(
				::SendMessageW(listView, LVM_GETITEMCOUNT, 0, 0));
			for(int row = 0; row < diagnosticItemCount; ++row) {
				if(listViewText(listView, row, 10).find(
						L"SMOKE_PASSWORD_VISIBLE_FOR_DEBUG") != std::wstring::npos)
				{
					diagnosticPasswordRow = row;
					break;
				}
			}
			expect(diagnosticPasswordRow >= 0,
				"disable-redaction setting exposes sensitive values in new table rows");
			if(diagnosticPasswordRow >= 0) {
				ListView_SetItemState(
					listView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
				ListView_SetItemState(listView, diagnosticPasswordRow,
					LVIS_SELECTED | LVIS_FOCUSED,
					LVIS_SELECTED | LVIS_FOCUSED);
				pumpMessages(std::chrono::milliseconds(20));
				expect(windowText(inspector).find(
						L"SMOKE_PASSWORD_VISIBLE_FOR_DEBUG") != std::wstring::npos,
					"disable-redaction setting exposes sensitive values in the inspector");
			}
			{
				std::lock_guard<std::mutex> lock(stateMutex);
				boolConfig[configKey(metadata.guid, "DisableRedaction")] = False;
			}

			int richEditLiteralRow = -1;
			int bloomRow = -1;
			int smallBloomRow = -1;
			int afterBloomRow = -1;
			int zeroBloomFollowupRow = -1;
			int uncorrelatedBloomFollowupRow = -1;
			int virtualHubIsolationRow = -1;
			for(int row = 0; row < initialItemCount; ++row) {
				if(listViewText(listView, row, 10).find(L"NIbrace{value}") !=
					std::wstring::npos)
				{
					richEditLiteralRow = row;
				}
				if(listViewText(listView, row, 4) == L"BLOM-DATA") {
					const auto raw = listViewText(listView, row, 10);
					if(raw.find(L"92408") != std::wstring::npos) {
						bloomRow = row;
					} else if(raw.find(L"16") != std::wstring::npos) {
						smallBloomRow = row;
					}
				}
				const auto raw = listViewText(listView, row, 10);
				if(raw.find(L"NIAfterBinaryBloom") != std::wstring::npos) {
					afterBloomRow = row;
				}
				if(raw.find(L"NIZeroByteBloomFollowup") != std::wstring::npos) {
					zeroBloomFollowupRow = row;
				}
				if(raw.find(L"NIUncorrelatedBloomFollowup") !=
					std::wstring::npos)
				{
					uncorrelatedBloomFollowupRow = row;
				}
				if(raw.find(L"NIVirtualHubIsolation") != std::wstring::npos) {
					virtualHubIsolationRow = row;
				}
			}
			expect(richEditLiteralRow >= 0,
				"captured RichEdit metacharacters remain visible in the table");
			if(richEditLiteralRow >= 0) {
				ListView_SetItemState(
					listView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
				ListView_SetItemState(listView, richEditLiteralRow,
					LVIS_SELECTED | LVIS_FOCUSED,
					LVIS_SELECTED | LVIS_FOCUSED);
				pumpMessages(std::chrono::milliseconds(20));
				const auto inspected = windowText(inspector);
				expect(inspected.find(L"NIbrace{value}") != std::wstring::npos &&
					inspected.find(L"DEpath\\\\folder") != std::wstring::npos,
					"decoded RichEdit treats braces and backslashes as plain text");
			}

			expect(bloomRow >= 0,
				"correlated IGET/HSND blom captures the following binary write");
			if(bloomRow >= 0) {
				const auto renderedRaw = listViewText(listView, bloomRow, 10);
				expect(renderedRaw.find(L"BLOM payload omitted") !=
						std::wstring::npos &&
					renderedRaw.find(L"BLOOM_BODY") == std::wstring::npos,
					"BLOM bytes are replaced before table rendering");

				ListView_SetItemState(
					listView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
				ListView_SetItemState(listView, bloomRow,
					LVIS_SELECTED | LVIS_FOCUSED,
					LVIS_SELECTED | LVIS_FOCUSED);
				pumpMessages(std::chrono::milliseconds(20));
				const auto inspected = windowText(inspector);
				expect(inspected.find(L"Expected byte count: 92408") !=
						std::wstring::npos &&
					inspected.find(
						L"Observed byte count: Unavailable from host hook") !=
						std::wstring::npos &&
					inspected.find(L"IGET correlation: Matched") !=
						std::wstring::npos &&
					inspected.find(L"BLOOM_BODY") == std::wstring::npos,
					"RichEdit receives only bounded BLOM metadata");
			}

			expect(smallBloomRow >= 0 &&
				listViewText(listView, smallBloomRow, 10).find(
					L"BLOOM_BODY") == std::wstring::npos &&
				listViewText(listView, smallBloomRow, 10).find(
					static_cast<wchar_t>(0x01)) == std::wstring::npos,
				"binary controls and invalid UTF-8 never reach the table");
			if(smallBloomRow >= 0) {
				ListView_SetItemState(
					listView, -1, 0, LVIS_SELECTED | LVIS_FOCUSED);
				ListView_SetItemState(listView, smallBloomRow,
					LVIS_SELECTED | LVIS_FOCUSED,
					LVIS_SELECTED | LVIS_FOCUSED);
				pumpMessages(std::chrono::milliseconds(20));
				const auto inspected = windowText(inspector);
				expect(inspected.find(L"BLOOM_BODY") == std::wstring::npos &&
					inspected.find(static_cast<wchar_t>(0x01)) ==
						std::wstring::npos &&
					inspected.find(L"Expected byte count: 16") !=
						std::wstring::npos,
					"binary controls and invalid UTF-8 never reach RichEdit");
			}
			expect(afterBloomRow >= 0 &&
				listViewText(listView, afterBloomRow, 4) == L"HINF",
				"ordinary traffic after a one-shot BLOM body still renders");
			expect(zeroBloomFollowupRow >= 0 &&
				listViewText(listView, zeroBloomFollowupRow, 4) == L"HINF",
				"zero-byte BLOM response does not consume the next ADC command");
			expect(uncorrelatedBloomFollowupRow >= 0 &&
				listViewText(listView, uncorrelatedBloomFollowupRow, 4) ==
					L"HINF",
				"uncorrelated HSND does not arm a false payload");
			expect(virtualHubIsolationRow >= 0 &&
				listViewText(listView, virtualHubIsolationRow, 4) == L"HINF",
				"BLOM correlation does not cross virtual hub identities");
		}

		if(!protocolLogPath.empty()) {
			std::ifstream logged(protocolLogPath, std::ios::binary);
			const string contents(
				(std::istreambuf_iterator<char>(logged)),
				std::istreambuf_iterator<char>());
			expect(contents.find(passwordSecret) == string::npos &&
				contents.find("<redacted>") != string::npos,
				"persistent protocol logging redacts credential material");
			expect(contents.find(diagnosticPasswordSecret) != string::npos,
				"disable-redaction setting exposes sensitive values in protocol logs");
			expect(contents.find(bloomSecret) == string::npos &&
				contents.find(string("\x01\xfe", 2)) == string::npos &&
				contents.find("BLOM payload omitted") != string::npos,
				"persistent logging records BLOM metadata without binary bytes");
		}

		const auto darkButton = findChildWindow(pluginWindow, L"Button", L"Dark mode");
		expect(darkButton != nullptr, "light theme exposes a dark-mode button");
		if(darkButton) {
			clickButton(darkButton);
			pumpMessages(std::chrono::milliseconds(20));
			expect(findChildWindow(pluginWindow, L"Button", L"Light mode") != nullptr,
				"dark mode updates the theme toggle");
			const auto lightButton =
				findChildWindow(pluginWindow, L"Button", L"Light mode");
			if(lightButton) {
				clickButton(lightButton);
				pumpMessages(std::chrono::milliseconds(20));
			}
		}

		const auto clearButton =
			findChildWindow(pluginWindow, L"Button", L"Clear history");
		expect(clearButton != nullptr, "clear-history control is present");
		if(clearButton && listView) {
			clickButton(clearButton);
			pumpMessages(std::chrono::milliseconds(20));
			expect(::SendMessageW(listView, LVM_GETITEMCOUNT, 0, 0) == 0,
				"clear removes visible and queued rows");

			char afterClear[] = "BINF IDAFTERCLEAR";
			fireHook(HOOK_NETWORK_HUB_IN, &hub, afterClear);
			pumpMessages(std::chrono::milliseconds(400));
			expect(::SendMessageW(listView, LVM_GETITEMCOUNT, 0, 0) == 1,
				"the first message after clear is drawn");
		}

		const auto captionClose =
			findTopmostChildWindow(pluginWindow, L"Button", L"Close");
		expect(captionClose != nullptr,
			"client-drawn caption exposes a Close button");
		if(captionClose) {
			clickButton(captionClose);
			pumpMessages(std::chrono::milliseconds(20));
			expect(pluginWindow && ::IsWindow(pluginWindow) &&
				!::IsWindowVisible(pluginWindow),
				"caption close hides the existing monitor window");

			expect(invokeUiCommand("Show the dialog"),
				"mock host can invoke Show after caption close");
			pumpMessages(std::chrono::milliseconds(20));
			expect(pluginWindow && ::IsWindow(pluginWindow) &&
				::IsWindowVisible(pluginWindow) &&
				findTopLevelWindow(L"Protocol Analyzer") == pluginWindow,
				"Show reopens the same caption-closed monitor HWND");
		}

		::SendMessageW(pluginWindow, WM_CLOSE, 0, 0);
		pumpMessages(std::chrono::milliseconds(20));
		expect(pluginWindow && ::IsWindow(pluginWindow) &&
			!::IsWindowVisible(pluginWindow),
			"system close hides without destroying the monitor window");
		expect(invokeUiCommand("Show the dialog"),
			"mock host can invoke Show after system close");
		pumpMessages(std::chrono::milliseconds(20));
		expect(pluginWindow && ::IsWindow(pluginWindow) &&
			::IsWindowVisible(pluginWindow) &&
			findTopLevelWindow(L"Protocol Analyzer") == pluginWindow,
			"Show reopens the same system-closed monitor HWND");

		expect(invokeUiCommand("Hide the dialog"),
			"mock host can invoke Hide with its retained command-name pointer");
		pumpMessages(std::chrono::milliseconds(20));
		expect(!pluginWindow || !::IsWindowVisible(pluginWindow),
			"Hide command hides the existing monitor window");
		expect(invokeUiCommand("Show the dialog"),
			"mock host can invoke Show after Hide");
		pumpMessages(std::chrono::milliseconds(20));
		expect(pluginWindow && ::IsWindowVisible(pluginWindow),
			"Show command restores the existing monitor window");

		if(pluginWindow) {
			::ShowWindow(pluginWindow, SW_MINIMIZE);
			pumpMessages(std::chrono::milliseconds(20));
			expect(::IsIconic(pluginWindow),
				"protocol-monitor window can enter the minimized state");
			expect(invokeUiCommand("Hide the dialog"),
				"mock host can invoke Hide for a minimized window");
			pumpMessages(std::chrono::milliseconds(20));
			expect(invokeUiCommand("Show the dialog"),
				"mock host can invoke Show for a hidden minimized window");
			pumpMessages(std::chrono::milliseconds(20));
			expect(::IsWindowVisible(pluginWindow) && !::IsIconic(pluginWindow),
				"Show command restores a hidden minimized monitor window");
		}
	}

	std::atomic<bool> runCallbacks { true };
	std::vector<std::thread> callbackThreads;
	if(hook.callback) {
		for(unsigned i = 0; i < 4; ++i) {
			callbackThreads.emplace_back([&] {
				while(runCallbacks.load(std::memory_order_acquire)) {
					Bool shouldBreak = False;
					hook.callback(&hub, hubMessage, hook.common, &shouldBreak);
					std::this_thread::yield();
				}
			});
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(20));
	}
	runCallbacks.store(false, std::memory_order_release);
	expect(pluginMain(ON_UNLOAD, &coreInterface, nullptr) == True,
		"unload succeeds while callbacks drain");
	for(auto& thread : callbackThreads) {
		thread.join();
	}
	expect(activeHookCount() == 0, "unload releases every hook");
	expect(uiCommandCount() == 0, "unload removes every UI command");
	if(commandCallback) {
		commandCallback("Show the dialog");
	}

	failedInterface = DCINTF_DCPP_DATAACCESSOR;
	expect(pluginMain(ON_LOAD_RUNTIME, &coreInterface, nullptr) == False,
		"missing required interface fails load");
	expect(activeHookCount() == 0, "failed load rolls back hooks");
	expect(uiCommandCount() == 0, "failed load rolls back UI commands");
	failedInterface.clear();

	const auto utf8ToWideCallback = utilInterface.utf8_to_wcs;
	utilInterface.utf8_to_wcs = nullptr;
	expect(pluginMain(ON_LOAD_RUNTIME, &coreInterface, nullptr) == False,
		"an incomplete required interface fails load");
	expect(activeHookCount() == 0 && uiCommandCount() == 0,
		"incomplete-interface failure rolls back registrations");
	utilInterface.utf8_to_wcs = utf8ToWideCallback;

	expect(pluginMain(ON_LOAD_RUNTIME, &coreInterface, nullptr) == True,
		"plugin reloads after a failed initialization");
	pumpMessages(std::chrono::milliseconds(50));
	const auto reloadedWindow = findTopLevelWindow(L"Protocol Analyzer");
	expect(reloadedWindow != nullptr && ::IsWindowVisible(reloadedWindow),
		"runtime activation restores the protocol-monitor window");
	expect(pluginMain(ON_UNLOAD, &coreInterface, nullptr) == True,
		"final unload succeeds");
	expect(activeHookCount() == 0, "final unload leaves no hooks");
	expect(uiCommandCount() == 0, "final unload leaves no commands");
	expect(releasedInterfaces > 0, "queried interfaces are released");

	::FreeLibrary(module);
	if(!protocolLogPath.empty()) {
		::DeleteFileA(protocolLogPath.c_str());
	}
	if(failures) {
		std::cerr << failures << " smoke-test assertion(s) failed\n";
		return 1;
	}
	std::cout << "All ABI smoke checks passed\n";
	return 0;
}
