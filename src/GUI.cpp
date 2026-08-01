/*
 * Copyright (C) 2012-2026 Jacek Sieka, arnetheduck on gmail point com
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
#include "CustomTitleBar.h"
#include "GUI.h"
#include "ProtocolAnalyzer.h"
#include "SettingsDlg.h"
#include "TableColors.h"
#include "UIStyles.h"

#include <pluginsdk/Config.h>
#include <pluginsdk/Core.h>
#include <pluginsdk/Logger.h>
#include <pluginsdk/Util.h>

#include <dwt/Clipboard.h>
#include <dwt/DWTException.h>
#include <dwt/Events.h>
#include <dwt/WidgetCreator.h>
#include <dwt/util/HoldRedraw.h>
#include <dwt/widgets/Button.h>
#include <dwt/widgets/CheckBox.h>
#include <dwt/widgets/ComboBox.h>
#include <dwt/widgets/Grid.h>
#include <dwt/widgets/GroupBox.h>
#include <dwt/widgets/Header.h>
#include <dwt/widgets/Label.h>
#include <dwt/widgets/Menu.h>
#include <dwt/widgets/MessageBox.h>
#include <dwt/widgets/RichTextBox.h>
#include <dwt/widgets/SaveDialog.h>
#include <dwt/widgets/Table.h>
#include <dwt/widgets/TextBox.h>
#include <dwt/widgets/Window.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <ctime>
#include <limits>
#include <memory>
#include <sstream>
#include <string_view>
#include <unordered_set>

// dwt defines another tstring...
typedef tstring _tstring;
#define tstring _tstring

using dcapi::Config;
using dcapi::Util;

using namespace dwt;

std::atomic_bool GUI::unloading { false };

WindowPtr window;
TablePtr table;
ComboBoxPtr protocolFilterBox;
ComboBoxPtr ipFilterBox;
ComboBoxPtr portFilterBox;
ComboBoxPtr peerFilterBox;
ComboBoxPtr commandFilterBox;
ComboBoxPtr categoryFilterBox;
RichTextBoxPtr inspectorBox;
LabelPtr captureStatusLabel;
LabelPtr filterStatusLabel;
LabelPtr itemCountLabel;
FontPtr uiFont;
FontPtr titleFont;
FontPtr sectionFont;

const TCHAR* FILTER_ALL = _T("\x1f<all>");
const TCHAR* FILTER_ALL_LABEL = _T("All");
const char* DEFAULT_TIMESTAMP_FORMAT = "[%Y-%m-%d %H:%M:%S]";

static const ColumnInfo cols[] = {
	{ "Timestamp", 125, false },
	{ "#", 50, true },
	{ "Direction", 52, false },
	{ "Protocol", 70, false },
	{ "Command", 78, false },
	{ "Category", 86, false },
	{ "Address", 115, false },
	{ "Port", 60, true },
	{ "Peer", 150, false },
	{ "Summary", 240, false },
	{ "Raw (redacted)", 360, false }
};

namespace {
constexpr size_t MAX_TIMESTAMP_FORMAT_CHARS = 64;
constexpr size_t MAX_REGEX_CHARS = 256;
constexpr size_t MAX_REGEX_FIELD_BYTES = 4096;
constexpr size_t MAX_LOG_FILE_BYTES = 10 * 1024 * 1024;
constexpr size_t MAX_LOG_BATCH_BYTES = 8 * 1024 * 1024;
constexpr unsigned LOG_ROTATION_COUNT = 3;
constexpr size_t MAX_PENDING_BLOOM_REQUESTS = 32;
constexpr size_t MAX_PENDING_BLOOM_PAYLOADS = 32;
// These are deliberately shorter than the Plugin hook guard's lifetimes.
// GUI state must never outlive the guard that prevents a lengthless binary
// pointer from being scanned as a C string.
constexpr auto BLOOM_REQUEST_LIFETIME = std::chrono::seconds(29);
constexpr auto BLOOM_PAYLOAD_LIFETIME = std::chrono::seconds(4);

enum class BloomHeaderKind {
	None,
	Get,
	Send
};

struct BloomHeader {
	BloomHeaderKind kind = BloomHeaderKind::None;
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
	for(const auto ch : value) {
		if(ch < '0' || ch > '9') {
			return false;
		}
		const auto digit = static_cast<uint64_t>(ch - '0');
		if(result > ((std::numeric_limits<uint64_t>::max)() - digit) / 10) {
			return false;
		}
		result = result * 10 + digit;
	}
	parsed = result;
	return true;
}

bool parseBloomHeader(const string& message, BloomHeader& result) noexcept {
	result = BloomHeader {};
	std::string_view header(message);
	if(!header.empty() && header.back() == '\n') {
		header.remove_suffix(1);
		if(!header.empty() && header.back() == '\r') {
			header.remove_suffix(1);
		}
	}
	if(header.size() < 15 || header.find_first_of("\r\n") != std::string_view::npos 
						|| header.front() == ' ' || header.back() == ' ')
	{
		return false;
	}

	for(const auto ch : header) {
		const auto byte = static_cast<unsigned char>(ch);
		if(byte < 0x20 || byte > 0x7e) {
			return false;
		}
	}

	std::array<std::string_view, 16> tokens {};
	size_t tokenCount = 0;
	size_t position = 0;
	while(position < header.size()) {
		const auto end = header.find(' ', position);
		const auto tokenEnd =
			end == std::string_view::npos ? header.size() : end;
		if(tokenEnd == position || tokenCount == tokens.size()) {
			return false;
		}
		tokens[tokenCount++] = header.substr(position, tokenEnd - position);
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

	uint64_t bytes = 0;
	if(!parseUnsigned(tokens[4], bytes) || bytes > (std::numeric_limits<uint64_t>::max)() / 8)
	{
		return false;
	}

	result.kind = tokens[0] == "IGET" ? BloomHeaderKind::Get : BloomHeaderKind::Send;
	result.bytes = bytes;
	for(size_t i = 5; i < tokenCount; ++i) {
		if(tokens[i].size() < 2 ||
			tokens[i][0] < 'A' || tokens[i][0] > 'Z' ||
			!((tokens[i][1] >= 'A' && tokens[i][1] <= 'Z') ||
				(tokens[i][1] >= '0' && tokens[i][1] <= '9')))
		{
			return false;
		}
		uint64_t value = 0;
		if(tokens[i].substr(0, 2) == "BK") {
			if(result.hasK || !parseUnsigned(tokens[i].substr(2), value) ||
				value == 0 || value > 192)
			{
				return false;
			}
			result.k = static_cast<uint32_t>(value);
			result.hasK = true;
		} else if(tokens[i].substr(0, 2) == "BH") {
			if(result.hasH || !parseUnsigned(tokens[i].substr(2), value) ||
				value == 0 || value > 64)
			{
				return false;
			}
			result.h = static_cast<uint32_t>(value);
			result.hasH = true;
		}
	}

	if(result.kind == BloomHeaderKind::Get &&
		(!result.hasK || !result.hasH))
	{
		return false;
	}
	if(result.hasK && result.hasH &&
		static_cast<uint64_t>(result.k) * result.h > 192)
	{
		return false;
	}
	if(bytes % 8 != 0) {
		return false;
	}
	if(result.hasH && result.h < 64 &&
		bytes * 8 >= (uint64_t { 1 } << result.h))
	{
		return false;
	}
	return true;
}

const tstring* getColumnText(const Item& item, int column) noexcept {
	switch(column) {
	case COLUMN_TIMESTAMP: return &item.timestamp;
	case COLUMN_COUNT:     return &item.index;
	case COLUMN_DIRECTION: return &item.dir;
	case COLUMN_PROTOCOL:  return &item.protocol;
	case COLUMN_COMMAND:   return &item.command;
	case COLUMN_CATEGORY:  return &item.category;
	case COLUMN_IP:        return &item.ip;
	case COLUMN_PORT:      return &item.port;
	case COLUMN_PEER:      return &item.peer;
	case COLUMN_SUMMARY:   return &item.summary;
	case COLUMN_MESSAGE:   return &item.safeMessage();
	default:                return nullptr;
	}
}

bool columnTextOverflows(dwt::TablePtr owner, int column, const tstring& text) noexcept
{
	if(!owner || !::IsWindow(owner->handle()) || text.empty() ||
		column < COLUMN_FIRST || column >= COLUMN_LAST)
	{
		return false;
	}

	const auto columnWidth = static_cast<int>(owner->sendMessage(
		LVM_GETCOLUMNWIDTH, static_cast<WPARAM>(column), 0));
	const auto horizontalPadding = owner->scale(12);
	if(columnWidth <= horizontalPadding) {
		return true;
	}

	// Ask the list view to measure with its active font. This avoids creating
	// tooltip-time GDI objects and keeps work proportional to the hovered cell.
	const auto textWidth = static_cast<int>(owner->sendMessage(
		LVM_GETSTRINGWIDTH, 0, reinterpret_cast<LPARAM>(text.c_str())));
	return textWidth >= 0 && textWidth > columnWidth - horizontalPadding;
}

template<typename T>
void saturatingAdd(T& target, T value) {
	const auto maximum = std::numeric_limits<T>::max();
	target = value > maximum - target ? maximum : target + value;
}

void fillRect(dwt::Canvas& canvas, const dwt::Rectangle& rect, COLORREF color) {
	dwt::Brush brush(color);
	canvas.fill(rect, brush);
}

string normalizeTimestampFormat(string format) {
	if(format.empty()) {
		return DEFAULT_TIMESTAMP_FORMAT;
	}
	auto textFormat = Util::toT(format);
	if(textFormat.size() > MAX_TIMESTAMP_FORMAT_CHARS) {
		textFormat.resize(MAX_TIMESTAMP_FORMAT_CHARS);
		format = Util::fromT(textFormat);
	}

	// %D is POSIX shorthand and is not supported consistently by the Windows CRT.
	const string portableDate = "%m/%d/%y";
	for(size_t pos = 0; (pos = format.find("%D", pos)) != string::npos;
		pos += portableDate.size())
	{
		format.replace(pos, 2, portableDate);
	}
	return format;
}

string encodeFilterSetting(const tstring& value) {
	return value.empty() || value == FILTER_ALL ?
		string("all:") : string("value:") + Util::fromT(value);
}

tstring decodeFilterSetting(const char* key) {
	const auto stored = Config::getConfig(key);
	if(stored.empty() || stored == "all:" || _stricmp(stored.c_str(), "All") == 0) {
		return FILTER_ALL;
	}
	static const string prefix = "value:";
	return Util::toT(stored.compare(0, prefix.size(), prefix) == 0 ?
		stored.substr(prefix.size()) : stored);
}

void truncateBytes(string& value, size_t limit) {
	if(value.size() > limit) {
		value.resize(limit);
	}
}

size_t messageStorageBytes(const string& protocol, const string& ip,
	const string& peer, const string& message)
{
	return sizeof(std::chrono::system_clock::time_point) + sizeof(ConnectionData) +
		protocol.size() + ip.size() + peer.size() + message.size() + 64;
}

size_t itemStorageBytes(const Item& item) {
	return sizeof(Item) + sizeof(TCHAR) * (
		item.timestamp.size() + item.index.size() + item.dir.size() +
		item.protocol.size() + item.command.size() + item.category.size() +
		item.ip.size() + item.port.size() + item.peer.size() +
		item.summary.size() + item.message.size() + item.details.size() +
		item.validation.size() + 13);
}

tstring formatTimestamp(const std::chrono::system_clock::time_point& arrival,
	const string& configuredFormat)
{
	const auto time = std::chrono::system_clock::to_time_t(arrival);
	std::tm localTime {};
	std::array<TCHAR, 256> timestamp {};
	const auto format = Util::toT(normalizeTimestampFormat(configuredFormat));
	if(localtime_s(&localTime, &time) == 0) {
		if(_tcsftime(timestamp.data(), timestamp.size(), format.c_str(), &localTime) == 0) {
			const auto fallback = Util::toT(DEFAULT_TIMESTAMP_FORMAT);
			_tcsftime(timestamp.data(), timestamp.size(), fallback.c_str(), &localTime);
		}
	}
	if(timestamp[0] == _T('\0')) {
		_tcscpy_s(timestamp.data(), timestamp.size(), _T("[time unavailable]"));
	}
	return tstring(timestamp.data());
}

bool isSafeRegexPattern(const tstring& pattern) {
	if(pattern.size() > MAX_REGEX_CHARS) {
		return false;
	}

	bool escaped = false;
	bool inClass = false;
	for(size_t i = 0; i < pattern.size(); ++i) {
		const TCHAR ch = pattern[i];
		if(escaped) {
			if(!inClass && ch >= _T('1') && ch <= _T('9')) {
				return false; // back-references can trigger explosive backtracking.
			}
			escaped = false;
			continue;
		}
		if(ch == _T('\\')) {
			escaped = true;
			continue;
		}
		if(ch == _T('[')) {
			inClass = true;
			continue;
		}
		if(ch == _T(']') && inClass) {
			inClass = false;
			continue;
		}
		if(inClass) {
			continue;
		}

		// Keep the supported subset free of repetition, grouping, alternation,
		// look-around, and back-references. The remaining literals, dot,
		// character classes and anchors have bounded, non-explosive matching.
		if(ch == _T('(') || ch == _T(')') || ch == _T('|') ||
			ch == _T('{') || ch == _T('}') || ch == _T('*') ||
			ch == _T('+') || ch == _T('?'))
		{
			return false;
		}
	}
	return !escaped && !inClass;
}

string escapeLogField(const string& value) {
	static const char hex[] = "0123456789ABCDEF";
	string result;
	result.reserve(std::min(value.size() * 2, MAX_LOG_BATCH_BYTES));
	for(unsigned char ch : value) {
		switch(ch) {
			case '\r': result += "\\r"; break;
			case '\n': result += "\\n"; break;
			case '\t': result += "\\t"; break;
			default:
				if(ch < 0x20 || ch == 0x7f) {
					result += "\\x";
					result += hex[ch >> 4];
					result += hex[ch & 0x0f];
				} else {
					result.push_back(static_cast<char>(ch));
				}
				break;
		}
	}
	return result;
}

tstring win32ErrorText(DWORD error) {
	TCHAR* buffer = nullptr;
	const DWORD size = ::FormatMessage(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM |
			FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr, error, 0, reinterpret_cast<TCHAR*>(&buffer), 0, nullptr);
	tstring result = size && buffer ? tstring(buffer, size) : _T("unknown error");
	if(buffer) {
		::LocalFree(buffer);
	}
	while(!result.empty() &&
		(result.back() == _T('\r') || result.back() == _T('\n') ||
			result.back() == _T(' ')))
	{
		result.pop_back();
	}
	return result;
}

bool rotateLogIfNeeded(const tstring& path, size_t incomingBytes, tstring& error) {
	WIN32_FILE_ATTRIBUTE_DATA attributes {};
	uint64_t size = 0;
	if(::GetFileAttributesEx(path.c_str(), GetFileExInfoStandard, &attributes)) {
		size = (static_cast<uint64_t>(attributes.nFileSizeHigh) << 32) |
			attributes.nFileSizeLow;
	} else {
		const auto code = ::GetLastError();
		if(code != ERROR_FILE_NOT_FOUND && code != ERROR_PATH_NOT_FOUND) {
			error = _T("Unable to inspect log file: ") + win32ErrorText(code);
			return false;
		}
	}
	if(incomingBytes <= MAX_LOG_FILE_BYTES &&
		size <= MAX_LOG_FILE_BYTES - incomingBytes)
	{
		return true;
	}

	for(unsigned i = LOG_ROTATION_COUNT; i > 0; --i) {
		const auto destination = path + _T(".") + Util::toT(std::to_string(i));
		const auto source = i == 1 ? path :
			path + _T(".") + Util::toT(std::to_string(i - 1));
		if(!::MoveFileEx(source.c_str(), destination.c_str(),
			MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
		{
			const auto code = ::GetLastError();
			if(code != ERROR_FILE_NOT_FOUND && code != ERROR_PATH_NOT_FOUND) {
				error = _T("Unable to rotate log file: ") + win32ErrorText(code);
				return false;
			}
		}
	}
	return true;
}

bool appendUtf8Log(const string& configuredPath, const string& data, tstring& error) {
	if(configuredPath.empty() || data.empty()) {
		error.clear();
		return true;
	}

	const auto path = Util::toT(configuredPath);
	if(data.size() > (std::numeric_limits<size_t>::max)() - 3) {
		error = _T("Log entry is too large.");
		return false;
	}
	if(!rotateLogIfNeeded(path, data.size() + 3, error)) {
		return false;
	}

	HANDLE file = ::CreateFile(path.c_str(), FILE_APPEND_DATA,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr,
		OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
	if(file == INVALID_HANDLE_VALUE) {
		error = _T("Unable to open log file: ") + win32ErrorText(::GetLastError());
		return false;
	}

	LARGE_INTEGER size {};
	bool ok = ::GetFileSizeEx(file, &size) != FALSE;
	auto writeAll = [file](const void* bytes, size_t count) {
		const auto* cursor = static_cast<const BYTE*>(bytes);
		while(count) {
			const DWORD chunk = static_cast<DWORD>(std::min<size_t>(
				count, std::numeric_limits<DWORD>::max()));
			DWORD written = 0;
			if(!::WriteFile(file, cursor, chunk, &written, nullptr) || written == 0) {
				return false;
			}
			cursor += written;
			count -= written;
		}
		return true;
	};

	static const BYTE utf8Bom[] { 0xef, 0xbb, 0xbf };
	if(ok && size.QuadPart == 0) {
		ok = writeAll(utf8Bom, sizeof(utf8Bom));
	}
	if(ok) {
		ok = writeAll(data.data(), data.size());
	}
	const DWORD failure = ok ? ERROR_SUCCESS : ::GetLastError();
	::CloseHandle(file);
	if(!ok) {
		error = _T("Unable to write log file: ") + win32ErrorText(failure);
		return false;
	}
	error.clear();
	return true;
}

LRESULT drawTableHeader(NMCUSTOMDRAW& data) {
	const auto& colors = ui::palette();
	const auto headerBackground = table_colors::get(table_colors::Role::HeaderBackground);
	const auto headerText = table_colors::get(table_colors::Role::HeaderText);

	if(data.dwDrawStage == CDDS_PREPAINT) {
		return CDRF_NOTIFYITEMDRAW | CDRF_NOTIFYPOSTPAINT;
	}

	if(data.dwDrawStage == CDDS_POSTPAINT) {
		auto header = dwt::hwnd_cast<Header*>(data.hdr.hwndFrom);
		if(!header) {
			return CDRF_DODEFAULT;
		}
		dwt::Rectangle client(header->getClientSize());
		const int count = Header_GetItemCount(data.hdr.hwndFrom);
		long paintedRight = client.left();
		for(int index = 0; index < count; ++index) {
			RECT nativeItem {};
			if(Header_GetItemRect(data.hdr.hwndFrom, index, &nativeItem)) {
				paintedRight = std::max(paintedRight,
					dwt::Rectangle(nativeItem).right());
			}
		}
		const auto right = client.right();
		client.pos.x = std::min(paintedRight, right);
		client.size.x = std::max(0L, right - client.pos.x);
		if(client.width() > 0) {
			dwt::FreeCanvas canvas(data.hdc);
			fillRect(canvas, client, headerBackground);
		}
		return CDRF_DODEFAULT;
	}

	if(data.dwDrawStage != CDDS_ITEMPREPAINT) {
		return CDRF_DODEFAULT;
	}

	auto background = headerBackground;
	if((data.uItemState & CDIS_SELECTED) != 0) {
		background = ui::blend(headerBackground, colors.accent, 45);
	} else if((data.uItemState & CDIS_HOT) != 0) {
		background = ui::blend(headerBackground, colors.accent, 22);
	}
	dwt::FreeCanvas canvas(data.hdc);
	dwt::Rectangle bounds(data.rc);
	fillRect(canvas, bounds, background);
	{
		dwt::Pen border(colors.border, dwt::Pen::Solid, 1);
		auto penSelection = canvas.select(border);
		canvas.line(
			dwt::Point(bounds.right() - 1, bounds.top()),
			dwt::Point(bounds.right() - 1, bounds.bottom()));
		canvas.line(
			dwt::Point(bounds.left(), bounds.bottom() - 1),
			dwt::Point(bounds.right(), bounds.bottom() - 1));
	}

	TCHAR text[256] {};
	HDITEM item {};
	item.mask = HDI_TEXT | HDI_FORMAT;
	item.pszText = text;
	item.cchTextMax = 255;
	Header_GetItem(data.hdr.hwndFrom, static_cast<int>(data.dwItemSpec), &item);

	dwt::Rectangle textRect(data.rc);
	auto itemHeader = dwt::hwnd_cast<Header*>(data.hdr.hwndFrom);
	const auto textPadding = itemHeader ? itemHeader->scale(10) : 10;
	textRect.pos.x += textPadding;
	textRect.size.x = std::max(0L, textRect.size.x - textPadding * 2);
	UINT format = DT_LEFT;
	if((item.fmt & HDF_CENTER) == HDF_CENTER) {
		format = DT_CENTER;
	} else if((item.fmt & HDF_RIGHT) == HDF_RIGHT) {
		format = DT_RIGHT;
	}
	auto backgroundMode = canvas.setBkMode(true);
	canvas.setTextColor(headerText);
	canvas.drawText(tstring(text), textRect,
		format | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS | DT_NOPREFIX);
	return CDRF_SKIPDEFAULT;
}

HeaderPtr getTableHeader(TablePtr owner) {
	if(!owner) {
		return nullptr;
	}
	HWND handle = ListView_GetHeader(owner->handle());
	if(!handle || !::IsWindow(handle)) {
		return nullptr;
	}
	if(auto existing = dwt::hwnd_cast<Header*>(handle)) {
		return existing;
	}
	return WidgetCreator<Header>::attach(owner, handle);
}

void styleLabel(LabelPtr label, COLORREF text, COLORREF background, FontPtr font) {
	if(!label) {
		return;
	}
	label->setColor(text, background);
	label->setFont(font);
}

void setControlTreeFont(Composite* parent, const FontPtr& font) {
	if(!parent) {
		return;
	}
	auto children = parent->getChildren<Control>();
	for(auto i = children.first; i != children.second; ++i) {
		auto child = *i;
		child->setFont(font);
		if(auto composite = dynamic_cast<Composite*>(child)) {
			setControlTreeFont(composite, font);
		}
	}
}

void makeColumns(dwt::TablePtr table_, const ColumnInfo* columnInfo, size_t columnCount) {
	std::vector<dwt::Column> n(columnCount);
	
	for(size_t i = 0; i < columnCount; ++i) {
		n[i].header = Util::toT(columnInfo[i].name);
		n[i].width = table_->scale(columnInfo[i].size);
		n[i].alignment = columnInfo[i].numerical ? dwt::Column::RIGHT : dwt::Column::LEFT;
	}

	table_->setColumns(n);
}

bool containsCaseInsensitive(const tstring& haystack, const tstring& needle) {
	if(needle.empty()) {
		return true;
	}
	return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end(),
		[](TCHAR a, TCHAR b) { return _totlower(a) == _totlower(b); }) != haystack.end();
}

void refreshFilterCombo(ComboBoxPtr box, const std::vector<tstring>& values,
	const tstring& selectedValue, bool preserveMissing)
{
	if(!box) {
		return;
	}

	dwt::util::HoldRedraw hold(box);
	box->clear();
	box->addValue(FILTER_ALL_LABEL);
	for(const auto& value : values) {
		box->addValue(value);
	}
	int selectedIndex = 0;
	if(!selectedValue.empty() && selectedValue != FILTER_ALL) {
		for(size_t i = 0; i < values.size(); ++i) {
			if(_tcsicmp(values[i].c_str(), selectedValue.c_str()) == 0) {
				selectedIndex = static_cast<int>(i + 1);
				break;
			}
		}
		// Preserve a restored/current filter even while it has no matches.
		if(selectedIndex == 0 && preserveMissing) {
			box->addValue(selectedValue);
			selectedIndex = static_cast<int>(box->size()) - 1;
		}
	}
	box->setSelected(selectedIndex);
	box->redraw();
}

int inspectorOffset(const tstring& text, size_t offset) {
	offset = std::min(offset, text.size());
	return static_cast<int>(offset -
		static_cast<size_t>(std::count(text.begin(), text.begin() + offset, _T('\r'))));
}

void formatInspectorRange(const tstring& text, size_t begin, size_t end,
	table_colors::Role role, bool bold = false)
{
	if(!inspectorBox || begin >= end || begin >= text.size()) {
		return;
	}
	end = std::min(end, text.size());
	inspectorBox->setSelection(
		inspectorOffset(text, begin), inspectorOffset(text, end));

	CHARFORMAT2 format {};
	format.cbSize = sizeof(format);
	format.dwMask = CFM_COLOR | CFM_BOLD;
	format.dwEffects = bold ? CFE_BOLD : 0;
	format.crTextColor = table_colors::get(role);
	inspectorBox->sendMessage(
		EM_SETCHARFORMAT, SCF_SELECTION, reinterpret_cast<LPARAM>(&format));
}

table_colors::Role inspectorValidationRole(const tstring& value) {
	if(value == _T("Valid")) {
		return table_colors::Role::InspectorValid;
	}
	if(value == _T("Invalid")) {
		return table_colors::Role::InspectorError;
	}
	return table_colors::Role::InspectorWarning;
}

table_colors::Role inspectorProtocolRole(const tstring& value) {
	if(value == _T("ADC")) {
		return table_colors::Role::Adc;
	}
	if(value == _T("NMDC")) {
		return table_colors::Role::Nmdc;
	}
	if(value == _T("UDP")) {
		return table_colors::Role::Udp;
	}
	if(value == _T("DHT")) {
		return table_colors::Role::Dht;
	}
	return table_colors::Role::InspectorValue;
}

void forceInspectorRedraw() {
	if(!inspectorBox) {
		return;
	}
	::RedrawWindow(inspectorBox->handle(), nullptr, nullptr,
		RDW_INVALIDATE | RDW_UPDATENOW | RDW_ERASE);
	::UpdateWindow(inspectorBox->handle());
}

void setInspectorPlainText(const tstring& text) {
	if(!inspectorBox) {
		return;
	}
	SETTEXTEX setText { ST_DEFAULT, 1200 };
	inspectorBox->sendMessage(EM_SETTEXTEX,
		reinterpret_cast<WPARAM>(&setText),
		reinterpret_cast<LPARAM>(text.c_str()));
}

void renderInspectorText(const tstring& text) {
	if(!inspectorBox) {
		return;
	}

	{
		dwt::util::HoldRedraw hold(inspectorBox);
		setInspectorPlainText(text);
		formatInspectorRange(text, 0, text.size(),
			table_colors::Role::InspectorText);

		enum class Section {
			Metadata,
			Fields,
			Warnings,
			Raw
		};
		Section section = Section::Metadata;
		size_t lineBegin = 0;
		while(lineBegin < text.size()) {
			auto lineEnd = text.find_first_of(_T("\r\n"), lineBegin);
			if(lineEnd == tstring::npos) {
				lineEnd = text.size();
			}
			const auto line = text.substr(lineBegin, lineEnd - lineBegin);

			if(line == _T("Fields:")) {
				formatInspectorRange(text, lineBegin, lineEnd,
					table_colors::Role::InspectorHeading, true);
				section = Section::Fields;
			} else if(line == _T("Warnings:")) {
				formatInspectorRange(text, lineBegin, lineEnd,
					table_colors::Role::InspectorWarning, true);
				section = Section::Warnings;
			} else if(line == _T("Raw (sensitive values redacted):")) {
				formatInspectorRange(text, lineBegin, lineEnd,
					table_colors::Role::InspectorHeading, true);
				section = Section::Raw;
			} else if(!line.empty() && section == Section::Raw) {
				formatInspectorRange(text, lineBegin, lineEnd,
					table_colors::Role::InspectorRaw);
			} else if(!line.empty() && section == Section::Warnings) {
				formatInspectorRange(text, lineBegin, lineEnd,
					table_colors::Role::InspectorWarning);
			} else if(!line.empty() && section == Section::Fields) {
				const size_t contentBegin = line.find_first_not_of(_T(" \t"));
				const size_t fieldBegin = contentBegin == tstring::npos ?
					0 : contentBegin;
				const auto separator = line.find(_T(" — "), fieldBegin);
				const size_t nameBegin = separator == tstring::npos ?
					fieldBegin : separator + 3;
				if(separator != tstring::npos) {
					formatInspectorRange(text, lineBegin + fieldBegin,
						lineBegin + separator,
						table_colors::Role::InspectorFieldCode, true);
				}
				const auto colon = line.find(_T(':'), nameBegin);
				if(colon != tstring::npos) {
					formatInspectorRange(text, lineBegin + nameBegin,
						lineBegin + colon + 1,
						table_colors::Role::InspectorLabel, true);
					const auto valueBegin = std::min(colon + 2, line.size());
					formatInspectorRange(text, lineBegin + valueBegin, lineEnd,
						table_colors::Role::InspectorValue);
				}
			} else if(!line.empty()) {
				const auto colon = line.find(_T(':'));
				if(colon != tstring::npos) {
					formatInspectorRange(text, lineBegin, lineBegin + colon + 1,
						table_colors::Role::InspectorLabel, true);
					const auto valueBegin = std::min(colon + 2, line.size());
					auto valueRole = table_colors::Role::InspectorValue;
					if(line.compare(0, colon, _T("Validation")) == 0) {
						valueRole = inspectorValidationRole(line.substr(valueBegin));
					} else if(line.compare(0, colon, _T("Protocol")) == 0) {
						valueRole = inspectorProtocolRole(line.substr(valueBegin));
					}
					formatInspectorRange(text, lineBegin + valueBegin, lineEnd,
						valueRole, valueRole != table_colors::Role::InspectorValue);
				}
			}

			if(lineEnd == text.size()) {
				break;
			}
			lineBegin = lineEnd + 1;
			if(lineBegin < text.size() && text[lineEnd] == _T('\r') &&
				text[lineBegin] == _T('\n'))
			{
				++lineBegin;
			}
		}

		inspectorBox->setSelection(0, 0);
		inspectorBox->sendMessage(WM_VSCROLL, MAKEWPARAM(SB_TOP, 0), 0);
	}
	forceInspectorRedraw();
}

void refreshInspectorPalette() {
	if(!inspectorBox) {
		return;
	}
	const auto text = inspectorBox->getText();
	{
		dwt::util::HoldRedraw hold(inspectorBox);
		// RichTextBox::setColor preserves per-character formatting with one
		// message per character. Clear first because the renderer immediately
		// reapplies every syntax span using the selected palette.
		setInspectorPlainText(tstring());
		inspectorBox->setColor(
			table_colors::get(table_colors::Role::InspectorText),
			table_colors::get(table_colors::Role::InspectorBackground));
	}
	renderInspectorText(text);
}

} //unnamed namespace

GUI::GUI() :
	messageQueueCapacity(DEFAULT_CAPTURE_QUEUE_CAPACITY),
	messagesBytes(0),
	captureGeneration(0),
	pendingDroppedMessages(0),
	pendingDroppedBytes(0),
	historyBytes(0),
	filterChoicesDirty(false),
	counter(0),
	droppedMessages(0),
	droppedBytes(0),
	evictedMessages(0),
	scroll(true),
	shuttingDown(false),
	justCleared(false),
	findText(),
	pendingFindText(),
	searchPending(false),
	searchDue(),
	selectedProtocol(FILTER_ALL),
	selectedIp(FILTER_ALL),
	selectedPort(FILTER_ALL),
	selectedPeer(FILTER_ALL),
	selectedCommand(FILTER_ALL),
	selectedCategory(FILTER_ALL),
	regexText(),
	regexValid(true),
	searchRegex(),
	keepOnTop(false),
	logError(),
	themeButton(nullptr),
	customTitleBar(nullptr),
	rootGrid(nullptr),
	actionsGrid(nullptr),
	themeUpdates(),
	settingsState(std::make_shared<SettingsState>()),
	lifetime(std::make_shared<std::atomic_bool>(true))
{
}

size_t GUI::normalizeCaptureQueueCapacity(int64_t capacity) noexcept {
	if(capacity == 0) {
		return DEFAULT_CAPTURE_QUEUE_CAPACITY;
	}
	if(capacity < static_cast<int64_t>(MIN_CAPTURE_QUEUE_CAPACITY)) {
		return MIN_CAPTURE_QUEUE_CAPACITY;
	}
	if(capacity > static_cast<int64_t>(MAX_CAPTURE_QUEUE_CAPACITY)) {
		return MAX_CAPTURE_QUEUE_CAPACITY;
	}
	return static_cast<size_t>(capacity);
}

void GUI::loadCaptureQueueCapacity() {
	setCaptureQueueCapacity(normalizeCaptureQueueCapacity(
		Config::getIntConfig("CaptureQueueCapacity")));
}

void GUI::setCaptureQueueCapacity(size_t capacity) {
	capacity = std::max(MIN_CAPTURE_QUEUE_CAPACITY,
		std::min(capacity, MAX_CAPTURE_QUEUE_CAPACITY));
	Config::setConfig("CaptureQueueCapacity",
		static_cast<int32_t>(capacity));

	std::vector<std::unique_ptr<Message>> discarded;
	{
		std::lock_guard<std::mutex> lock(messagesMutex);
		messageQueueCapacity = capacity;
		if(messages.size() > messageQueueCapacity) {
			discarded.reserve(messages.size() - messageQueueCapacity);
		}
		while(messages.size() > messageQueueCapacity) {
			auto message = std::move(messages.back());
			messages.pop_back();
			const auto bytes = message ? message->storageBytes : size_t { 0 };
			messagesBytes = bytes <= messagesBytes ? messagesBytes - bytes : 0;
			saturatingAdd(pendingDroppedMessages, uint64_t { 1 });
			saturatingAdd(pendingDroppedBytes, static_cast<uint64_t>(bytes));
			discarded.emplace_back(std::move(message));
		}
	}
	// Release discarded strings after the callback-facing queue lock is free.
}

GUI::~GUI() {
	shuttingDown = true;
	lifetime->store(false);
	std::shared_ptr<SettingsDlg> dialog;
	{
		std::lock_guard<std::mutex> lock(settingsState->mutex);
		settingsState->alive = false;
		dialog = std::move(settingsState->active);
	}
	if(dialog) {
		dialog->endDialog(IDCANCEL);
	}
	if(window) {
		auto hWnd = window->handle();
		if(::IsWindow(hWnd)) {
			::DestroyWindow(hWnd);
		}
	}
	customTitleBar.reset();
}

void GUI::create() {
	if(window) {
		const bool needsRestore =
			!window->getVisible() || ::IsIconic(window->handle());
		if(needsRestore) {
			if(showWindow()) {
				Config::setConfig("Dialog", true);
				dcapi::Logger::log("[Protocol Analyzer]: window shown");
			}
		}
		window->setFocus();
		return;
	}

	shuttingDown = false;

	initSettings(); // load our state from settings
	ui::setDarkMode(Config::getBoolConfig("DarkMode"));
	themeUpdates.clear();

	Application::init();

	{
		Window::Seed seed(tstring(_T(PLUGIN_NAME)) + _T(" ") + Util::toT(PLUGIN_VERSION_STR) + _T(" \u00b7 Protocol Analyzer"));
		seed.location.size.x = 1280;
		seed.location.size.y = 840;

		window = new Window();
		window->create(seed);
		window->addRemoveStyle(WS_CLIPCHILDREN, true);
		auto initialBounds = window->getWindowRect();
		initialBounds.size = window->scale(Point(1280, 840));
		window->resize(initialBounds);

		const auto dpi = window->getDpi();
		uiFont = ui::makeFont(dpi, 9);
		titleFont = ui::makeFont(dpi, 20, FW_SEMIBOLD);
		sectionFont = ui::makeFont(dpi, 9, FW_SEMIBOLD);
		window->setFont(uiFont);
		addThemeUpdate([] { ui::styleSurface(window); });

		auto iconPath = Util::toT(Config::getInstallPath() + "ProtocolAnalyzer.ico");
		try {
			window->setSmallIcon(new dwt::Icon(iconPath, dwt::Point(16, 16)));
			window->setLargeIcon(new dwt::Icon(iconPath, dwt::Point(32, 32)));
		} catch(const dwt::DWTException&) { }

		customTitleBar.reset(new ui::CustomTitleBar(window, uiFont, [this] { close(); }));

		window->onClosing([this]() -> bool {
			saveState();
			if(!unloading.load()) {
				Config::setConfig("Dialog", false);
				if(window) {
					window->setVisible(false);
					dcapi::Logger::log("[Protocol Analyzer]: window hidden, messages are still being processed in the background");
				}
				return false;
			}
			shuttingDown = true;
			return true;
		});
		window->onDestroy([this] {
			shuttingDown = true;
			tableItems.clear();
			visibleItems.clear();
			ipChoices.clear();
			portChoices.clear();
			peerChoices.clear();
			commandChoices.clear();
			categoryChoices.clear();
			historyBytes = 0;
			counter = 0;
			table = nullptr;
			protocolFilterBox = nullptr;
			ipFilterBox = nullptr;
			portFilterBox = nullptr;
			peerFilterBox = nullptr;
			commandFilterBox = nullptr;
			categoryFilterBox = nullptr;
			inspectorBox = nullptr;
			captureStatusLabel = nullptr;
			filterStatusLabel = nullptr;
			itemCountLabel = nullptr;
			themeButton = nullptr;
			rootGrid = nullptr;
			actionsGrid = nullptr;
			themeUpdates.clear();
			window = nullptr;
			Application::uninit();
		});
	}

	auto grid = window->addChild(Grid::Seed(5, 1));
	rootGrid = grid;
	grid->column(0).mode = GridInfo::FILL;
	grid->row(2).mode = GridInfo::FILL;
	grid->row(2).align = GridInfo::STRETCH;
	grid->row(3).mode = GridInfo::STATIC;
	grid->row(3).size = 190;
	grid->row(3).align = GridInfo::STRETCH;
	grid->setSpacing(12);
	grid->setFont(uiFont);
	addThemeUpdate([grid] { ui::styleSurface(grid); });

	{
		auto header = grid->addChild(Grid::Seed(2, 5));
		header->column(0).mode = GridInfo::FILL;
		header->column(1).size = 132;
		header->column(1).mode = GridInfo::STATIC;
		header->column(2).size = 106;
		header->column(2).mode = GridInfo::STATIC;
		header->column(3).size = 94;
		header->column(3).mode = GridInfo::STATIC;
		header->column(4).size = 86;
		header->column(4).mode = GridInfo::STATIC;
		header->row(0).mode = GridInfo::AUTO;
		header->row(1).mode = GridInfo::AUTO;
		header->setSpacing(8);
		addThemeUpdate([header] { ui::styleSurface(header); });
		grid->setWidget(header, 0, 0);

		Label::Seed titleSeed(_T("Protocol Analyzer"));
		titleSeed.font = titleFont;
		auto title = header->addChild(titleSeed);
		header->setWidget(title, 0, 0);
		addThemeUpdate([title] {
			styleLabel(title, ui::palette().text, ui::palette().window, titleFont);
		});
		title->setAccessibleName(_T("Protocol Analyzer"));

		Label::Seed subtitleSeed(_T("Inspect live ADC, NMDC, DHT, and UDP traffic."));
		subtitleSeed.font = uiFont;
		auto subtitle = header->addChild(subtitleSeed);
		header->setWidget(subtitle, 1, 0);
		addThemeUpdate([subtitle] {styleLabel(subtitle, ui::palette().muted, ui::palette().window, uiFont);
		});

		Label::Seed liveSeed(_T("\u25cf  LIVE CAPTURE"));
		liveSeed.style |= SS_CENTER;
		liveSeed.font = sectionFont;
		captureStatusLabel = header->addChild(liveSeed);
		header->setWidget(captureStatusLabel, 0, 1, 2, 1);
		addThemeUpdate([] {
			styleLabel(captureStatusLabel, ui::palette().success, ui::palette().window, sectionFont);
		});
		captureStatusLabel->setAccessibleName(_T("Live capture active"));

		Button::Seed themeSeed(ui::isDarkMode() ? _T("Light mode") : _T("Dark mode"));
		themeSeed.font = uiFont;
		themeSeed.padding = Point(16, 7);
		themeButton = header->addChild(themeSeed);
		header->setWidget(themeButton, 0, 2, 2, 1);
		themeButton->onClicked([this] { toggleTheme(); });
		themeButton->setAccessibleName(ui::isDarkMode() ? _T("Switch to light mode") : _T("Switch to dark mode"));
		ui::styleButton(themeButton);

		Button::Seed settingsSeed(_T("Settings"));
		settingsSeed.font = uiFont;
		settingsSeed.padding = Point(16, 7);
		auto settingsButton = header->addChild(settingsSeed);
		header->setWidget(settingsButton, 0, 3, 2, 1);
		settingsButton->onClicked([this] { openSettings(); });
		settingsButton->setAccessibleName(_T("Open Protocol Analyzer settings"));
		ui::styleButton(settingsButton);

		Button::Seed closeSeed(_T("Close"));
		closeSeed.font = uiFont;
		closeSeed.padding = Point(18, 7);
		closeSeed.style |= BS_DEFPUSHBUTTON;
		auto closeButton = header->addChild(closeSeed);
		header->setWidget(closeButton, 0, 4, 2, 1);
		closeButton->onClicked([this] { close(); });
		closeButton->setAccessibleName(_T("Close Protocol Analyzer"));
		ui::styleButton(closeButton, ui::ButtonTone::Primary);
	}

	{
		Table::Seed seed;
		seed.style |= LVS_SHOWSELALWAYS | LVS_OWNERDATA;
		seed.exStyle |= WS_EX_CLIENTEDGE;
		seed.lvStyle = LVS_EX_DOUBLEBUFFER | LVS_EX_HEADERDRAGDROP | LVS_EX_FULLROWSELECT |
						LVS_EX_LABELTIP | LVS_EX_INFOTIP;
		seed.font = uiFont;
		table = grid->addChild(seed);
		grid->setWidget(table, 2, 0);
		addThemeUpdate([] { ui::ScrollBarStyle::apply(table); });
		table->setAccessibleName(_T("Captured protocol messages"));
		table->setAccessibleHelpText(_T("Virtual list of live protocol traffic. Use the filter workspace to narrow the view."));
		table->onGetEmptyText([] { return _T("Waiting for matching protocol traffic\u2026"); });
		makeColumns(table, cols, COLUMN_LAST);
		if(auto header = getTableHeader(table)) {
			header->setFont(sectionFont);
			header->onCustomDraw([](NMCUSTOMDRAW& data) { return drawTableHeader(data); });
		}
		table->onSized([this](const SizedEvent& e) {
			long fixedColumnsWidth = 0;
			const auto widths = table->getColumnWidths();
			for(int column = 0; column < COLUMN_MESSAGE && static_cast<size_t>(column) < widths.size();	++column) {
				fixedColumnsWidth += widths[column];
			}
			const auto chrome = table->getSystemMetric(SM_CXVSCROLL) + table->scale(6);
			auto messageColWidth = std::max(static_cast<long>(table->scale(260)), e.size.x - fixedColumnsWidth - chrome);
			table->setColumnWidth(COLUMN_MESSAGE, messageColWidth);
		});

		// Handle the virtual ListView stuff for our table.
		table->onRaw([this](WPARAM, LPARAM lParam) -> LRESULT {
			auto& nmlv = *reinterpret_cast<NMLVDISPINFO*>(lParam);
			const int idx = nmlv.item.iItem;
			if(idx < 0 || static_cast<size_t>(idx) >= visibleItems.size()) return 0;
			if(!(nmlv.item.mask & LVIF_TEXT)) return 0;
			const Item& it = *visibleItems[idx];
			const auto text = getColumnText(it, nmlv.item.iSubItem);
			if(text && nmlv.item.pszText && nmlv.item.cchTextMax > 0) {
				_tcsncpy_s(nmlv.item.pszText, static_cast<size_t>(nmlv.item.cchTextMax), text->c_str(), _TRUNCATE);
			}
			return 0;
		}, dwt::Message(WM_NOTIFY, LVN_GETDISPINFO));

		table->onRaw([this](WPARAM, LPARAM lParam) -> LRESULT {
			auto tip = reinterpret_cast<NMLVGETINFOTIP*>(lParam);
			if(!tip || !tip->pszText || tip->cchTextMax <= 1) {
				return 0;
			}
			tip->pszText[0] = _T('\0');

			const int row = tip->iItem;
			const int column = tip->iSubItem;
			if(row < 0 || static_cast<size_t>(row) >= visibleItems.size()) {
				return 0;
			}
			const auto item = visibleItems[row];
			const auto text = item ? getColumnText(*item, column) : nullptr;
			if(!text || !columnTextOverflows(table, column, *text)) {
				return 0;
			}

			_tcsncpy_s(tip->pszText, static_cast<size_t>(tip->cchTextMax), text->c_str(), _TRUNCATE);
			return 0;
		}, dwt::Message(WM_NOTIFY, LVN_GETINFOTIP));

		table->onContextMenu([this](const ScreenCoordinate& pt) -> bool {
			auto menu = window->addChild(Menu::Seed());
			auto hasSel = table->hasSelected();
			menu->appendItem(_T("Copy selected messages"), [this] { copy(); }, nullptr, hasSel);
			menu->appendItem(_T("Copy decoded analysis"), [] {
				if(inspectorBox && !inspectorBox->getText().empty()) {
					dwt::Clipboard::setData(inspectorBox->getText(), window);
				}
			}, nullptr, hasSel);
			menu->appendItem(_T("Remove selected messages"), [this] { remove(); }, nullptr, hasSel);
			menu->appendSeparator();
			menu->appendItem(_T("Select all"), [] { table->selectAll(); }, nullptr, !table->empty());

			menu->appendSeparator();
			menu->appendItem(_T("Open protocol documentation"), [this] { openDoc(); }, nullptr, hasSel);

			menu->appendSeparator();
			menu->appendItem(_T("Open settings"), [this] { openSettings(); }, nullptr, true);

			menu->open(pt.x() == -1 || pt.y() == -1 ? table->getContextMenuPos() : pt);
			return true;
		});

		table->onCustomDraw([this](NMLVCUSTOMDRAW& data) { return GUI::handleCustomDraw(data); });
		table->onItemChanged([this](const NMLISTVIEW& change) {
			if((change.uChanged & LVIF_STATE) != 0 &&
				((change.uOldState ^ change.uNewState) &
					(LVIS_SELECTED | LVIS_FOCUSED)) != 0)
			{
				updateInspector();
			}
		});

		// Live filtering
		// I wonder how poy would handle this.. 
		table->onRaw([this](WPARAM, LPARAM lParam) -> LRESULT {
			auto& fi = *reinterpret_cast<NMLVFINDITEM*>(lParam);
			if((fi.lvfi.flags & LVFI_STRING) == 0 || !fi.lvfi.psz) {
				return -1;
			}
			const tstring needle(fi.lvfi.psz);
			const int n = static_cast<int>(visibleItems.size());
			if(n == 0) {
				return -1;
			}
			const int start = fi.iStart < 0 ? 0 : std::min(fi.iStart, n);
			const bool partial = (fi.lvfi.flags & LVFI_PARTIAL) != 0;
			const bool wrap = (fi.lvfi.flags & LVFI_WRAP) != 0;
			auto match = [&](const Item& it) {
				auto compare = [&](const tstring& value) {
					if(partial) {
						return value.size() >= needle.size() &&
							_tcsnicmp(value.c_str(), needle.c_str(), needle.size()) == 0;
					}
					return _tcsicmp(value.c_str(), needle.c_str()) == 0;
				};
				return compare(it.timestamp) || compare(it.index) ||
					compare(it.ip) || compare(it.peer) ||
					compare(it.protocol) || compare(it.dir) ||
					compare(it.command) || compare(it.category) ||
					compare(it.port) || compare(it.summary) ||
					compare(it.safeMessage());
			};
			for(int i = start; i < n; ++i) {
				if(visibleItems[i] && match(*visibleItems[i])) {
					return static_cast<LRESULT>(i);
				}
			}
			if(wrap) {
				for(int i = 0; i < start; ++i) {
					if(visibleItems[i] && match(*visibleItems[i])) {
						return static_cast<LRESULT>(i);
					}
				}
			}
			return -1;
		}, dwt::Message(WM_NOTIFY, LVN_ODFINDITEM));
	}

	auto applyFiltersRef = std::make_shared<std::function<void()>>();

	{
		GroupBox::Seed filterPanelSeed(_T("Filter workspace"));
		filterPanelSeed.font = sectionFont;
		auto filterPanel = grid->addChild(filterPanelSeed);
		grid->setWidget(filterPanel, 1, 0);
		ui::styleGroupBox(filterPanel);
		addThemeUpdate([filterPanel] {
			filterPanel->setFont(sectionFont);
			ui::refreshGroupBox(filterPanel);
		});

		auto cur2 = filterPanel->addChild(Grid::Seed(3, 9));
		cur2->row(0).mode = GridInfo::AUTO;
		cur2->row(1).mode = GridInfo::AUTO;
		cur2->row(2).mode = GridInfo::AUTO;
		cur2->column(0).size = 68;
		cur2->column(1).size = 120;
		cur2->column(2).size = 48;
		cur2->column(3).size = 180;
		cur2->column(4).size = 40;
		cur2->column(5).size = 96;
		cur2->column(6).size = 48;
		cur2->column(7).mode = GridInfo::FILL;
		cur2->column(8).mode = GridInfo::AUTO;
		cur2->setSpacing(8);
		cur2->setFont(uiFont);
		addThemeUpdate([cur2] { ui::styleSurface(cur2); });

		Label::Seed pls;
		pls.style |= SS_CENTER;
		pls.font = uiFont;
		pls.caption = _T("Protocol");
		auto protocolLabel = cur2->addChild(pls);
		addThemeUpdate([protocolLabel] {
			styleLabel(protocolLabel, ui::palette().muted, ui::palette().window, uiFont);
		});

		ComboBox::Seed protocolSeed;
		protocolSeed.style |= CBS_DROPDOWNLIST;
		protocolSeed.font = uiFont;
		protocolFilterBox = cur2->addChild(protocolSeed);
		protocolFilterBox->setAccessibleName(_T("Protocol filter"));
		ui::styleComboBox(protocolFilterBox);
		addThemeUpdate([] { ui::refreshComboBox(protocolFilterBox); });
		protocolFilterBox->addValue(FILTER_ALL_LABEL);
		protocolFilterBox->addValue(_T("ADC"));
		protocolFilterBox->addValue(_T("NMDC"));
		protocolFilterBox->addValue(_T("UDP"));
		protocolFilterBox->addValue(_T("DHT"));
		protocolFilterBox->addValue(_T("Unknown"));
		{
			auto selectedIndex = isAllFilterValue(selectedProtocol) ? 0 :
				protocolFilterBox->findString(selectedProtocol);
			if(selectedIndex < 0) {
				selectedIndex = 0;
			}
			protocolFilterBox->setSelected(selectedIndex);
		}

		Label::Seed ils;
		ils.style |= SS_CENTER;
		ils.font = uiFont;
		ils.caption = _T("Address");
		auto ipLabel = cur2->addChild(ils);
		addThemeUpdate([ipLabel] {
			styleLabel(ipLabel, ui::palette().muted, ui::palette().window, uiFont);
		});

		ComboBox::Seed ipSeed;
		ipSeed.style |= CBS_DROPDOWNLIST;
		ipSeed.font = uiFont;
		ipFilterBox = cur2->addChild(ipSeed);
		ipFilterBox->setAccessibleName(_T("IP address filter"));
		ui::styleComboBox(ipFilterBox);
		addThemeUpdate([] { ui::refreshComboBox(ipFilterBox); });
		ipFilterBox->addValue(FILTER_ALL_LABEL);
		ipFilterBox->setSelected(0);

		Label::Seed pols;
		pols.style |= SS_CENTER;
		pols.font = uiFont;
		pols.caption = _T("Port");
		auto portLabel = cur2->addChild(pols);
		addThemeUpdate([portLabel] {
			styleLabel(portLabel, ui::palette().muted, ui::palette().window, uiFont);
		});

		ComboBox::Seed portSeed;
		portSeed.style |= CBS_DROPDOWNLIST;
		portSeed.font = uiFont;
		portFilterBox = cur2->addChild(portSeed);
		portFilterBox->setAccessibleName(_T("Port filter"));
		ui::styleComboBox(portFilterBox);
		addThemeUpdate([] { ui::refreshComboBox(portFilterBox); });
		portFilterBox->addValue(FILTER_ALL_LABEL);
		portFilterBox->setSelected(0);

		Label::Seed pels;
		pels.style |= SS_CENTER;
		pels.font = uiFont;
		pels.caption = _T("Peer");
		auto peerLabel = cur2->addChild(pels);
		addThemeUpdate([peerLabel] {
			styleLabel(peerLabel, ui::palette().muted, ui::palette().window, uiFont);
		});

		ComboBox::Seed peerSeed;
		peerSeed.style |= CBS_DROPDOWNLIST;
		peerSeed.font = uiFont;
		peerFilterBox = cur2->addChild(peerSeed);
		peerFilterBox->setAccessibleName(_T("Peer filter"));
		ui::styleComboBox(peerFilterBox);
		addThemeUpdate([] { ui::refreshComboBox(peerFilterBox); });
		peerFilterBox->addValue(FILTER_ALL_LABEL);
		peerFilterBox->setSelected(0);

		Label::Seed commandLabelSeed;
		commandLabelSeed.style |= SS_CENTER;
		commandLabelSeed.font = uiFont;
		commandLabelSeed.caption = _T("Command");
		auto commandLabel = cur2->addChild(commandLabelSeed);
		cur2->setWidget(commandLabel, 1, 0);
		addThemeUpdate([commandLabel] {
			styleLabel(commandLabel, ui::palette().muted, ui::palette().window, uiFont);
		});

		ComboBox::Seed commandSeed;
		commandSeed.style |= CBS_DROPDOWNLIST;
		commandSeed.font = uiFont;
		commandFilterBox = cur2->addChild(commandSeed);
		cur2->setWidget(commandFilterBox, 1, 1);
		commandFilterBox->setAccessibleName(_T("Decoded command filter"));
		ui::styleComboBox(commandFilterBox);
		addThemeUpdate([] { ui::refreshComboBox(commandFilterBox); });
		commandFilterBox->addValue(FILTER_ALL_LABEL);
		commandFilterBox->setSelected(0);

		Label::Seed categoryLabelSeed;
		categoryLabelSeed.style |= SS_CENTER;
		categoryLabelSeed.font = uiFont;
		categoryLabelSeed.caption = _T("Category");
		auto categoryLabel = cur2->addChild(categoryLabelSeed);
		cur2->setWidget(categoryLabel, 1, 2);
		addThemeUpdate([categoryLabel] {
			styleLabel(categoryLabel, ui::palette().muted, ui::palette().window, uiFont);
		});

		ComboBox::Seed categorySeed;
		categorySeed.style |= CBS_DROPDOWNLIST;
		categorySeed.font = uiFont;
		categoryFilterBox = cur2->addChild(categorySeed);
		cur2->setWidget(categoryFilterBox, 1, 3);
		categoryFilterBox->setAccessibleName(_T("Decoded category filter"));
		ui::styleComboBox(categoryFilterBox);
		addThemeUpdate([] { ui::refreshComboBox(categoryFilterBox); });
		categoryFilterBox->addValue(FILTER_ALL_LABEL);
		categoryFilterBox->setSelected(0);

		Label::Seed fls;
		fls.style |= SS_CENTER;
		fls.font = uiFont;
		fls.caption = _T("Search");
		auto searchLabel = cur2->addChild(fls);
		cur2->setWidget(searchLabel, 2, 0);
		addThemeUpdate([searchLabel] {
			styleLabel(searchLabel, ui::palette().muted, ui::palette().window, uiFont);
		});

		TextBox::Seed tbs;
		tbs.style |= ES_AUTOHSCROLL | ES_WANTRETURN;
		tbs.font = uiFont;
		auto findBox = cur2->addChild(tbs);
		cur2->setWidget(findBox, 2, 1, 1, 5);
		findBox->setTextLimit(512);
		findBox->setCue(_T("Search command, category, summary, peer, or message"));
		findBox->setAccessibleName(_T("Search captured traffic"));
		addThemeUpdate([findBox] {
			findBox->setColor(ui::palette().text, ui::palette().panel);
		});

		Label::Seed rls;
		rls.style |= SS_CENTER;
		rls.font = uiFont;
		rls.caption = _T("Regex");
		auto regexLabel = cur2->addChild(rls);
		cur2->setWidget(regexLabel, 2, 6);
		addThemeUpdate([regexLabel] {
			styleLabel(regexLabel, ui::palette().muted, ui::palette().window, uiFont);
		});

		TextBox::Seed regexSeed;
		regexSeed.style |= ES_AUTOHSCROLL | ES_WANTRETURN;
		regexSeed.font = uiFont;
		auto regexBox = cur2->addChild(regexSeed);
		cur2->setWidget(regexBox, 2, 7);
		regexBox->setTextLimit(MAX_REGEX_CHARS);
		regexBox->setCue(_T("Safe regex: literals, ., [classes], ^ and $"));
		regexBox->setAccessibleName(_T("Regular expression filter"));
		addThemeUpdate([regexBox] {
			regexBox->setColor(ui::palette().text, ui::palette().panel);
		});
		if(!regexText.empty()) {
			regexBox->setText(regexText);
		}

		Button::Seed applyBtnSeed(_T("Apply"));
		applyBtnSeed.font = uiFont;
		applyBtnSeed.padding = Point(16, 5);
		auto applyBtn = cur2->addChild(applyBtnSeed);
		cur2->setWidget(applyBtn, 2, 8);
		ui::styleButton(applyBtn, ui::ButtonTone::Primary);

		Button::Seed resetBtnSeed(_T("Reset"));
		resetBtnSeed.font = uiFont;
		resetBtnSeed.padding = Point(16, 5);
		auto resetBtn = cur2->addChild(resetBtnSeed);
		cur2->setWidget(resetBtn, 0, 8);
		resetBtn->setAccessibleName(_T("Reset all filters"));
		ui::styleButton(resetBtn);

		*applyFiltersRef = [this, findBox] {
			findText = findBox->getText();
			if(findText.size() > 512) {
				findText.resize(512);
			}
			pendingFindText = findText;
			searchPending = false;
			refreshVisibleItems();
			if(table) {
				table->clearSelection();
				table->redraw();
			}
			updateStatus();
		};

		auto applyRegexRef = std::make_shared<std::function<void()>>();
		*applyRegexRef = [this, regexBox, applyFiltersRef] {
			regexText = regexBox->getText();
			if(regexText.size() > MAX_REGEX_CHARS) {
				regexText.resize(MAX_REGEX_CHARS);
			}
			Config::setConfig("RegEx", Util::fromT(regexText));
			(*applyFiltersRef)();
		};

		findBox->onUpdated([this, findBox] {
			scheduleSearch(findBox->getText());
		});
		regexBox->onKeyDown([applyRegexRef](int key) -> bool {
			if(key == VK_RETURN) { (*applyRegexRef)(); return true; }
			return false;
		});
		applyBtn->onClicked([applyRegexRef] { (*applyRegexRef)(); });
		resetBtn->onClicked([this, findBox, regexBox, applyFiltersRef] {
			selectedProtocol = FILTER_ALL;
			selectedIp = FILTER_ALL;
			selectedPort = FILTER_ALL;
			selectedPeer = FILTER_ALL;
			selectedCommand = FILTER_ALL;
			selectedCategory = FILTER_ALL;
			findText.clear();
			regexText.clear();
			regexValid = true;

			protocolFilterBox->setSelected(0);
			ipFilterBox->setSelected(0);
			portFilterBox->setSelected(0);
			peerFilterBox->setSelected(0);
			commandFilterBox->setSelected(0);
			categoryFilterBox->setSelected(0);
			findBox->setText(tstring());
			regexBox->setText(tstring());

			Config::setConfig("FilterProtocol", "all:");
			Config::setConfig("FilterIp", "all:");
			Config::setConfig("FilterPort", "all:");
			Config::setConfig("FilterPeer", "all:");
			Config::setConfig("FilterCommand", "all:");
			Config::setConfig("FilterCategory", "all:");
			Config::setConfig("RegEx", "");
			(*applyFiltersRef)();
		});

		protocolFilterBox->onSelectionChanged([this, applyFiltersRef] {
			const int selected = protocolFilterBox ? protocolFilterBox->getSelected() : -1;
			selectedProtocol = selected > 0 ?
				protocolFilterBox->getValue(selected) : tstring(FILTER_ALL);
			Config::setConfig("FilterProtocol", encodeFilterSetting(selectedProtocol));
			(*applyFiltersRef)();
		});

		ipFilterBox->onSelectionChanged([this, applyFiltersRef] {
			const int selected = ipFilterBox ? ipFilterBox->getSelected() : -1;
			selectedIp = selected > 0 ? ipFilterBox->getValue(selected) : tstring(FILTER_ALL);
			Config::setConfig("FilterIp", encodeFilterSetting(selectedIp));
			(*applyFiltersRef)();
		});

		portFilterBox->onSelectionChanged([this, applyFiltersRef] {
			const int selected = portFilterBox ? portFilterBox->getSelected() : -1;
			selectedPort = selected > 0 ? portFilterBox->getValue(selected) : tstring(FILTER_ALL);
			Config::setConfig("FilterPort", encodeFilterSetting(selectedPort));
			(*applyFiltersRef)();
		});

		peerFilterBox->onSelectionChanged([this, applyFiltersRef] {
			const int selected = peerFilterBox ? peerFilterBox->getSelected() : -1;
			selectedPeer = selected > 0 ? peerFilterBox->getValue(selected) : tstring(FILTER_ALL);
			Config::setConfig("FilterPeer", encodeFilterSetting(selectedPeer));
			(*applyFiltersRef)();
		});

		commandFilterBox->onSelectionChanged([this, applyFiltersRef] {
			const int selected = commandFilterBox ? commandFilterBox->getSelected() : -1;
			selectedCommand = selected > 0 ?
				commandFilterBox->getValue(selected) : tstring(FILTER_ALL);
			Config::setConfig("FilterCommand", encodeFilterSetting(selectedCommand));
			(*applyFiltersRef)();
		});

		categoryFilterBox->onSelectionChanged([this, applyFiltersRef] {
			const int selected = categoryFilterBox ? categoryFilterBox->getSelected() : -1;
			selectedCategory = selected > 0 ?
				categoryFilterBox->getValue(selected) : tstring(FILTER_ALL);
			Config::setConfig("FilterCategory", encodeFilterSetting(selectedCategory));
			(*applyFiltersRef)();
		});

		auto refreshOnClose = [this](ComboBoxPtr box) {
			box->onRaw([this](WPARAM, LPARAM) -> LRESULT {
				rebuildFilterChoices(true);
				return 0;
			}, dwt::Message(WM_COMMAND, CBN_CLOSEUP));
		};
		refreshOnClose(ipFilterBox);
		refreshOnClose(portFilterBox);
		refreshOnClose(peerFilterBox);
		refreshOnClose(commandFilterBox);
		refreshOnClose(categoryFilterBox);

		compileRegex();
		rebuildFilterChoices(true);
	}

	{
		GroupBox::Seed inspectorPanelSeed(_T("Decoded message inspector"));
		inspectorPanelSeed.font = sectionFont;
		auto inspectorPanel = grid->addChild(inspectorPanelSeed);
		grid->setWidget(inspectorPanel, 3, 0);
		ui::styleGroupBox(inspectorPanel);
		addThemeUpdate([inspectorPanel] {
			inspectorPanel->setFont(sectionFont);
			ui::refreshGroupBox(inspectorPanel);
		});

		auto inspectorContent = inspectorPanel->addChild(Grid::Seed(1, 1));
		inspectorContent->row(0).mode = GridInfo::FILL;
		inspectorContent->row(0).align = GridInfo::STRETCH;
		inspectorContent->column(0).mode = GridInfo::FILL;
		ui::styleSurface(inspectorContent);
		addThemeUpdate([inspectorContent] { ui::styleSurface(inspectorContent); });

		RichTextBox::Seed inspectorSeed;
		inspectorSeed.style |= ES_READONLY | ES_WANTRETURN;
		inspectorSeed.font = uiFont;
		inspectorSeed.scrollBarVerticallyFlag = true;
		inspectorBox = inspectorContent->addChild(inspectorSeed);
		inspectorContent->setWidget(inspectorBox, 0, 0);
		addThemeUpdate([] { ui::ScrollBarStyle::apply(inspectorBox); });
		inspectorBox->setColor(
			table_colors::get(table_colors::Role::InspectorText),
			table_colors::get(table_colors::Role::InspectorBackground));
		renderInspectorText(
			_T("Select a captured message to decode its fields."));
		inspectorBox->setAccessibleName(_T("Decoded protocol message details"));
		inspectorBox->setAccessibleHelpText(
			_T("Read-only color-highlighted decoded fields, validation warnings, ")
			_T("and redacted raw data."));
		addThemeUpdate([] {
			if(inspectorBox) {
				refreshInspectorPalette();
			}
		});
	}

	{
		GroupBox::Seed actionPanelSeed(_T("View and actions"));
		actionPanelSeed.font = sectionFont;
		auto actionPanel = grid->addChild(actionPanelSeed);
		grid->setWidget(actionPanel, 4, 0);
		ui::styleGroupBox(actionPanel);
		addThemeUpdate([actionPanel] {
			actionPanel->setFont(sectionFont);
			ui::refreshGroupBox(actionPanel);
		});

		auto actions = actionPanel->addChild(Grid::Seed(1, 5));
		actionsGrid = actions;
		actions->column(3).mode = GridInfo::FILL;
		actions->column(4).size = 270;
		actions->column(4).mode = GridInfo::STATIC;
		actions->setSpacing(18);
		addThemeUpdate([actions] { ui::styleSurface(actions); });

		CheckBox::Seed scrollSeed(_T("Follow newest traffic"));
		scrollSeed.font = uiFont;
		auto scrollW = actions->addChild(scrollSeed);
		scrollW->setChecked(scroll);
		ui::styleCheckBox(scrollW);
		addThemeUpdate([scrollW] {
			ui::refreshCheckBox(scrollW);
		});
		scrollW->setAccessibleHelpText(_T("Automatically reveal the newest matching message."));
		scrollW->onClicked([this, scrollW] {
			scroll = scrollW->getChecked();
		});

		CheckBox::Seed onTopSeed(_T("Always on top"));
		onTopSeed.font = uiFont;
		auto onTop = actions->addChild(onTopSeed);
		onTop->setChecked(keepOnTop);
		ui::styleCheckBox(onTop);
		addThemeUpdate([onTop] {
			ui::refreshCheckBox(onTop);
		});
		onTop->onClicked([this, onTop] {
			window->setZOrder(onTop->getChecked() ? HWND_TOPMOST : HWND_NOTOPMOST);
			keepOnTop = onTop->getChecked();
		});
		window->setZOrder(keepOnTop ? HWND_TOPMOST : HWND_NOTOPMOST);

		Button::Seed clearSeed(_T("Clear history"));
		clearSeed.font = uiFont;
		clearSeed.padding = Point(16, 5);
		auto clearButton = actions->addChild(clearSeed);
		clearButton->onClicked([this] { clear(); });
		clearButton->setAccessibleName(_T("Clear captured message history"));
		ui::styleButton(clearButton, ui::ButtonTone::Danger);

		Label::Seed filterStatusSeed(_T("All traffic"));
		filterStatusSeed.style |= SS_RIGHT;
		filterStatusSeed.font = sectionFont;
		filterStatusLabel = actions->addChild(filterStatusSeed);
		addThemeUpdate([] {
			styleLabel(filterStatusLabel, ui::palette().muted, ui::palette().window, sectionFont);
		});

		Label::Seed itemCountSeed(_T("0 shown  \u00b7  0 captured"));
		itemCountSeed.style |= SS_RIGHT;
		itemCountSeed.font = uiFont;
		itemCountLabel = actions->addChild(itemCountSeed);
		addThemeUpdate([] {
			styleLabel(itemCountLabel, ui::palette().muted, ui::palette().window, uiFont);
		});
	}

	layoutRoot();
	window->onSized([this](const SizedEvent&) { layoutRoot(); });
	window->onDpiChanged([this](const DpiChangedEvent& event) {
		handleDpiChanged(event.oldDpi, event.newDpi);
	});
	window->onSystemColorsChanged([this] { applyTheme(); });
	window->onSystemSettingsChanged([this](const SystemSettingsEvent&) { applyTheme(); });
	window->onThemeChanged([this] { applyTheme(); });

	table->setFocus();
	const auto tableBackground = getTableBackground();
	table->setColor(table_colors::get(table_colors::Role::Text), tableBackground);
	updateStatus();

	window->setTimer([this]() -> bool {
		if(shuttingDown) {
			return false;
		}
		timer();
		return !shuttingDown;
	}, 250, 1);

	Config::setConfig("Dialog", true);
	showWindow();
	dcapi::Logger::log("[Protocol Analyzer]: window shown");
}

bool GUI::showWindow() {
	if(!window) {
		return false;
	}
	const auto hWnd = window->handle();
	if(!::IsWindow(hWnd)) {
		return false;
	}

	if(::IsIconic(hWnd)) {
		window->restore();
	} else {
		window->setVisible(true);
	}
	window->setFocus();
	return ::IsWindowVisible(hWnd) && !::IsIconic(hWnd);
}

void GUI::write(bool sending, ProtocolType proto, string ip, decltype(ConnectionData().port) port, string peer, string message) {
	auto pStr = [](ProtocolType p) -> string {
		if(static_cast<int>(p) == static_cast<int>(PROTOCOL_UDP)) {
			return "UDP"; // HACK: use our own definition for UDP.
		}
		switch (p) {
			case PROTOCOL_ADC: return "ADC";
			case PROTOCOL_NMDC: return "NMDC";
			case PROTOCOL_DHT: return "DHT"; // Reserved
			default: return "Unknown";
		}
	};

	truncateBytes(ip, MAX_ADDRESS_BYTES);
	truncateBytes(message, MAX_MESSAGE_BYTES);

	const auto protocol = pStr(proto);
	const auto stateNow = std::chrono::steady_clock::now();
	BloomHeader bloomHeader;
	const bool hasBloomHeader =
		protocol == "ADC" && parseBloomHeader(message, bloomHeader);
	bool bloomPayload = false;
	bool bloomRequestCorrelated = false;
	uint64_t bloomAnnouncedBytes = 0;
	{
		std::lock_guard<std::mutex> lock(messagesMutex);
		while(!bloomRequests.empty() &&
			bloomRequests.front().expires <= stateNow)
		{
			bloomRequests.pop_front();
		}
		while(!bloomPayloads.empty() &&
			bloomPayloads.front().expires <= stateNow)
		{
			bloomPayloads.pop_front();
		}

		const auto sameEndpoint = [&](const auto& state) {
			return state.protocol == protocol && state.ip == ip &&
				state.port == port && state.peer == peer;
		};
		auto payload = std::find_if(
			bloomPayloads.begin(), bloomPayloads.end(),
			[&](const BloomPayload& state) {
				return state.sending == sending && sameEndpoint(state);
			});
		if(payload != bloomPayloads.end()) {
			bloomPayload = true;
			bloomRequestCorrelated = payload->requestCorrelated;
			bloomAnnouncedBytes = payload->bytes;
			bloomPayloads.erase(payload);
		} else if(hasBloomHeader && !sending &&
			bloomHeader.kind == BloomHeaderKind::Get)
		{
			bloomRequests.erase(std::remove_if(
				bloomRequests.begin(), bloomRequests.end(),
				[&](const BloomRequest& state) {
					return state.sending == sending && sameEndpoint(state);
				}), bloomRequests.end());
			if(bloomRequests.size() == MAX_PENDING_BLOOM_REQUESTS) {
				bloomRequests.pop_front();
			}
			bloomRequests.push_back(BloomRequest {
				sending, protocol, ip, port, peer, bloomHeader.bytes,
				bloomHeader.k, bloomHeader.h,
				stateNow + BLOOM_REQUEST_LIFETIME
			});
		} else if(hasBloomHeader && sending &&
			bloomHeader.kind == BloomHeaderKind::Send)
		{
			auto request = std::find_if(
				bloomRequests.begin(), bloomRequests.end(),
				[&](const BloomRequest& state) {
					return state.sending != sending && sameEndpoint(state) &&
						state.bytes == bloomHeader.bytes &&
						(!bloomHeader.hasK || state.k == bloomHeader.k) &&
						(!bloomHeader.hasH || state.h == bloomHeader.h);
				});
			if(request != bloomRequests.end()) {
				bloomRequestCorrelated = true;
				bloomRequests.erase(request);
			}

			// Do not let an injected stand-alone HSND (for example via /raw)
			// suppress the next ordinary command. The hub-side BLOM exchange is
			// armed only after its opposite-direction IGET was observed.
			const bool armPayload = bloomRequestCorrelated;
			if(armPayload && bloomHeader.bytes != 0) {
				bloomPayloads.erase(std::remove_if(
					bloomPayloads.begin(), bloomPayloads.end(),
					[&](const BloomPayload& state) {
						return state.sending == sending && sameEndpoint(state);
					}), bloomPayloads.end());
				if(bloomPayloads.size() == MAX_PENDING_BLOOM_PAYLOADS) {
					bloomPayloads.pop_front();
				}
				bloomPayloads.push_back(BloomPayload {
					sending, protocol, ip, port, peer, bloomHeader.bytes,
					bloomRequestCorrelated,
					stateNow + BLOOM_PAYLOAD_LIFETIME
				});
			}
		}
	}

	truncateBytes(peer, MAX_PEER_BYTES);
	if(bloomPayload) {
		// Do not retain a byte of the body in the callback queue. In
		// particular, it must never reach UTF-8 conversion or RichEdit.
		std::fill(message.begin(), message.end(), '\0');
		message =
			"[BLOM binary payload withheld; announced " +
			std::to_string(bloomAnnouncedBytes) + " bytes]";
	}

	auto msg = std::make_unique<Message>();
	msg->sending = sending;
	msg->protocol = protocol;
	msg->ip = move(ip);
	msg->port = port;
	msg->peer = move(peer);
	msg->message = move(message);
	msg->bloomPayload = bloomPayload;
	msg->bloomRequestCorrelated = bloomRequestCorrelated;
	msg->bloomAnnouncedBytes = bloomAnnouncedBytes;
	msg->arrival = std::chrono::system_clock::now();
	msg->storageBytes = messageStorageBytes(
		msg->protocol, msg->ip, msg->peer, msg->message);

	std::lock_guard<std::mutex> lock(messagesMutex);
	msg->generation = captureGeneration;
	if(messages.size() < messageQueueCapacity &&
		msg->storageBytes <= MESSAGE_QUEUE_BYTE_CAPACITY &&
		messagesBytes <= MESSAGE_QUEUE_BYTE_CAPACITY - msg->storageBytes)
	{
		messagesBytes += msg->storageBytes;
		messages.emplace_back(std::move(msg));
	} else {
		saturatingAdd(pendingDroppedMessages, uint64_t { 1 });
		saturatingAdd(pendingDroppedBytes,
			static_cast<uint64_t>(msg->storageBytes));
	}
}

void GUI::close() {
	if(window) {
		saveState();
		Config::setConfig("Dialog", false);
		window->setVisible(false);
		dcapi::Logger::log("[Protocol Analyzer]: window hidden, messages are still being processed in the background");
	}
}

void GUI::openSettings() {
	if(!window || shuttingDown) {
		return;
	}
	auto state = settingsState;
	std::shared_ptr<SettingsDlg> dialog;
	{
		std::lock_guard<std::mutex> lock(state->mutex);
		if(!state->alive || state->active || shuttingDown) {
			return;
		}
		dialog = std::make_shared<SettingsDlg>(window, *this);
		state->active = dialog;
	}
	try {
		dialog->run();
	} catch(...) {
		std::lock_guard<std::mutex> lock(state->mutex);
		if(state->active == dialog) {
			state->active.reset();
		}
		throw;
	}
	{
		std::lock_guard<std::mutex> lock(state->mutex);
		if(state->active == dialog) {
			state->active.reset();
		}
		if(!state->alive || !window || !table || shuttingDown) {
			return;
		}
		log = Config::getConfig("Log");
		if(log.empty()) {
			logError.clear();
		}
		const auto tableBackground = getTableBackground();
		table->setColor(
			table_colors::get(table_colors::Role::Text), tableBackground);
		redrawTable();
	}
}

void GUI::timer() {
	applyPendingSearch();

	std::deque<std::unique_ptr<Message>> pending;
	uint64_t activeGeneration = 0;
	uint64_t newDrops = 0;
	uint64_t newDroppedBytes = 0;
	{
		std::lock_guard<std::mutex> lock(messagesMutex);
		pending.swap(messages);
		messagesBytes = 0;
		activeGeneration = captureGeneration;
		newDrops = pendingDroppedMessages;
		newDroppedBytes = pendingDroppedBytes;
		pendingDroppedMessages = 0;
		pendingDroppedBytes = 0;
	}
	saturatingAdd(droppedMessages, newDrops);
	saturatingAdd(droppedBytes, newDroppedBytes);

	if(pending.empty() && !newDrops && !filterChoicesDirty) {
		return;
	}

	const auto timeFmt = normalizeTimestampFormat(Config::getConfig("TimeStampFormat"));
	string logBatch;
	bool logBatchTruncated = false;
	bool matchingItemAdded = false;

	while(!pending.empty()) {
		auto messagePtr = std::move(pending.front());
		pending.pop_front();
		if(!messagePtr || messagePtr->generation != activeGeneration) {
			continue;
		}
		auto& message = *messagePtr;

		auto ip = Util::toT(message.ip);
		const auto timeText = formatTimestamp(message.arrival, timeFmt);
		protocol_analyzer::Result analysis;
		string formattedAnalysis;
		try {
			if(message.bloomPayload) {
				const auto announcedBytes = static_cast<size_t>(
					std::min<uint64_t>(
						message.bloomAnnouncedBytes,
						(std::numeric_limits<size_t>::max)()));
				analysis = protocol_analyzer::analyzeBinaryPayload(
					message.protocol, "blom", announcedBytes);
				analysis.fields.push_back(protocol_analyzer::Field {
					"request", "IGET correlation",
					message.bloomRequestCorrelated ?
						"Matched" : "Not observed", false
				});
				formattedAnalysis =
					protocol_analyzer::formatDetails(analysis);
			} else {
				analysis = protocol_analyzer::analyze(
					message.protocol, message.message);
				formattedAnalysis =
					protocol_analyzer::formatDetails(analysis);
			}
		} catch(...) {
			analysis.family = message.protocol;
			analysis.command = "AnalysisError";
			analysis.name = "Analysis unavailable";
			analysis.category = "Malformed";
			analysis.routing = "Unknown";
			analysis.summary = "Analysis unavailable; raw data withheld from output";
			analysis.safeMessage = "[analysis unavailable; raw message withheld]";
			analysis.status = protocol_analyzer::Status::Invalid;
			analysis.known = false;
			analysis.warnings.emplace_back(
				"The decoder could not safely allocate or process this message.");
			formattedAnalysis =
				"Analysis unavailable. Raw message was not retained.";
		}

		if(!log.empty() && !logBatchTruncated) {
			const auto line = escapeLogField(Util::fromT(timeText)) + " " +
				std::to_string(counter) + " [" +
				(message.sending ? "Out" : "In") + "] [" +
				escapeLogField(message.protocol) + "] " +
				escapeLogField(message.ip) + ":" + std::to_string(message.port) +
				" (" + escapeLogField(message.peer) + "): " +
				escapeLogField(analysis.safeMessage) + "\r\n";
			if(line.size() <= MAX_LOG_BATCH_BYTES &&
				logBatch.size() <= MAX_LOG_BATCH_BYTES - line.size())
			{
				logBatch += line;
			} else {
				logBatchTruncated = true;
			}
		}

		auto item = std::make_unique<Item>();
		item->timestamp = timeText;
		item->index = Util::toT(std::to_string(counter));
		item->dir = message.sending ? _T("Out") : _T("In");
		item->protocol = Util::toT(message.protocol);
		item->command = Util::toT(analysis.command);
		item->category = Util::toT(analysis.category);
		item->ip = move(ip);
		item->port = Util::toT(std::to_string(message.port));
		item->peer = Util::toT(message.peer);
		item->summary = Util::toT(analysis.summary);
		// Retained history never keeps the unredacted payload. The bounded
		// inspector text is computed once while the temporary capture is alive.
		item->message = Util::toT(analysis.safeMessage);
		item->details = Util::toT(formattedAnalysis);
		item->validation = Util::toT(protocol_analyzer::statusName(analysis.status));
		item->sensitive = analysis.sensitive;
		item->storageBytes = itemStorageBytes(*item);

		auto itemPtr = item.get();
		historyBytes += item->storageBytes;
		addFilterChoices(*item);
		tableItems.emplace_back(std::move(item));
		if(matchFind(*itemPtr)) {
			visibleItems.push_back(itemPtr);
			matchingItemAdded = true;
		}

		saturatingAdd(counter, uint64_t { 1 });
	}

	if(!log.empty() && !logBatch.empty()) {
		appendUtf8Log(log, logBatch, logError);
	}
	if(logBatchTruncated) {
		logError = _T("A log batch exceeded 8 MiB and was truncated.");
	}

	const auto evictionsBefore = evictedMessages;
	enforceHistoryLimits();
	const bool filtersChanged = rebuildFilterChoices(
		false, evictionsBefore == evictedMessages);
	if(filtersChanged || evictionsBefore != evictedMessages) {
		rebuildVisibleItems();
	}

	if(!pending.empty() || matchingItemAdded || evictionsBefore != evictedMessages ||
		newDrops || filtersChanged)
	{
		const bool resetViewport = justCleared || evictionsBefore != evictedMessages;
		syncTableItemCount(resetViewport);
		justCleared = false;

		if(table && scroll && matchingItemAdded && !visibleItems.empty()) {
			table->ensureVisible(static_cast<int>(visibleItems.size() - 1));
		}
	}

	updateStatus();
}

void GUI::copy() {
	tstring str;
	str.reserve(std::min<size_t>(MAX_COPY_CHARS, visibleItems.size() * 160));
	bool truncated = false;

	int i = -1;
	while((i = table->getNext(i, LVNI_SELECTED)) != -1) {
		if(static_cast<size_t>(i) < visibleItems.size()) {
			auto& item = *visibleItems[i];
			tstring line = item.timestamp + _T(" ") + item.index + _T(" ") +
				_T(" [") + item.dir + _T("] ") + _T(" [") + item.protocol +
				_T("] [") + item.command + _T("] ") + item.ip + _T(":") +
				item.port + _T(" (") + item.peer + _T("): ") +
				item.safeMessage();
			const size_t separator = str.empty() ? 0 : 2;
			if(line.size() > MAX_COPY_CHARS ||
				str.size() > MAX_COPY_CHARS - std::min(line.size() + separator,
					MAX_COPY_CHARS))
			{
				truncated = true;
				break;
			}
			if(separator) {
				str += _T("\r\n");
			}
			str += line;
		}
	}

	if(!str.empty()) {
		dwt::Clipboard::setData(str, window);
	}
	if(truncated && window) {
		dwt::MessageBox(window).show(
			_T("The selection exceeded the 4 MiB clipboard safety limit. ")
			_T("Only the rows that fit were copied."),
			_T("Protocol Analyzer"), dwt::MessageBox::BOX_OK,
			dwt::MessageBox::BOX_ICONINFORMATION);
	}
}

void GUI::updateInspector() {
	if(!inspectorBox) {
		return;
	}
	if(!table || shuttingDown) {
		renderInspectorText(tstring());
		return;
	}
	const int selected = table->getNext(-1, LVNI_SELECTED);
	if(selected < 0 || static_cast<size_t>(selected) >= visibleItems.size() ||
		!visibleItems[static_cast<size_t>(selected)])
	{
		renderInspectorText(
			_T("Select a captured message to decode its fields."));
		return;
	}

	const auto& item = *visibleItems[static_cast<size_t>(selected)];
	renderInspectorText(item.details.empty() ?
		_T("Analysis unavailable. Raw message was not retained.") : item.details);
}

void GUI::clear() {
	{
		std::lock_guard<std::mutex> lock(messagesMutex);
		saturatingAdd(captureGeneration, uint64_t { 1 });
		messages.clear();
		bloomRequests.clear();
		bloomPayloads.clear();
		messagesBytes = 0;
		pendingDroppedMessages = 0;
		pendingDroppedBytes = 0;
	}
	tableItems.clear();
	visibleItems.clear();
	ipChoices.clear();
	portChoices.clear();
	peerChoices.clear();
	commandChoices.clear();
	categoryChoices.clear();
	filterChoicesDirty = true;
	historyBytes = 0;
	syncTableItemCount(true);
	justCleared = true;
	counter = 0;
	droppedMessages = 0;
	droppedBytes = 0;
	evictedMessages = 0;
	rebuildFilterChoices(true, false);
	rebuildVisibleItems();
	updateInspector();
	updateStatus();
}

void GUI::remove() {
	std::unordered_set<Item*> selectedItems;
	for(int i = table->getNext(-1, LVNI_SELECTED); i != -1; i = table->getNext(i, LVNI_SELECTED)) {
		if(static_cast<size_t>(i) < visibleItems.size() && visibleItems[i]) {
			selectedItems.insert(visibleItems[i]);
		}
	}

	if(selectedItems.empty()) {
		return;
	}
	for(const auto& item : tableItems) {
		if(item && selectedItems.find(item.get()) != selectedItems.end()) {
			removeFilterChoices(*item);
			historyBytes -= std::min(historyBytes, item->storageBytes);
		}
	}
	tableItems.erase(std::remove_if(tableItems.begin(), tableItems.end(),
		[&selectedItems](const std::unique_ptr<Item>& item) {
			return item && selectedItems.find(item.get()) != selectedItems.end();
		}), tableItems.end());

	rebuildFilterChoices(true, false);
	rebuildVisibleItems();
	syncTableItemCount(true);
	updateInspector();
	updateStatus();
}

LRESULT GUI::handleCustomDraw(NMLVCUSTOMDRAW& data) {
	if(shuttingDown || !table) {
		return CDRF_DODEFAULT;
	}

	if(data.nmcd.dwDrawStage == CDDS_PREPAINT) {
		return CDRF_NOTIFYITEMDRAW;
	}
	if(data.nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
		return CDRF_NOTIFYSUBITEMDRAW;
	}

	const auto itemIndex = static_cast<size_t>(data.nmcd.dwItemSpec);
	if(data.nmcd.dwDrawStage == (CDDS_ITEMPREPAINT | CDDS_SUBITEM) &&
		data.dwItemType == LVCDI_ITEM && itemIndex < visibleItems.size())
	{
		const auto row = static_cast<int>(itemIndex);
		const bool selected =
			(ListView_GetItemState(table->handle(), row, LVIS_SELECTED) & LVIS_SELECTED) != 0;
		if(selected) {
			data.nmcd.uItemState |= CDIS_SELECTED;
		} else {
			data.nmcd.uItemState &= ~CDIS_SELECTED;
		}
		if(selected) {
			data.clrText = table_colors::get(table_colors::Role::SelectionText);
			data.clrTextBk = table_colors::get(table_colors::Role::SelectionBackground);
			return CDRF_NEWFONT;
		}

		data.clrTextBk = table_colors::get(
			itemIndex % 2 == 0 ?
				table_colors::Role::Background :
				table_colors::Role::AlternateBackground);
		const Item& item = *visibleItems[itemIndex];
		auto role = table_colors::Role::Text;
		switch(data.iSubItem) {
			case COLUMN_TIMESTAMP:
				role = table_colors::Role::Timestamp;
				break;
			case COLUMN_COUNT:
				role = table_colors::Role::Counter;
				break;
			case COLUMN_DIRECTION:
				role = item.dir == _T("Out") ?
					table_colors::Role::Outgoing : table_colors::Role::Incoming;
				break;
			case COLUMN_PROTOCOL:
				if(item.protocol == _T("ADC")) {
					role = table_colors::Role::Adc;
				} else if(item.protocol == _T("NMDC")) {
					role = table_colors::Role::Nmdc;
				} else if(item.protocol == _T("UDP")) {
					role = table_colors::Role::Udp;
				} else if(item.protocol == _T("DHT")) {
					role = table_colors::Role::Dht;
				} else {
					role = table_colors::Role::Unknown;
				}
				break;
			case COLUMN_IP:
				role = table_colors::Role::Address;
				break;
			case COLUMN_PORT:
				role = table_colors::Role::Port;
				break;
			case COLUMN_PEER:
				role = table_colors::Role::Peer;
				break;
			case COLUMN_SUMMARY:
			case COLUMN_MESSAGE:
				role = table_colors::Role::Message;
				break;
			default:
				break;
		}
		data.clrText = table_colors::get(role);
		return CDRF_NEWFONT;
	}

	return CDRF_DODEFAULT;
}

void GUI::openDoc() {
	if(!table || shuttingDown) {
		return;
	}

	const tstring ADC_Doc = _T("https://adc.sourceforge.io/ADC.html");
	const tstring NMDC_Doc = _T("https://dc-protocols.github.io/NMDC.html");
	const tstring DHT_Doc = _T("https://dc-protocols.github.io/NMDC.html#4622-dht");
	const tstring UDP_Doc = _T("https://www.rfc-editor.org/rfc/rfc768.html");
	const tstring Protocol_Index = _T("https://dc-protocols.github.io/");

	int i = -1;
	while((i = table->getNext(i, LVNI_SELECTED)) != -1) {
		if(i < 0 || static_cast<size_t>(i) >= visibleItems.size()) {
			continue;
		}

		auto data = visibleItems[i];
		if(data) {
			auto openLink = [](const tstring& doc) {
				::ShellExecute(0, 0, doc.c_str(), 0, 0, SW_SHOW);
			};

			if(data->protocol == _T("ADC")) {
				openLink(ADC_Doc);
			} else if(data->protocol == _T("NMDC")) {
				openLink(NMDC_Doc);
			} else if(data->protocol == _T("DHT")) {
				openLink(DHT_Doc);
			} else if(data->protocol == _T("UDP")) {
				openLink(UDP_Doc);
			} else {
				openLink(Protocol_Index);
			}

			break;
		}
	}
}


//I have horrible naming conventions, please forgive me :'(
bool GUI::matchFind(const Item& item) const {
	return matchesStructuredFilters(item) && matchesSearch(item);
}

bool GUI::matchesStructuredFilters(const Item& item) const {
	auto equal = [](const tstring& a, const tstring& b) {
		return _tcsicmp(a.c_str(), b.c_str()) == 0;
	};
	return (isAllFilterValue(selectedProtocol) || equal(item.protocol, selectedProtocol)) &&
		(isAllFilterValue(selectedIp) || equal(item.ip, selectedIp)) &&
		(isAllFilterValue(selectedPort) || equal(item.port, selectedPort)) &&
		(isAllFilterValue(selectedPeer) || equal(item.peer, selectedPeer)) &&
		(isAllFilterValue(selectedCommand) || equal(item.command, selectedCommand)) &&
		(isAllFilterValue(selectedCategory) || equal(item.category, selectedCategory));
}

bool GUI::matchesSearch(const Item& item) const {
	const auto& safeMessage = item.safeMessage();
	const std::array<const tstring*, 12> fields {
		&item.timestamp, &item.index, &item.ip, &item.peer,
		&item.protocol, &item.dir, &item.port, &item.command,
		&item.category, &item.summary, &item.validation, &safeMessage
	};

	const bool textMatches = findText.empty() ||
		std::any_of(fields.begin(), fields.end(), [this](const tstring* value) {
			return containsCaseInsensitive(*value, findText);
		});
	if(!textMatches || regexText.empty()) {
		return textMatches;
	}
	if(!regexValid) {
		return false;
	}
	return std::any_of(fields.begin(), fields.end(), [this](const tstring* value) {
		auto utf8 = Util::fromT(*value);
		if(utf8.size() > MAX_REGEX_FIELD_BYTES) {
			utf8.resize(MAX_REGEX_FIELD_BYTES);
		}
		return std::regex_search(utf8, searchRegex);
	});
}

bool GUI::isAllFilterValue(const tstring& value) const {
	return value.empty() || value == FILTER_ALL;
}

bool GUI::CaseInsensitiveLess::operator()(const tstring& a, const tstring& b) const {
	return _tcsicmp(a.c_str(), b.c_str()) < 0;
}

void GUI::addFilterChoices(const Item& item) {
	auto add = [](FilterChoiceCounts& choices, const tstring& value) {
		if(!value.empty()) {
			++choices[value];
		}
	};
	add(ipChoices, item.ip);
	add(portChoices, item.port);
	add(peerChoices, item.peer);
	add(commandChoices, item.command);
	add(categoryChoices, item.category);
	filterChoicesDirty = true;
}

void GUI::removeFilterChoices(const Item& item) {
	auto remove = [](FilterChoiceCounts& choices, const tstring& value) {
		auto i = choices.find(value);
		if(i != choices.end() && --i->second == 0) {
			choices.erase(i);
		}
	};
	remove(ipChoices, item.ip);
	remove(portChoices, item.port);
	remove(peerChoices, item.peer);
	remove(commandChoices, item.command);
	remove(categoryChoices, item.category);
	filterChoicesDirty = true;
}

bool GUI::rebuildFilterChoices(bool force, bool preserveMissing) {
	if(!force && !filterChoicesDirty) {
		return false;
	}

	auto values = [](const FilterChoiceCounts& choices) {
		std::vector<tstring> result;
		result.reserve(choices.size());
		for(const auto& entry : choices) {
			result.push_back(entry.first);
		}
		return result;
	};
	const auto ips = values(ipChoices);
	const auto ports = values(portChoices);
	const auto peers = values(peerChoices);
	const auto commands = values(commandChoices);
	const auto categories = values(categoryChoices);
	const auto oldProtocol = selectedProtocol;
	const auto oldIp = selectedIp;
	const auto oldPort = selectedPort;
	const auto oldPeer = selectedPeer;
	const auto oldCommand = selectedCommand;
	const auto oldCategory = selectedCategory;
	if(!preserveMissing) {
		if(!isAllFilterValue(selectedIp) && ipChoices.find(selectedIp) == ipChoices.end()) {
			selectedIp = FILTER_ALL;
			if(ipFilterBox) {
				ipFilterBox->setSelected(0);
			}
		}
		if(!isAllFilterValue(selectedPort) &&
			portChoices.find(selectedPort) == portChoices.end())
		{
			selectedPort = FILTER_ALL;
			if(portFilterBox) {
				portFilterBox->setSelected(0);
			}
		}
		if(!isAllFilterValue(selectedPeer) &&
			peerChoices.find(selectedPeer) == peerChoices.end())
		{
			selectedPeer = FILTER_ALL;
			if(peerFilterBox) {
				peerFilterBox->setSelected(0);
			}
		}
		if(!isAllFilterValue(selectedCommand) &&
			commandChoices.find(selectedCommand) == commandChoices.end())
		{
			selectedCommand = FILTER_ALL;
			if(commandFilterBox) {
				commandFilterBox->setSelected(0);
			}
		}
		if(!isAllFilterValue(selectedCategory) &&
			categoryChoices.find(selectedCategory) == categoryChoices.end())
		{
			selectedCategory = FILTER_ALL;
			if(categoryFilterBox) {
				categoryFilterBox->setSelected(0);
			}
		}
	}

	auto isDropped = [](ComboBoxPtr box) -> bool {
		return box && ::SendMessage(box->handle(), CB_GETDROPPEDSTATE, 0, 0) != FALSE;
	};

	bool deferred = false;
	if(!isDropped(ipFilterBox)) {
		refreshFilterCombo(ipFilterBox, ips, selectedIp, preserveMissing);
	} else {
		deferred = true;
	}
	if(!isDropped(portFilterBox)) {
		refreshFilterCombo(portFilterBox, ports, selectedPort, preserveMissing);
	} else {
		deferred = true;
	}
	if(!isDropped(peerFilterBox)) {
		refreshFilterCombo(peerFilterBox, peers, selectedPeer, preserveMissing);
	} else {
		deferred = true;
	}
	if(!isDropped(commandFilterBox)) {
		refreshFilterCombo(commandFilterBox, commands, selectedCommand, preserveMissing);
	} else {
		deferred = true;
	}
	if(!isDropped(categoryFilterBox)) {
		refreshFilterCombo(categoryFilterBox, categories, selectedCategory, preserveMissing);
	} else {
		deferred = true;
	}

	if(protocolFilterBox && protocolFilterBox->getSelected() >= 0) {
		const auto selected = protocolFilterBox->getSelected();
		selectedProtocol = selected > 0 ?
			protocolFilterBox->getValue(selected) : tstring(FILTER_ALL);
	}
	if(ipFilterBox && ipFilterBox->getSelected() >= 0) {
		const auto selected = ipFilterBox->getSelected();
		selectedIp = selected > 0 ? ipFilterBox->getValue(selected) : tstring(FILTER_ALL);
	}
	if(portFilterBox && portFilterBox->getSelected() >= 0) {
		const auto selected = portFilterBox->getSelected();
		selectedPort = selected > 0 ? portFilterBox->getValue(selected) : tstring(FILTER_ALL);
	}
	if(peerFilterBox && peerFilterBox->getSelected() >= 0) {
		const auto selected = peerFilterBox->getSelected();
		selectedPeer = selected > 0 ? peerFilterBox->getValue(selected) : tstring(FILTER_ALL);
	}
	if(commandFilterBox && commandFilterBox->getSelected() >= 0) {
		const auto selected = commandFilterBox->getSelected();
		selectedCommand = selected > 0 ?
			commandFilterBox->getValue(selected) : tstring(FILTER_ALL);
	}
	if(categoryFilterBox && categoryFilterBox->getSelected() >= 0) {
		const auto selected = categoryFilterBox->getSelected();
		selectedCategory = selected > 0 ?
			categoryFilterBox->getValue(selected) : tstring(FILTER_ALL);
	}
	filterChoicesDirty = deferred;
	const bool changed = oldProtocol != selectedProtocol || oldIp != selectedIp ||
		oldPort != selectedPort || oldPeer != selectedPeer ||
		oldCommand != selectedCommand || oldCategory != selectedCategory;
	if(changed && !preserveMissing) {
		Config::setConfig("FilterProtocol", encodeFilterSetting(selectedProtocol));
		Config::setConfig("FilterIp", encodeFilterSetting(selectedIp));
		Config::setConfig("FilterPort", encodeFilterSetting(selectedPort));
		Config::setConfig("FilterPeer", encodeFilterSetting(selectedPeer));
		Config::setConfig("FilterCommand", encodeFilterSetting(selectedCommand));
		Config::setConfig("FilterCategory", encodeFilterSetting(selectedCategory));
	}
	return changed;
}

void GUI::enforceHistoryLimits() {
	size_t removeCount = 0;
	size_t remainingBytes = historyBytes;
	while(removeCount < tableItems.size() &&
		(tableItems.size() - removeCount > HISTORY_ITEM_CAPACITY ||
			remainingBytes > HISTORY_BYTE_CAPACITY))
	{
		const auto& item = tableItems[removeCount];
		if(item) {
			removeFilterChoices(*item);
			remainingBytes -= std::min(remainingBytes, item->storageBytes);
		}
		++removeCount;
	}
	if(removeCount) {
		tableItems.erase(tableItems.begin(), tableItems.begin() + removeCount);
		historyBytes = remainingBytes;
		saturatingAdd(evictedMessages, static_cast<uint64_t>(removeCount));
	}
}

void GUI::compileRegex() {
	if(regexText.empty()) {
		regexValid = true;
		searchRegex = std::regex();
		return;
	}
	if(!isSafeRegexPattern(regexText)) {
		regexValid = false;
		return;
	}
	try {
		searchRegex = std::regex(Util::fromT(regexText),
			std::regex_constants::ECMAScript | std::regex_constants::optimize);
		regexValid = true;
	} catch(const std::regex_error&) {
		regexValid = false;
	}
}

void GUI::scheduleSearch(const tstring& value) {
	pendingFindText = value.substr(0, 512);
	searchPending = true;
	searchDue = std::chrono::steady_clock::now() + std::chrono::milliseconds(250);
}

void GUI::applyPendingSearch(bool force) {
	if(!searchPending ||
		(!force && std::chrono::steady_clock::now() < searchDue))
	{
		return;
	}
	searchPending = false;
	if(findText == pendingFindText) {
		return;
	}
	findText = pendingFindText;
	refreshVisibleItems();
}

void GUI::refreshVisibleItems() {
	compileRegex();

	rebuildVisibleItems();
	if(table) {
		syncTableItemCount(true);
	}
	updateStatus();
}

void GUI::rebuildVisibleItems() {
	visibleItems.clear();
	visibleItems.reserve(tableItems.size());
	for(const auto& ownedItem : tableItems) {
		auto item = ownedItem.get();
		if(item && matchFind(*item)) {
			visibleItems.push_back(item);
		}
	}
}

void GUI::syncTableItemCount(bool resetViewport) {
	if(!table) {
		return;
	}

	const auto count = static_cast<WPARAM>(visibleItems.size());
	const LPARAM flags = resetViewport ? 0 : (LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
	table->sendMessage(LVM_SETITEMCOUNT, count, flags);

	if(resetViewport) {
		// Virtual list views can retain a stale scroll origin after their item count
		// transitions through zero. Reset the viewport and force a complete repaint.
		table->sendMessage(WM_VSCROLL, MAKEWPARAM(SB_TOP, 0), 0);
		if(count > 0) {
			table->sendMessage(LVM_REDRAWITEMS, 0, static_cast<LPARAM>(count - 1));
		}
		::RedrawWindow(table->handle(), nullptr, nullptr,
			RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_UPDATENOW);
	}
}

void GUI::addThemeUpdate(std::function<void()> update) {
	update();
	themeUpdates.emplace_back(std::move(update));
}

void GUI::layoutRoot() {
	if(!window || !rootGrid) {
		return;
	}
	const auto size = window->getClientSize();
	const long titleBarHeight =
		customTitleBar ? customTitleBar->height() : 0;
	const long margin = rootGrid->scale(16);
	rootGrid->resize(dwt::Rectangle(margin, titleBarHeight + margin,
		std::max(0L, size.x - margin * 2),
		std::max(0L, size.y - titleBarHeight - margin * 2)));
}

void GUI::handleDpiChanged(unsigned oldDpi, unsigned newDpi) {
	if(!window || oldDpi == 0 || oldDpi == newDpi) {
		return;
	}
	auto life = lifetime;
	window->callAsync([this, life, oldDpi, newDpi] {
		if(!life->load() || !window) {
			return;
		}
		uiFont = ui::makeFont(newDpi, 9);
		titleFont = ui::makeFont(newDpi, 20, FW_SEMIBOLD);
		sectionFont = ui::makeFont(newDpi, 9, FW_SEMIBOLD);
		window->setFont(uiFont);
		setControlTreeFont(window, uiFont);
		if(table) {
			const auto widths = table->getColumnWidths();
			for(int column = 0;
				column < COLUMN_LAST && static_cast<size_t>(column) < widths.size();
				++column)
			{
				const auto width = widths[column];
				table->setColumnWidth(column,
					::MulDiv(width, static_cast<int>(newDpi),
						static_cast<int>(oldDpi)));
			}
			if(auto header = getTableHeader(table)) {
				header->setFont(sectionFont);
			}
		}
		applyTheme();
		layoutRoot();
	});
}

COLORREF GUI::getTableBackground() const {
	return table_colors::get(table_colors::Role::Background);
}

void GUI::applyTheme() {
	for(const auto& update : themeUpdates) {
		update();
	}
	if(customTitleBar) {
		customTitleBar->refresh();
	}

	if(themeButton) {
		themeButton->setText(ui::isDarkMode() ? _T("Light mode") : _T("Dark mode"));
		themeButton->setAccessibleName(
			ui::isDarkMode() ? _T("Switch to light mode") : _T("Switch to dark mode"));
	}

	if(table) {
		const auto background = getTableBackground();
		table->setColor(table_colors::get(table_colors::Role::Text), background);
	}

	updateStatus();
	if(window) {
		::RedrawWindow(window->handle(), nullptr, nullptr,
			RDW_INVALIDATE | RDW_ERASE | RDW_FRAME | RDW_ALLCHILDREN | RDW_UPDATENOW);
	}
}

void GUI::toggleTheme() {
	const bool dark = !ui::isDarkMode();
	ui::setDarkMode(dark);
	Config::setConfig("DarkMode", dark);
	applyTheme();
}

void GUI::updateStatus() {
	if(itemCountLabel) {
		tstring text = Util::toT(std::to_string(visibleItems.size())) + _T(" shown  \u00b7  ") +
			Util::toT(std::to_string(tableItems.size())) + _T(" captured");
		if(evictedMessages) {
			text += _T("  \u00b7  ") + Util::toT(std::to_string(evictedMessages)) +
				_T(" evicted");
		}
		if(droppedMessages) {
			text += _T("  \u00b7  ") + Util::toT(std::to_string(droppedMessages)) +
				_T(" dropped (") +
				Util::toT(std::to_string(droppedBytes / 1024)) + _T(" KiB)");
		}
		itemCountLabel->setText(text);
	}

	if(filterStatusLabel) {
		const bool filtered = !isAllFilterValue(selectedProtocol) ||
			!isAllFilterValue(selectedIp) || !isAllFilterValue(selectedPort) ||
			!isAllFilterValue(selectedPeer) || !isAllFilterValue(selectedCommand) ||
			!isAllFilterValue(selectedCategory) || !findText.empty() ||
			!regexText.empty();
		if(!logError.empty()) {
			filterStatusLabel->setText(logError);
			filterStatusLabel->setColor(ui::palette().danger, ui::palette().window);
		} else if(!regexValid) {
			filterStatusLabel->setText(
				_T("Invalid or potentially expensive regular expression"));
			filterStatusLabel->setColor(ui::palette().danger, ui::palette().window);
		} else if(droppedMessages) {
			filterStatusLabel->setText(_T("Capture queue saturated"));
			filterStatusLabel->setColor(ui::palette().danger, ui::palette().window);
		} else {
			filterStatusLabel->setText(filtered ? _T("Filtered view") : _T("All traffic"));
			filterStatusLabel->setColor(
				filtered ? ui::palette().accent : ui::palette().muted,
				ui::palette().window);
		}
	}
}

void GUI::redrawTable() {
	if(table) {
		table->Control::redraw(true);
	}
}

void GUI::refreshTableColors() {
	if(table) {
		const auto background = table_colors::get(table_colors::Role::Background);
		table->setColor(table_colors::get(table_colors::Role::Text), background);
		if(auto header = getTableHeader(table)) {
			header->redraw(true);
		}
		redrawTable();
	}
	if(inspectorBox) {
		refreshInspectorPalette();
	}
}

void GUI::initSettings() {
	if(Config::getBoolConfig("FirstRun")) {
		Config::setConfig("FirstRun", false);
		//Offload these settings from Plugin
		Config::setConfig("DarkMode", false);
		Config::setConfig("TimeStampFormat", DEFAULT_TIMESTAMP_FORMAT);
		Config::setConfig("AutoScroll", scroll);
		Config::setConfig("KeepOnTop", keepOnTop);
	}
	table_colors::initialize();
	loadCaptureQueueCapacity();

	Config::setConfig("Dialog", true);
	// Remove legacy filter settings that are no longer used after live-filter refactor.
	// Removed in 1.3 and on
	Config::removeConfig("ProtocolFilter");
	Config::removeConfig("ShowHubMessages");
	Config::removeConfig("ShowUserMessages");
	const auto savedTimestampFormat = Config::getConfig("TimeStampFormat");
	const auto timestampFormat = normalizeTimestampFormat(savedTimestampFormat);
	if(timestampFormat != savedTimestampFormat) {
		Config::setConfig("TimeStampFormat", timestampFormat);
	}

	scroll = Config::getBoolConfig("AutoScroll");
	keepOnTop = Config::getBoolConfig("KeepOnTop");
	selectedProtocol = decodeFilterSetting("FilterProtocol");
	selectedIp = decodeFilterSetting("FilterIp");
	selectedPort = decodeFilterSetting("FilterPort");
	selectedPeer = decodeFilterSetting("FilterPeer");
	selectedCommand = decodeFilterSetting("FilterCommand");
	selectedCategory = decodeFilterSetting("FilterCategory");
	if(selectedProtocol.empty()) {
		selectedProtocol = FILTER_ALL;
	}
	if(selectedIp.empty()) {
		selectedIp = FILTER_ALL;
	}
	if(selectedPort.empty()) {
		selectedPort = FILTER_ALL;
	}
	if(selectedPeer.empty()) {
		selectedPeer = FILTER_ALL;
	}
	if(selectedCommand.empty()) {
		selectedCommand = FILTER_ALL;
	}
	if(selectedCategory.empty()) {
		selectedCategory = FILTER_ALL;
	}
	regexText = Util::toT(Config::getConfig("RegEx"));
	if(regexText.size() > MAX_REGEX_CHARS) {
		regexText.resize(MAX_REGEX_CHARS);
		Config::setConfig("RegEx", Util::fromT(regexText));
	}
	compileRegex();
	log = Config::getConfig("Log");
}

void GUI::saveState() {
	Config::setConfig("AutoScroll", scroll);
	Config::setConfig("KeepOnTop", keepOnTop);
	Config::setConfig("DarkMode", ui::isDarkMode());
	Config::setConfig("FilterProtocol", encodeFilterSetting(selectedProtocol));
	Config::setConfig("FilterIp", encodeFilterSetting(selectedIp));
	Config::setConfig("FilterPort", encodeFilterSetting(selectedPort));
	Config::setConfig("FilterPeer", encodeFilterSetting(selectedPeer));
	Config::setConfig("FilterCommand", encodeFilterSetting(selectedCommand));
	Config::setConfig("FilterCategory", encodeFilterSetting(selectedCategory));
	Config::setConfig("RegEx", Util::fromT(regexText));
}
