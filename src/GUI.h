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

#ifndef PROTOCOL_ANALYZER_GUI_H
#define PROTOCOL_ANALYZER_GUI_H

//#include "ListFilter.h"

#include <dwt/Application.h>
#include <dwt/forward.h>

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <regex>
#include <unordered_set>
#include <vector>

using std::move;
using std::string;

constexpr ProtocolType PROTOCOL_UDP = static_cast<ProtocolType>(3);

class SettingsDlg;
namespace ui {
class CustomTitleBar;
}

// objects associated to each list item as LPARAMs.
struct Item {
	tstring timestamp;
	tstring index;
	tstring dir;
	tstring protocol;
	tstring command;
	tstring category;
	tstring ip;
	tstring port;
	tstring peer;
	tstring summary;
	tstring message;
	tstring details;
	tstring validation;
	bool sensitive = false;
	size_t storageBytes = 0;

	const tstring& safeMessage() const noexcept {
		return message;
	}
};

struct ColumnInfo {
	const char* name;
	const int size;
	const bool numerical;
};

enum {
	COLUMN_FIRST,
	COLUMN_TIMESTAMP = COLUMN_FIRST,
	COLUMN_COUNT,
	COLUMN_DIRECTION,
	COLUMN_PROTOCOL,
	COLUMN_COMMAND,
	COLUMN_CATEGORY,
	COLUMN_IP,
	COLUMN_PORT,
	COLUMN_PEER,
	COLUMN_SUMMARY,
	COLUMN_MESSAGE,

	COLUMN_LAST
};

class GUI
{
public:
	GUI();
	~GUI();

	void create();
	void write(bool sending, ProtocolType proto, string ip, decltype(ConnectionData().port) port, string peer, string message);
	void close();
	void loadCaptureQueueCapacity();
	void setCaptureQueueCapacity(size_t capacity);

	static constexpr size_t DEFAULT_CAPTURE_QUEUE_CAPACITY = 1024;
	static constexpr size_t MIN_CAPTURE_QUEUE_CAPACITY = 64;
	static constexpr size_t MAX_CAPTURE_QUEUE_CAPACITY = 65536;
	static size_t normalizeCaptureQueueCapacity(int64_t capacity) noexcept;
	
	static void redrawTable();
	static void refreshTableColors();

	void initSettings();
	void saveState();

	static std::atomic_bool unloading;

private:
	void timer();
	bool matchFind(const Item& item) const;
	bool matchesStructuredFilters(const Item& item) const;
	bool matchesSearch(const Item& item) const;
	bool isAllFilterValue(const tstring& value) const;
	bool rebuildFilterChoices(bool force = false, bool preserveMissing = true);
	void addFilterChoices(const Item& item);
	void removeFilterChoices(const Item& item);
	void enforceHistoryLimits();
	void compileRegex();
	void scheduleSearch(const tstring& value);
	void applyPendingSearch(bool force = false);
	void refreshVisibleItems();
	void rebuildVisibleItems();
	void syncTableItemCount(bool resetViewport);
	void updateStatus();
	void layoutRoot();
	void handleDpiChanged(unsigned oldDpi, unsigned newDpi);
	void addThemeUpdate(std::function<void()> update);
	void applyTheme();
	void toggleTheme();
	COLORREF getTableBackground() const;
	void copy();
	void clear();
	void remove();
	void openSettings();
	void updateInspector();
	bool showWindow();

	// store the messages to be displayed here; process them with a timer.
	struct Message {
		bool sending;
		string protocol;
		string ip;
		decltype(ConnectionData().port) port;
		string peer;
		string message;
		bool bloomPayload = false;
		bool bloomRequestCorrelated = false;
		uint64_t bloomAnnouncedBytes = 0;
		std::chrono::system_clock::time_point arrival;
		uint64_t generation;
		size_t storageBytes;
	};
	struct BloomRequest {
		bool sending;
		string protocol;
		string ip;
		decltype(ConnectionData().port) port;
		string peer;
		uint64_t bytes;
		uint32_t k;
		uint32_t h;
		std::chrono::steady_clock::time_point expires;
	};
	struct BloomPayload {
		bool sending;
		string protocol;
		string ip;
		decltype(ConnectionData().port) port;
		string peer;
		uint64_t bytes;
		bool requestCorrelated;
		std::chrono::steady_clock::time_point expires;
	};
	static constexpr size_t MESSAGE_QUEUE_BYTE_CAPACITY = 4 * 1024 * 1024;
	static constexpr size_t HISTORY_ITEM_CAPACITY = 20000;
	static constexpr size_t HISTORY_BYTE_CAPACITY = 64 * 1024 * 1024;
	static constexpr size_t MAX_MESSAGE_BYTES = 64 * 1024;
	static constexpr size_t MAX_PEER_BYTES = 4096;
	static constexpr size_t MAX_ADDRESS_BYTES = 512;
	static constexpr size_t MAX_COPY_CHARS = 4 * 1024 * 1024;
	std::deque<std::unique_ptr<Message>> messages;
	std::deque<BloomRequest> bloomRequests;
	std::deque<BloomPayload> bloomPayloads;
	size_t messageQueueCapacity;
	size_t messagesBytes;
	uint64_t captureGeneration;
	uint64_t pendingDroppedMessages;
	uint64_t pendingDroppedBytes;
	std::mutex messagesMutex;

	// Storage for all displayed items (virtual Table).
	std::vector<std::unique_ptr<Item>> tableItems;
	size_t historyBytes;
	// Live filtered view for the virtual Table.
	std::vector<Item*> visibleItems;

	struct CaseInsensitiveLess {
		bool operator()(const tstring& a, const tstring& b) const;
	};
	using FilterChoiceCounts = std::map<tstring, size_t, CaseInsensitiveLess>;
	FilterChoiceCounts ipChoices;
	FilterChoiceCounts portChoices;
	FilterChoiceCounts peerChoices;
	FilterChoiceCounts commandChoices;
	FilterChoiceCounts categoryChoices;
	bool filterChoicesDirty;

	uint64_t counter;
	uint64_t droppedMessages;
	uint64_t droppedBytes;
	uint64_t evictedMessages;
	bool scroll;
	std::atomic_bool shuttingDown;
	bool justCleared;
	tstring findText;
	tstring pendingFindText;
	bool searchPending;
	std::chrono::steady_clock::time_point searchDue;
	tstring selectedProtocol;
	tstring selectedIp;
	tstring selectedPort;
	tstring selectedPeer;
	tstring selectedCommand;
	tstring selectedCategory;
	tstring regexText;
	bool regexValid;
	std::regex searchRegex;
	bool keepOnTop;
	string log;
	tstring logError;
	dwt::ButtonPtr themeButton;
	std::unique_ptr<ui::CustomTitleBar> customTitleBar;
	dwt::GridPtr rootGrid;
	dwt::GridPtr actionsGrid;
	std::vector<std::function<void()>> themeUpdates;
	struct SettingsState {
		std::mutex mutex;
		std::shared_ptr<SettingsDlg> active;
		bool alive = true;
	};
	std::shared_ptr<SettingsState> settingsState;
	std::shared_ptr<std::atomic_bool> lifetime;

	LRESULT handleCustomDraw(NMLVCUSTOMDRAW& data);
	void openDoc();

};

#endif
