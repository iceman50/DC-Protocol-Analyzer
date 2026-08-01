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

/* Helpers around the DCHooks interface. */

#ifndef PLUGINSDK_HOOKS_H
#define PLUGINSDK_HOOKS_H

#include <condition_variable>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <utility>

#include <pluginsdk/PluginDefs.h>

namespace dcapi {

using std::function;
using std::map;
using std::string;
using std::pair;

class Hooks
{
public:
	static bool init();
	static void init(DCHooksPtr coreHooks);
	static void reset() noexcept;
	static DCHooksPtr handle();

	/* The following functions register events. See the Hooks section of PluginDefs.h to see a
	description of each.
	Callbacks return a bool to indicate whether they want to prevent the plugin host from doing any
	further processing related to the event.
	Callbacks are also given a "bool& bBreak" argument to indicate whether they want to prevent
	other plugins from catching the event.
	Remember to remove hooks the plugin has added by calling Hooks::clear() before destroying the
	plugin. */

	struct Chat {
		static bool onIncomingChat(function<bool (HubDataPtr, char*, bool&)> f);
		static bool onOutgoingChat(function<bool (HubDataPtr, char*, bool&)> f);
		static bool onIncomingPM(function<bool (UserDataPtr, char*, bool&)> f);
		static bool onOutgoingPM(function<bool (UserDataPtr, char*, bool&)> f);
	};

	struct Timer {
		static bool onSecond(function<bool (uint64_t, bool&)> f);
		static bool onMinute(function<bool (uint64_t, bool&)> f);
	};

	struct Hubs {
		static bool onOnline(function<bool (HubDataPtr, bool&)> f);
		static bool onOffline(function<bool (HubDataPtr, bool&)> f);
	};

	struct Users {
		static bool onOnline(function<bool (UserDataPtr, bool&)> f);
		static bool onOffline(function<bool (UserDataPtr, bool&)> f);
	};

	struct Network {
		static bool onHubDataIn(function<bool (HubDataPtr, char*, bool&)> f);
		static bool onHubDataOut(function<bool (HubDataPtr, char*, bool&)> f);
		static bool onClientDataIn(function<bool (ConnectionDataPtr, char*, bool&)> f);
		static bool onClientDataOut(function<bool (ConnectionDataPtr, char*, bool&)> f);
		static bool onUDPDataIn(function<bool (UDPDataPtr, char*, bool&)> f);
		static bool onUDPDataOut(function<bool (UDPDataPtr, char*, bool&)> f);
	};

	struct Queue {
		static bool onAdded(function<bool (QueueDataPtr, bool&)> f);
		static bool onMoved(function<bool (QueueDataPtr, bool&)> f);
		static bool onRemoved(function<bool (QueueDataPtr, bool&)> f);
		static bool onFinished(function<bool (QueueDataPtr, bool&)> f);
	};

	struct UI {
		static bool onCreated(function<bool (dcptr_t, bool&)> f);
		static bool onChatTags(function<bool (UserDataPtr, TagDataPtr, bool&)> f);
		static bool onChatDisplay(function<bool (UserDataPtr, StringDataPtr, bool&)> f);
		static bool onChatCommand(function<bool (HubDataPtr, CommandDataPtr, bool&)> f);
		static bool onChatCommandPM(function<bool (UserDataPtr, CommandDataPtr, bool&)> f);
	};

	struct DataAccessor {
		static bool onHTTPResourceNotification(function<bool(char*, bool&)> f);
		static bool onHTTPResourceNotificationFailed(function<bool(char*, bool&)> f);
		static bool onHTTPResourceStream(function<bool(char*, DataArrayPtr, bool&)> f);
	};

	static bool empty();
	static bool inCallback() noexcept;
	static void clear() noexcept;
	static bool remove(const char* id) noexcept;

private:
	typedef function<bool (dcptr_t, dcptr_t, bool&)> Callback;
	struct EventEntry;

	static bool addEvent(const char* id, Callback f) noexcept;
	static Bool DCAPI eventCallback(dcptr_t pObject, dcptr_t pData, dcptr_t pCommon, Bool* bBreak);

	static DCHooksPtr hooks;
	static map<string, std::shared_ptr<EventEntry>> events;
	static std::unordered_map<EventEntry*, std::shared_ptr<EventEntry>> eventTokens;
	static std::mutex eventsMutex;
	static std::condition_variable eventsChanged;
	static size_t bindingsInProgress;
	static size_t removalsInProgress;
	static size_t activeCallbacks;
	static bool stopping;
	static bool clearing;
};

} // namespace dcapi

#endif
