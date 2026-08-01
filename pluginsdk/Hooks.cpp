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

#include "Hooks.h"

#include "Core.h"

namespace dcapi {

using std::move;

namespace {

constexpr size_t MAX_EVENT_ID_LENGTH = 1024;
thread_local size_t hookCallbackDepth = 0;

bool copyEventId(const char* value, string& result) {
	result.clear();
	if(!value) {
		return false;
	}
	size_t length = 0;
	while(length < MAX_EVENT_ID_LENGTH && value[length] != '\0') {
		++length;
	}
	if(length == 0 || length == MAX_EVENT_ID_LENGTH) {
		return false;
	}
	result.assign(value, length);
	return true;
}

} // unnamed namespace

struct Hooks::EventEntry {
	EventEntry(string eventId, Callback eventCallback) :
		id(move(eventId)),
		subscription(nullptr),
		callback(move(eventCallback)),
		active(0),
		enabled(true)
	{
	}

	string id;
	subsHandle subscription;
	Callback callback;
	size_t active;
	bool enabled;
};

DCHooksPtr Hooks::hooks;
map<string, std::shared_ptr<Hooks::EventEntry>> Hooks::events;
std::unordered_map<Hooks::EventEntry*, std::shared_ptr<Hooks::EventEntry>> Hooks::eventTokens;
std::mutex Hooks::eventsMutex;
std::condition_variable Hooks::eventsChanged;
size_t Hooks::bindingsInProgress = 0;
size_t Hooks::removalsInProgress = 0;
size_t Hooks::activeCallbacks = 0;
bool Hooks::stopping = true;
bool Hooks::clearing = false;

bool Hooks::init() {
	if(inCallback()) {
		return false;
	}
	auto core = Core::handle();
	if(!core || !core->query_interface) {
		return false;
	}
	init(reinterpret_cast<DCHooksPtr>(
		core->query_interface(DCINTF_HOOKS, DCINTF_HOOKS_VER)));
	return hooks && hooks->bind_hook && hooks->release_hook;
}

void Hooks::init(DCHooksPtr coreHooks) {
	if(inCallback()) {
		return;
	}
	clear();
	std::lock_guard<std::mutex> lock(eventsMutex);
	hooks = coreHooks;
	stopping = coreHooks == nullptr;
}

void Hooks::reset() noexcept {
	if(inCallback()) {
		return;
	}
	clear();
	DCHooksPtr old = nullptr;
	{
		try {
			std::lock_guard<std::mutex> lock(eventsMutex);
			old = hooks;
			hooks = nullptr;
			stopping = true;
		} catch(...) {
			return;
		}
	}
	Core::releaseInterface(reinterpret_cast<DCInterfacePtr>(old));
}

DCHooksPtr Hooks::handle() {
	std::lock_guard<std::mutex> lock(eventsMutex);
	return hooks;
}

bool Hooks::Chat::onIncomingChat(function<bool (HubDataPtr, char*, bool&)> f) {
	return addEvent(HOOK_CHAT_IN, [f = move(f)](dcptr_t pObject, dcptr_t pData, bool& bBreak) {
		return f(reinterpret_cast<HubDataPtr>(pObject), reinterpret_cast<char*>(pData), bBreak);
	});
}

bool Hooks::Chat::onOutgoingChat(function<bool (HubDataPtr, char*, bool&)> f) {
	return addEvent(HOOK_CHAT_OUT, [f = move(f)](dcptr_t pObject, dcptr_t pData, bool& bBreak) {
		return f(reinterpret_cast<HubDataPtr>(pObject), reinterpret_cast<char*>(pData), bBreak);
	});
}

bool Hooks::Chat::onIncomingPM(function<bool (UserDataPtr, char*, bool&)> f) {
	return addEvent(HOOK_CHAT_PM_IN, [f = move(f)](dcptr_t pObject, dcptr_t pData, bool& bBreak) {
		return f(reinterpret_cast<UserDataPtr>(pObject), reinterpret_cast<char*>(pData), bBreak);
	});
}

bool Hooks::Chat::onOutgoingPM(function<bool (UserDataPtr, char*, bool&)> f) {
	return addEvent(HOOK_CHAT_PM_OUT, [f = move(f)](dcptr_t pObject, dcptr_t pData, bool& bBreak) {
		return f(reinterpret_cast<UserDataPtr>(pObject), reinterpret_cast<char*>(pData), bBreak);
	});
}

bool Hooks::Timer::onSecond(function<bool (uint64_t, bool&)> f) {
	return addEvent(HOOK_TIMER_SECOND, [f = move(f)](dcptr_t, dcptr_t pData, bool& bBreak) {
		return pData ? f(*reinterpret_cast<uint64_t*>(pData), bBreak) : false;
	});
}

bool Hooks::Timer::onMinute(function<bool (uint64_t, bool&)> f) {
	return addEvent(HOOK_TIMER_MINUTE, [f = move(f)](dcptr_t, dcptr_t pData, bool& bBreak) {
		return pData ? f(*reinterpret_cast<uint64_t*>(pData), bBreak) : false;
	});
}

bool Hooks::Hubs::onOnline(function<bool (HubDataPtr, bool&)> f) {
	return addEvent(HOOK_HUB_ONLINE, [f = move(f)](dcptr_t pObject, dcptr_t, bool& bBreak) {
		return f(reinterpret_cast<HubDataPtr>(pObject), bBreak);
	});
}

bool Hooks::Hubs::onOffline(function<bool (HubDataPtr, bool&)> f) {
	return addEvent(HOOK_HUB_OFFLINE, [f = move(f)](dcptr_t pObject, dcptr_t, bool& bBreak) {
		return f(reinterpret_cast<HubDataPtr>(pObject), bBreak);
	});
}

bool Hooks::Users::onOnline(function<bool (UserDataPtr, bool&)> f) {
	return addEvent(HOOK_USER_ONLINE, [f = move(f)](dcptr_t pObject, dcptr_t, bool& bBreak) {
		return f(reinterpret_cast<UserDataPtr>(pObject), bBreak);
	});
}

bool Hooks::Users::onOffline(function<bool (UserDataPtr, bool&)> f) {
	return addEvent(HOOK_USER_OFFLINE, [f = move(f)](dcptr_t pObject, dcptr_t, bool& bBreak) {
		return f(reinterpret_cast<UserDataPtr>(pObject), bBreak);
	});
}

bool Hooks::Network::onHubDataIn(function<bool (HubDataPtr, char*, bool&)> f) {
	return addEvent(HOOK_NETWORK_HUB_IN, [f = move(f)](dcptr_t pObject, dcptr_t pData, bool& bBreak) {
		return f(reinterpret_cast<HubDataPtr>(pObject), reinterpret_cast<char*>(pData), bBreak);
	});
}

bool Hooks::Network::onHubDataOut(function<bool (HubDataPtr, char*, bool&)> f) {
	return addEvent(HOOK_NETWORK_HUB_OUT, [f = move(f)](dcptr_t pObject, dcptr_t pData, bool& bBreak) {
		return f(reinterpret_cast<HubDataPtr>(pObject), reinterpret_cast<char*>(pData), bBreak);
	});
}

bool Hooks::Network::onClientDataIn(function<bool (ConnectionDataPtr, char*, bool&)> f) {
	return addEvent(HOOK_NETWORK_CONN_IN, [f = move(f)](dcptr_t pObject, dcptr_t pData, bool& bBreak) {
		return f(reinterpret_cast<ConnectionDataPtr>(pObject), reinterpret_cast<char*>(pData), bBreak);
	});
}

bool Hooks::Network::onClientDataOut(function<bool (ConnectionDataPtr, char*, bool&)> f) {
	return addEvent(HOOK_NETWORK_CONN_OUT, [f = move(f)](dcptr_t pObject, dcptr_t pData, bool& bBreak) {
		return f(reinterpret_cast<ConnectionDataPtr>(pObject), reinterpret_cast<char*>(pData), bBreak);
	});
}

bool Hooks::Network::onUDPDataIn(function<bool (UDPDataPtr, char*, bool&)> f) {
	return addEvent(HOOK_NETWORK_UDP_IN, [f = move(f)](dcptr_t pObject, dcptr_t pData, bool& bBreak) {
		return f(reinterpret_cast<UDPDataPtr>(pObject), reinterpret_cast<char*>(pData), bBreak);
	});
}

bool Hooks::Network::onUDPDataOut(function<bool (UDPDataPtr, char*, bool&)> f) {
	return addEvent(HOOK_NETWORK_UDP_OUT, [f = move(f)](dcptr_t pObject, dcptr_t pData, bool& bBreak) {
		return f(reinterpret_cast<UDPDataPtr>(pObject), reinterpret_cast<char*>(pData), bBreak);
	});
}

bool Hooks::Queue::onAdded(function<bool (QueueDataPtr, bool&)> f) {
	return addEvent(HOOK_QUEUE_ADDED, [f = move(f)](dcptr_t pObject, dcptr_t, bool& bBreak) {
		return f(reinterpret_cast<QueueDataPtr>(pObject), bBreak);
	});
}

bool Hooks::Queue::onMoved(function<bool (QueueDataPtr, bool&)> f) {
	return addEvent(HOOK_QUEUE_MOVED, [f = move(f)](dcptr_t pObject, dcptr_t, bool& bBreak) {
		return f(reinterpret_cast<QueueDataPtr>(pObject), bBreak);
	});
}

bool Hooks::Queue::onRemoved(function<bool (QueueDataPtr, bool&)> f) {
	return addEvent(HOOK_QUEUE_REMOVED, [f = move(f)](dcptr_t pObject, dcptr_t, bool& bBreak) {
		return f(reinterpret_cast<QueueDataPtr>(pObject), bBreak);
	});
}

bool Hooks::Queue::onFinished(function<bool (QueueDataPtr, bool&)> f) {
	return addEvent(HOOK_QUEUE_FINISHED, [f = move(f)](dcptr_t pObject, dcptr_t, bool& bBreak) {
		return f(reinterpret_cast<QueueDataPtr>(pObject), bBreak);
	});
}

bool Hooks::UI::onCreated(function<bool (dcptr_t, bool&)> f) {
	return addEvent(HOOK_UI_CREATED, [f = move(f)](dcptr_t pObject, dcptr_t, bool& bBreak) {
		return f(pObject, bBreak);
	});
}

bool Hooks::UI::onChatTags(function<bool (UserDataPtr, TagDataPtr, bool&)> f) {
	return addEvent(HOOK_UI_CHAT_TAGS, [f = move(f)](dcptr_t pObject, dcptr_t pData, bool& bBreak) {
		return f(reinterpret_cast<UserDataPtr>(pObject), reinterpret_cast<TagDataPtr>(pData), bBreak);
	});
}

bool Hooks::UI::onChatDisplay(function<bool (UserDataPtr, StringDataPtr, bool&)> f) {
	return addEvent(HOOK_UI_CHAT_DISPLAY, [f = move(f)](dcptr_t pObject, dcptr_t pData, bool& bBreak) {
		return f(reinterpret_cast<UserDataPtr>(pObject), reinterpret_cast<StringDataPtr>(pData), bBreak);
	});
}

bool Hooks::UI::onChatCommand(function<bool (HubDataPtr, CommandDataPtr, bool&)> f) {
	return addEvent(HOOK_UI_CHAT_COMMAND, [f = move(f)](dcptr_t pObject, dcptr_t pData, bool& bBreak) {
		return f(reinterpret_cast<HubDataPtr>(pObject), reinterpret_cast<CommandDataPtr>(pData), bBreak);
	});
}

bool Hooks::UI::onChatCommandPM(function<bool (UserDataPtr, CommandDataPtr, bool&)> f) {
	return addEvent(HOOK_UI_CHAT_COMMAND_PM, [f = move(f)](dcptr_t pObject, dcptr_t pData, bool& bBreak) {
		return f(reinterpret_cast<UserDataPtr>(pObject), reinterpret_cast<CommandDataPtr>(pData), bBreak);
	});
}

bool Hooks::DataAccessor::onHTTPResourceNotification(function<bool(char*, bool&)> f) {
	return addEvent(HOOK_DATAACESSOR_HTTP_RESOURCE_NOTIFICATION,
		[f = move(f)](dcptr_t pResource, dcptr_t, bool& bBreak) {
			return f(reinterpret_cast<char*>(pResource), bBreak);
		});
}

bool Hooks::DataAccessor::onHTTPResourceNotificationFailed(function<bool(char*, bool&)> f) {
	return addEvent(HOOK_DATAACESSOR_HTTP_RESOURCE_NOTIFICATION_FAILED,
		[f = move(f)](dcptr_t pResource, dcptr_t, bool& bBreak) {
			return f(reinterpret_cast<char*>(pResource), bBreak);
		});
}

bool Hooks::DataAccessor::onHTTPResourceStream(function<bool(char*, DataArrayPtr, bool&)> f) {
	return addEvent(HOOK_DATAACESSOR_HTTP_RESOURCE_STREAM,
		[f = move(f)](dcptr_t pResource, dcptr_t pData, bool& bBreak) {
			return f(reinterpret_cast<char*>(pResource), reinterpret_cast<DataArrayPtr>(pData), bBreak);
		});
}

bool Hooks::empty() {
	std::lock_guard<std::mutex> lock(eventsMutex);
	return events.empty();
}

bool Hooks::inCallback() noexcept {
	return hookCallbackDepth != 0;
}

void Hooks::clear() noexcept {
	if(inCallback()) {
		// Synchronous teardown cannot wait for the callback that requested it.
		return;
	}

	bool ownsClear = false;
	try {
		std::unique_lock<std::mutex> lock(eventsMutex);
		if(clearing) {
			eventsChanged.wait(lock, [] { return !clearing; });
			return;
		}
		clearing = true;
		ownsClear = true;
		stopping = true;
		eventsChanged.wait(lock, [] {
			return bindingsInProgress == 0 && removalsInProgress == 0;
		});

		for(auto& event : events) {
			event.second->enabled = false;
		}

		for(auto i = events.begin(); i != events.end(); ++i) {
			const auto entry = i->second;
			const auto subscription = entry->subscription;
			auto api = hooks;
			lock.unlock();
			if(api && api->release_hook && subscription) {
				try {
					api->release_hook(subscription);
				} catch(...) {
					// The registry remains disabled even if the host rejects teardown.
				}
			}
			lock.lock();
			entry->subscription = nullptr;
		}

		eventsChanged.wait(lock, [] { return activeCallbacks == 0; });
		eventTokens.clear();
		events.clear();
		clearing = false;
		eventsChanged.notify_all();
	} catch(...) {
		// Teardown must never throw through a plugin or DLL boundary.
		if(ownsClear) {
			try {
				std::lock_guard<std::mutex> lock(eventsMutex);
				clearing = false;
				eventsChanged.notify_all();
			} catch(...) {
			}
		}
	}
}

bool Hooks::remove(const char* id) noexcept {
	if(inCallback()) {
		return false;
	}

	try {
		string eventId;
		if(!copyEventId(id, eventId)) {
			return false;
		}
		std::unique_lock<std::mutex> lock(eventsMutex);
		if(stopping) {
			return false;
		}
		eventsChanged.wait(lock, [] {
			return bindingsInProgress == 0 || stopping;
		});
		if(stopping) {
			return false;
		}
		auto i = events.find(eventId);
		if(i == events.end() || !i->second->enabled) {
			return false;
		}

		const auto entry = i->second;
		entry->enabled = false;
		const auto subscription = entry->subscription;
		entry->subscription = nullptr;
		auto api = hooks;
		++removalsInProgress;
		lock.unlock();
		if(api && api->release_hook && subscription) {
			try {
				api->release_hook(subscription);
			} catch(...) {
				// Keep the callback disabled even when host teardown reports failure.
			}
		}
		lock.lock();
		eventsChanged.wait(lock, [&entry] { return entry->active == 0; });
		eventTokens.erase(entry.get());
		auto current = events.find(eventId);
		if(current != events.end() && current->second == entry) {
			events.erase(current);
		}
		--removalsInProgress;
		eventsChanged.notify_all();
		return true;
	} catch(...) {
		return false;
	}
}

bool Hooks::addEvent(const char* id, Callback f) noexcept {
	if(!f) {
		return false;
	}

	try {
		string eventId;
		if(!copyEventId(id, eventId)) {
			return false;
		}
		auto entry = std::make_shared<EventEntry>(move(eventId), move(f));
		DCHooksPtr api = nullptr;
		{
			std::unique_lock<std::mutex> lock(eventsMutex);
			if(stopping || !hooks || !hooks->bind_hook || events.find(entry->id) != events.end()) {
				return false;
			}

			auto inserted = events.emplace(entry->id, entry);
			if(!inserted.second) {
				return false;
			}
			try {
				eventTokens.emplace(entry.get(), entry);
			} catch(...) {
				events.erase(inserted.first);
				throw;
			}
			++bindingsInProgress;
			api = hooks;
		}

		subsHandle subscription = nullptr;
		try {
			subscription = api->bind_hook(entry->id.c_str(), eventCallback,
				reinterpret_cast<dcptr_t>(entry.get()));
		} catch(...) {
			subscription = nullptr;
		}

		std::unique_lock<std::mutex> lock(eventsMutex);
		entry->subscription = subscription;
		--bindingsInProgress;
		eventsChanged.notify_all();
		if(!subscription) {
			entry->enabled = false;
			eventTokens.erase(entry.get());
			auto current = events.find(entry->id);
			if(current != events.end() && current->second == entry) {
				events.erase(current);
			}
			return false;
		}

		// clear() may have started while bind_hook was executing. It owns release.
		return !stopping;
	} catch(...) {
		return false;
	}
}

Bool DCAPI Hooks::eventCallback(
	dcptr_t pObject, dcptr_t pData, dcptr_t pCommon, Bool* bBreak)
{
	if(!pCommon || !bBreak) {
		return False;
	}

	try {
		std::shared_ptr<EventEntry> entry;
		{
			std::lock_guard<std::mutex> lock(eventsMutex);
			if(stopping) {
				return False;
			}
			auto i = eventTokens.find(reinterpret_cast<EventEntry*>(pCommon));
			if(i == eventTokens.end() || !i->second->enabled || !i->second->callback) {
				return False;
			}
			entry = i->second;
			++entry->active;
			++activeCallbacks;
		}

		bool breakValue = *bBreak == True;
		bool result = false;
		++hookCallbackDepth;
		try {
			result = entry->callback(pObject, pData, breakValue);
		} catch(...) {
			result = false;
		}
		--hookCallbackDepth;

		{
			std::lock_guard<std::mutex> lock(eventsMutex);
			--entry->active;
			--activeCallbacks;
			eventsChanged.notify_all();
		}
		*bBreak = breakValue ? True : False;
		return result ? True : False;
	} catch(...) {
		return False;
	}
}

} // namespace dcapi
