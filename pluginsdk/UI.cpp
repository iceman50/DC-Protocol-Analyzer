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

/* Helpers around the DCUI interface. */

#include "UI.h"

#include "Core.h"

namespace dcapi {

namespace {

constexpr size_t MAX_COMMAND_NAME_LENGTH = 1024;
thread_local size_t commandCallbackDepth = 0;

bool copyCommandName(const char* value, string& result) {
	result.clear();
	if(!value) {
		return false;
	}
	size_t length = 0;
	while(length < MAX_COMMAND_NAME_LENGTH && value[length] != '\0') {
		++length;
	}
	if(length == 0 || length == MAX_COMMAND_NAME_LENGTH) {
		return false;
	}
	result.assign(value, length);
	return true;
}

} // unnamed namespace

struct UI::CommandEntry {
	CommandEntry(string commandName, Command commandCallback,
		string commandIcon) :
		name(std::move(commandName)),
		command(std::move(commandCallback)),
		icon(std::move(commandIcon)),
		active(0),
		enabled(true)
	{
	}

	string name;
	Command command;
	string icon;
	size_t active;
	bool enabled;
};

DCUIPtr UI::ui;
string UI::guid;
unordered_map<string, std::shared_ptr<UI::CommandEntry>> UI::commands;
std::mutex UI::commandsMutex;
std::condition_variable UI::commandsChanged;
size_t UI::registrationsInProgress = 0;
size_t UI::removalsInProgress = 0;
size_t UI::activeCallbacks = 0;
bool UI::stopping = true;
bool UI::clearing = false;

bool UI::init(string pluginGuid) {
	if(inCallback()) {
		return false;
	}
	auto core = Core::handle();
	if(!core || !core->query_interface || pluginGuid.empty()) {
		return false;
	}
	init(reinterpret_cast<DCUIPtr>(
		core->query_interface(DCINTF_DCPP_UI, DCINTF_DCPP_UI_VER)),
		std::move(pluginGuid));
	return ui && ui->add_command && ui->remove_command;
}

void UI::init(DCUIPtr coreUI, string pluginGuid) {
	if(inCallback()) {
		return;
	}
	clearCommands();
	std::lock_guard<std::mutex> lock(commandsMutex);
	ui = coreUI;
	guid = std::move(pluginGuid);
	stopping = coreUI == nullptr || guid.empty();
}

void UI::reset() noexcept {
	if(inCallback()) {
		return;
	}
	clearCommands();
	DCUIPtr old = nullptr;
	{
		try {
			std::lock_guard<std::mutex> lock(commandsMutex);
			old = ui;
			ui = nullptr;
			guid.clear();
			stopping = true;
		} catch(...) {
			return;
		}
	}
	Core::releaseInterface(reinterpret_cast<DCInterfacePtr>(old));
}

DCUIPtr UI::handle() {
	std::lock_guard<std::mutex> lock(commandsMutex);
	return ui;
}

bool UI::addCommand(string name, Command command, string icon) {
	if(name.empty() || name.size() >= MAX_COMMAND_NAME_LENGTH ||
		name.find('\0') != string::npos || !command)
	{
		return false;
	}

	try {
		auto entry = std::make_shared<CommandEntry>(
			name, std::move(command), std::move(icon));
		DCUIPtr api = nullptr;
		string pluginGuid;
		{
			std::unique_lock<std::mutex> lock(commandsMutex);
			if(stopping || !ui || !ui->add_command || commands.find(name) != commands.end()) {
				return false;
			}
			pluginGuid = guid;
			auto inserted = commands.emplace(name, entry);
			if(!inserted.second) {
				return false;
			}
			++registrationsInProgress;
			api = ui;
		}

		bool registered = true;
		try {
			// DC++ retains this pointer in its menu callback. CommandEntry is
			// shared until the host callback is removed and all calls drain.
			api->add_command(pluginGuid.c_str(), entry->name.c_str(),
				commandCallback, entry->icon.c_str());
		} catch(...) {
			registered = false;
		}

		std::lock_guard<std::mutex> lock(commandsMutex);
		--registrationsInProgress;
		commandsChanged.notify_all();
		if(!registered) {
			entry->enabled = false;
			auto current = commands.find(name);
			if(current != commands.end() && current->second == entry) {
				commands.erase(current);
			}
			return false;
		}

		// clearCommands() may have begun while the host registration ran.
		return !stopping;
	} catch(...) {
		return false;
	}
}

bool UI::removeCommand(const string& name) noexcept {
	if(name.empty() || inCallback()) {
		return false;
	}

	try {
		std::unique_lock<std::mutex> lock(commandsMutex);
		if(stopping) {
			return false;
		}
		commandsChanged.wait(lock, [] {
			return registrationsInProgress == 0 || stopping;
		});
		if(stopping) {
			return false;
		}
		auto i = commands.find(name);
		if(i == commands.end() || !i->second->enabled) {
			return false;
		}

		const auto entry = i->second;
		entry->enabled = false;
		auto api = ui;
		const auto pluginGuid = guid;
		++removalsInProgress;
		lock.unlock();
		if(api && api->remove_command) {
			try {
				api->remove_command(pluginGuid.c_str(), name.c_str());
			} catch(...) {
				// Keep the local callback disabled on host teardown failure.
			}
		}
		lock.lock();
		commandsChanged.wait(lock, [&entry] { return entry->active == 0; });
		auto current = commands.find(name);
		if(current != commands.end() && current->second == entry) {
			commands.erase(current);
		}
		--removalsInProgress;
		commandsChanged.notify_all();
		return true;
	} catch(...) {
		return false;
	}
}

bool UI::inCallback() noexcept {
	return commandCallbackDepth != 0;
}

void UI::clearCommands() noexcept {
	if(inCallback()) {
		// Synchronous teardown cannot wait for the command that requested it.
		return;
	}

	bool ownsClear = false;
	try {
		std::unique_lock<std::mutex> lock(commandsMutex);
		if(clearing) {
			commandsChanged.wait(lock, [] { return !clearing; });
			return;
		}
		clearing = true;
		ownsClear = true;
		stopping = true;
		commandsChanged.wait(lock, [] {
			return registrationsInProgress == 0 && removalsInProgress == 0;
		});

		for(auto& command : commands) {
			command.second->enabled = false;
		}

		for(auto i = commands.begin(); i != commands.end(); ++i) {
			const char* name = i->first.c_str();
			auto api = ui;
			const char* pluginGuid = guid.c_str();
			lock.unlock();
			if(api && api->remove_command) {
				try {
					api->remove_command(pluginGuid, name);
				} catch(...) {
					// The registry remains disabled even if host teardown fails.
				}
			}
			lock.lock();
		}

		commandsChanged.wait(lock, [] { return activeCallbacks == 0; });
		commands.clear();
		clearing = false;
		commandsChanged.notify_all();
	} catch(...) {
		// Teardown must never throw through a plugin or DLL boundary.
		if(ownsClear) {
			try {
				std::lock_guard<std::mutex> lock(commandsMutex);
				clearing = false;
				commandsChanged.notify_all();
			} catch(...) {
			}
		}
	}
}

void DCAPI UI::commandCallback(const char* name) {
	try {
		string commandName;
		if(!copyCommandName(name, commandName)) {
			return;
		}
		std::shared_ptr<CommandEntry> entry;
		{
			std::lock_guard<std::mutex> lock(commandsMutex);
			if(stopping) {
				return;
			}
			auto i = commands.find(commandName);
			if(i == commands.end() || !i->second->enabled || !i->second->command) {
				return;
			}
			entry = i->second;
			++entry->active;
			++activeCallbacks;
		}

		++commandCallbackDepth;
		try {
			entry->command();
		} catch(...) {
			// Never unwind through the host command callback ABI.
		}
		--commandCallbackDepth;

		{
			std::lock_guard<std::mutex> lock(commandsMutex);
			--entry->active;
			--activeCallbacks;
			commandsChanged.notify_all();
		}
	} catch(...) {
		// Never unwind through the host command callback ABI.
	}
}

} // namespace dcapi
