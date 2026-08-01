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

#ifndef PLUGINSDK_UI_H
#define PLUGINSDK_UI_H

#include <condition_variable>
#include <functional>
#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>

#include <pluginsdk/PluginDefs.h>

namespace dcapi {

using std::function;
using std::pair;
using std::string;
using std::unordered_map;

class UI
{
public:
	static bool init(string pluginGuid);
	static void init(DCUIPtr coreUI, string pluginGuid);
	static void reset() noexcept;
	static DCUIPtr handle();

	typedef function<void ()> Command;
	static bool addCommand(string name, Command command, string icon);
	static bool removeCommand(const string& name) noexcept;
	static bool inCallback() noexcept;
	static void clearCommands() noexcept;

private:
	struct CommandEntry;
	static void DCAPI commandCallback(const char* name);

	static DCUIPtr ui;

	static string guid;

	// command name -> callback state
	static unordered_map<string, std::shared_ptr<CommandEntry>> commands;
	static std::mutex commandsMutex;
	static std::condition_variable commandsChanged;
	static size_t registrationsInProgress;
	static size_t removalsInProgress;
	static size_t activeCallbacks;
	static bool stopping;
	static bool clearing;
};

} // namespace dcapi

#endif
