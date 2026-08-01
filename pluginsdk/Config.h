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

/* Helpers around the DCConfig interface. */

#ifndef PLUGINSDK_CONFIG_H
#define PLUGINSDK_CONFIG_H

#include <string>
#include <type_traits>

#include <pluginsdk/PluginDefs.h>

namespace dcapi {

using std::string;

class Config
{
public:
	static bool init(string pluginGuid);
	static void init(DCConfigPtr coreConfig, string pluginGuid);
	static void reset() noexcept;
	static DCConfigPtr handle();

	static void setConfig(const char* name, const char* value);
	static void setConfig(const char* name, const string& value);
	static void setConfig(const char* name, bool value);
	static void setConfig(const char* name, int32_t value);
	static void setConfig(const char* name, int64_t value);
	static void removeConfig(const char* name);

	static string getConfig(const char *name);
	static bool getBoolConfig(const char* name);
	static int32_t getIntConfig(const char* name);
	static int64_t getInt64Config(const char* name);

	static ConfigValuePtr getCoreConfig(const char* name);
	static void freeCoreConfig(ConfigValuePtr value) noexcept;

	static string getPath(PathType type);
	static string getInstallPath();

private:
	template<typename ConfigT, typename ValueT> static void setConfig(const char* name, ConfigType type, ValueT value);
	template<typename ConfigT, typename RetT> static RetT getConfig(const char* name, ConfigType type);
	static void releaseValue(DCConfigPtr owner, ConfigValuePtr value) noexcept;

	static DCConfigPtr config;

	static string guid;
};

template<typename ConfigT, typename ValueT> void Config::setConfig(const char* name, ConfigType type, ValueT value) {
	auto owner = config;
	if(!owner || !owner->set_cfg || !name || !*name || guid.empty()) {
		return;
	}
	ConfigT val = { type, value };
	try {
		owner->set_cfg(guid.c_str(), name, reinterpret_cast<ConfigValuePtr>(&val));
	} catch(...) {
	}
}

template<typename ConfigT, typename RetT> RetT Config::getConfig(const char* name, ConfigType type) {
	auto owner = config;
	if(!owner || !owner->get_cfg || !owner->release ||
		!name || !*name || guid.empty())
	{
		return RetT {};
	}
	ConfigValuePtr cfg = nullptr;
	try {
		cfg = owner->get_cfg(guid.c_str(), name, type);
	} catch(...) {
		return RetT {};
	}
	if(!cfg) {
		return RetT {};
	}

	try {
		RetT ret {};
		if(cfg->type == type) {
			const auto value = reinterpret_cast<ConfigT>(cfg)->value;
			if constexpr(std::is_pointer_v<std::decay_t<decltype(value)>>) {
				if(value) {
					ret = RetT(value);
				}
			} else {
				ret = static_cast<RetT>(value);
			}
		}
		releaseValue(owner, cfg);
		return ret;
	} catch(...) {
		releaseValue(owner, cfg);
		return RetT {};
	}
}

} // namespace dcapi

#endif
