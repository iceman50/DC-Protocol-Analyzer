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

#include "Config.h"

#include "Core.h"

namespace dcapi {

DCConfigPtr Config::config;
string Config::guid;

bool Config::init(string pluginGuid) {
	auto core = Core::handle();
	if(!core || !core->query_interface || pluginGuid.empty()) {
		return false;
	}
	init(reinterpret_cast<DCConfigPtr>(
		core->query_interface(DCINTF_CONFIG, DCINTF_CONFIG_VER)),
		move(pluginGuid));
	return config && config->set_cfg && config->get_cfg && config->release &&
		config->get_path && config->get_install_path;
}
void Config::init(DCConfigPtr coreConfig, string pluginGuid) { config = coreConfig; guid = move(pluginGuid); }
void Config::reset() noexcept {
	auto old = config;
	config = nullptr;
	guid.clear();
	Core::releaseInterface(reinterpret_cast<DCInterfacePtr>(old));
}
DCConfigPtr Config::handle() { return config; }

void Config::setConfig(const char* name, const char* value) {
	setConfig<ConfigStr>(name, CFG_TYPE_STRING, value ? value : "");
}
void Config::setConfig(const char* name, const string& value) { setConfig(name, value.c_str()); }
void Config::setConfig(const char* name, bool value) { setConfig<ConfigBool>(name, CFG_TYPE_BOOL, value ? True : False); };
void Config::setConfig(const char* name, int32_t value) { setConfig<ConfigInt>(name, CFG_TYPE_INT, value); }
void Config::setConfig(const char* name, int64_t value) { setConfig<ConfigInt64>(name, CFG_TYPE_INT64, value); }
void Config::removeConfig(const char* name) {
	auto owner = config;
	if(!owner || !owner->set_cfg || !name || !*name || guid.empty()) {
		return;
	}
	ConfigValue val = { CFG_TYPE_REMOVE };
	try {
		owner->set_cfg(guid.c_str(), name, reinterpret_cast<ConfigValuePtr>(&val));
	} catch(...) {
	}
}

string Config::getConfig(const char* name) { return getConfig<ConfigStrPtr, string>(name, CFG_TYPE_STRING); }
bool Config::getBoolConfig(const char* name) { return getConfig<ConfigBoolPtr, bool>(name, CFG_TYPE_BOOL); }
int32_t Config::getIntConfig(const char* name) { return getConfig<ConfigIntPtr, int32_t>(name, CFG_TYPE_INT); }
int64_t Config::getInt64Config(const char* name) { return getConfig<ConfigInt64Ptr, int64_t>(name, CFG_TYPE_INT64); }

ConfigValuePtr Config::getCoreConfig(const char* name) {
	auto owner = config;
	if(!owner || !owner->get_cfg || !owner->release || !name || !*name) {
		return nullptr;
	}
	try {
		return owner->get_cfg("CoreSetup", name, CFG_TYPE_UNKNOWN);
	} catch(...) {
		return nullptr;
	}
}
void Config::freeCoreConfig(ConfigValuePtr value) noexcept {
	releaseValue(config, value);
}

void Config::releaseValue(DCConfigPtr owner, ConfigValuePtr value) noexcept {
	if(owner && owner->release && value) {
		try {
			owner->release(value);
		} catch(...) {
		}
	}
}

string Config::getPath(PathType type) {
	auto owner = config;
	if(!owner || !owner->get_path || !owner->release) {
		return string();
	}
	ConfigStrPtr cfg = nullptr;
	try {
		cfg = owner->get_path(type);
	} catch(...) {
		return string();
	}
	if(!cfg) {
		return string();
	}
	try {
		string ret;
		if(cfg->type == CFG_TYPE_STRING && cfg->value) {
			ret = cfg->value;
		}
		releaseValue(owner, reinterpret_cast<ConfigValuePtr>(cfg));
		return ret;
	} catch(...) {
		releaseValue(owner, reinterpret_cast<ConfigValuePtr>(cfg));
		return string();
	}
}

string Config::getInstallPath() {
	auto owner = config;
	if(!owner || !owner->get_install_path || !owner->release || guid.empty()) {
		return string();
	}
	ConfigStrPtr cfg = nullptr;
	try {
		cfg = owner->get_install_path(guid.c_str());
	} catch(...) {
		return string();
	}
	if(!cfg) {
		return string();
	}
	try {
		string ret;
		if(cfg->type == CFG_TYPE_STRING && cfg->value) {
			ret = cfg->value;
		}
		releaseValue(owner, reinterpret_cast<ConfigValuePtr>(cfg));
		return ret;
	} catch(...) {
		releaseValue(owner, reinterpret_cast<ConfigValuePtr>(cfg));
		return string();
	}
}

} // namespace dcapi
