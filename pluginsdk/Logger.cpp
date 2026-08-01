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

/* Helpers around the DCLog interface. */

#include "Logger.h"

#include "Core.h"

namespace dcapi {

DCLogPtr Logger::logger;

bool Logger::init() {
	auto core = Core::handle();
	if(!core || !core->query_interface) {
		return false;
	}
	init(reinterpret_cast<DCLogPtr>(
		core->query_interface(DCINTF_LOGGING, DCINTF_LOGGING_VER)));
	return logger && logger->log;
}
void Logger::init(DCLogPtr coreLogger) { logger = coreLogger; }
void Logger::reset() noexcept {
	auto old = logger;
	logger = nullptr;
	Core::releaseInterface(reinterpret_cast<DCInterfacePtr>(old));
}
DCLogPtr Logger::handle() { return logger; }

bool Logger::log(const string& message) noexcept {
	if(!logger || !logger->log) {
		return false;
	}
	try {
		logger->log(message.c_str());
		return true;
	} catch(...) {
		return false;
	}
}

} // namespace dcapi
