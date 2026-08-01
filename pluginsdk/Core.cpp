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

/* Helpers around the DCCore interface. */

#include "Core.h"

namespace dcapi {

DCCorePtr Core::core;
string Core::appName;

bool Core::init(DCCorePtr corePtr) {
	core = nullptr;
	appName.clear();
	if(!corePtr || !corePtr->query_interface || !corePtr->release_interface) {
		return false;
	}
	core = corePtr;

	try {
		if(core->host_name) {
			const auto name = core->host_name();
			if(name) {
				appName = name;
			}
		}
		return true;
	} catch(...) {
		core = nullptr;
		appName.clear();
		return false;
	}
}

void Core::reset() noexcept {
	core = nullptr;
	appName.clear();
}

DCCorePtr Core::handle() { return core; }

bool Core::releaseInterface(DCInterfacePtr interfacePtr) noexcept {
	if(!interfacePtr || !core || !core->release_interface) {
		return interfacePtr == nullptr;
	}

	try {
		return core->release_interface(reinterpret_cast<intfHandle>(interfacePtr)) == True;
	} catch(...) {
		return false;
	}
}

} // namespace dcapi
