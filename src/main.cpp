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

#include "stdafx.h"
#include "Plugin.h"
#include "version.h"

extern "C" {

// Plugin loader
DCEXP DCMAIN DCAPI pluginInit(MetaDataPtr info) {
	if(!info) {
		return nullptr;
	}

	try {
		info->name = PLUGIN_NAME;
		info->author = PLUGIN_AUTHOR;
		info->description = PLUGIN_DESC;
		info->web = PLUGIN_WEB;
		info->guid = PLUGIN_GUID;
		info->dependencies = nullptr;
		info->numDependencies = 0;
		info->apiVersion = DCAPI_CORE_VER;
		info->version = PLUGIN_VERSION;
		return &Plugin::main;
	} catch(...) {
		// Never unwind through the host plugin loader ABI.
		return nullptr;
	}
}

#ifdef _WIN32
BOOL APIENTRY DllMain(HINSTANCE /*hinstDLL*/, DWORD /*fdwReason*/, LPVOID /*lpvReserved*/) {
	return TRUE;
}
#endif

}
