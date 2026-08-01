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

/* Helpers around the DCDataAccess interface. */

#include "DataAccess.h"

#include "Core.h"

namespace dcapi {

DCDataAccessPtr DataAccess::dataAccessor;

bool DataAccess::init() {
	auto core = Core::handle();
	if(!core || !core->query_interface) {
		return false;
	}
	init(reinterpret_cast<DCDataAccessPtr>(
		core->query_interface(DCINTF_DCPP_DATAACCESSOR, DCINTF_DCPP_DATAACCESSOR_VER)));
	return dataAccessor && dataAccessor->get_http_resource;
}
void DataAccess::init(DCDataAccessPtr coreDataAccessor) { dataAccessor = coreDataAccessor; }
void DataAccess::reset() noexcept {
	auto old = dataAccessor;
	dataAccessor = nullptr;
	Core::releaseInterface(reinterpret_cast<DCInterfacePtr>(old));
}
DCDataAccessPtr DataAccess::handle() { return dataAccessor; }

} // namespace dcapi
