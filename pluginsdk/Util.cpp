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

/* Helpers around the DCUtils interface. */

#include "Util.h"

#include "Core.h"

namespace dcapi {

namespace {

template<typename OutputString, typename InputString, typename Converter>
OutputString convertString(const InputString& input, Converter converter) {
	if(input.empty()) {
		return OutputString();
	}

	try {
		OutputString result(input.size(), typename OutputString::value_type {});
		auto size = converter(result.data(), input.data(), result.size());
		if(size > result.max_size()) {
			return OutputString();
		}
		if(size > result.size()) {
			result.resize(size);
			const auto written = converter(result.data(), input.data(), result.size());
			if(written > result.size()) {
				return OutputString();
			}
			size = written;
		}
		result.resize(size);
		return result;
	} catch(...) {
		return OutputString();
	}
}

} // unnamed namespace

DCUtilsPtr Util::utils;

bool Util::init() {
	auto core = Core::handle();
	if(!core || !core->query_interface) {
		return false;
	}
	init(reinterpret_cast<DCUtilsPtr>(
		core->query_interface(DCINTF_DCPP_UTILS, DCINTF_DCPP_UTILS_VER)));
	return utils && utils->to_utf8 && utils->from_utf8 &&
		utils->utf8_to_wcs && utils->wcs_to_utf8;
}
void Util::init(DCUtilsPtr coreUtils) { utils = coreUtils; }
void Util::reset() noexcept {
	auto old = utils;
	utils = nullptr;
	Core::releaseInterface(reinterpret_cast<DCInterfacePtr>(old));
}
DCUtilsPtr Util::handle() { return utils; }

#ifdef _UNICODE
string Util::fromT(const wstring& str) {
	auto api = utils;
	if(!api || !api->wcs_to_utf8) {
		return string();
	}
	return convertString<string>(str,
		[api](char* output, const wchar_t* input, size_t size) {
			return api->wcs_to_utf8(output, input, size);
		});
}

wstring Util::toT(const string& str) {
	auto api = utils;
	if(!api || !api->utf8_to_wcs) {
		return wstring();
	}
	return convertString<wstring>(str,
		[api](wchar_t* output, const char* input, size_t size) {
			return api->utf8_to_wcs(output, input, size);
		});
}

string Util::fromT(const string& str) { return str; }
wstring Util::toT(const wstring& str) { return str; }
#endif // _UNICODE

string Util::fromUtf8(const string& str) {
	auto api = utils;
	if(!api || !api->from_utf8) {
		return string();
	}
	return convertString<string>(str,
		[api](char* output, const char* input, size_t size) {
			return api->from_utf8(output, input, size);
		});
}

string Util::toUtf8(const string& str) {
	auto api = utils;
	if(!api || !api->to_utf8) {
		return string();
	}
	return convertString<string>(str,
		[api](char* output, const char* input, size_t size) {
			return api->to_utf8(output, input, size);
		});
}

} // namespace dcapi
