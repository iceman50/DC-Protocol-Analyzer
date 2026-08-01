/*
* Copyright (C) 2026 iceman50
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

#ifndef PROTOCOL_ANALYZER_TABLE_COLORS_H
#define PROTOCOL_ANALYZER_TABLE_COLORS_H

#include "UIStyles.h"

#include <pluginsdk/Config.h>

#include <array>
#include <cstddef>
#include <string>

namespace table_colors {

enum class Role {
	Background,
	AlternateBackground,
	Text,
	Timestamp,
	Counter,
	Incoming,
	Outgoing,
	Adc,
	Nmdc,
	Udp,
	Dht,
	Unknown,
	Address,
	Port,
	Peer,
	Message,
	SelectionBackground,
	SelectionText,
	HeaderBackground,
	HeaderText,
	InspectorBackground,
	InspectorText,
	InspectorHeading,
	InspectorLabel,
	InspectorFieldCode,
	InspectorValue,
	InspectorValid,
	InspectorWarning,
	InspectorError,
	InspectorRaw,
	Count
};

struct RoleInfo {
	Role role;
	const TCHAR* label;
	const char* keySuffix;
};

inline const std::array<RoleInfo, static_cast<size_t>(Role::Count)>& roles() {
	static const std::array<RoleInfo, static_cast<size_t>(Role::Count)> value {{
		{ Role::Background, _T("Row background"), "Background" },
		{ Role::AlternateBackground, _T("Alternate row"), "AlternateBackground" },
		{ Role::Text, _T("Default text"), "Text" },
		{ Role::Timestamp, _T("Timestamp"), "Timestamp" },
		{ Role::Counter, _T("Message number"), "Counter" },
		{ Role::Incoming, _T("Incoming direction"), "Incoming" },
		{ Role::Outgoing, _T("Outgoing direction"), "Outgoing" },
		{ Role::Adc, _T("ADC protocol"), "Adc" },
		{ Role::Nmdc, _T("NMDC protocol"), "Nmdc" },
		{ Role::Udp, _T("UDP protocol"), "Udp" },
		{ Role::Dht, _T("DHT protocol"), "Dht" },
		{ Role::Unknown, _T("Unknown protocol"), "Unknown" },
		{ Role::Address, _T("Network address"), "Address" },
		{ Role::Port, _T("Port"), "Port" },
		{ Role::Peer, _T("Peer"), "Peer" },
		{ Role::Message, _T("Message body"), "Message" },
		{ Role::SelectionBackground, _T("Selected row"), "SelectionBackground" },
		{ Role::SelectionText, _T("Selected text"), "SelectionText" },
		{ Role::HeaderBackground, _T("Header background"), "HeaderBackground" },
		{ Role::HeaderText, _T("Header text"), "HeaderText" },
		{ Role::InspectorBackground, _T("Inspector background"), "InspectorBackground" },
		{ Role::InspectorText, _T("Inspector default text"), "InspectorText" },
		{ Role::InspectorHeading, _T("Inspector headings"), "InspectorHeading" },
		{ Role::InspectorLabel, _T("Inspector labels"), "InspectorLabel" },
		{ Role::InspectorFieldCode, _T("Inspector field codes"), "InspectorFieldCode" },
		{ Role::InspectorValue, _T("Inspector values"), "InspectorValue" },
		{ Role::InspectorValid, _T("Inspector valid status"), "InspectorValid" },
		{ Role::InspectorWarning, _T("Inspector warnings"), "InspectorWarning" },
		{ Role::InspectorError, _T("Inspector errors"), "InspectorError" },
		{ Role::InspectorRaw, _T("Inspector raw message"), "InspectorRaw" }
	}};
	return value;
}

inline const RoleInfo& info(Role role) {
	return roles().at(static_cast<size_t>(role));
}

inline std::string configKey(Role role, bool dark) {
	return std::string(dark ? "TableDark" : "TableLight") + info(role).keySuffix;
}

constexpr uint32_t STORED_COLOR_MARKER = 0x01000000U;
constexpr uint32_t STORED_COLOR_MASK = 0x00ffffffU;

inline int32_t encodeStoredColor(COLORREF color) {
	return static_cast<int32_t>(
		STORED_COLOR_MARKER | (static_cast<uint32_t>(color) & STORED_COLOR_MASK));
}

inline bool decodeStoredColor(int32_t raw, COLORREF& color) {
	const auto value = static_cast<uint32_t>(raw);
	if((value & 0xff000000U) != STORED_COLOR_MARKER) {
		return false;
	}
	color = static_cast<COLORREF>(value & STORED_COLOR_MASK);
	return true;
}

inline COLORREF defaultColor(Role role, bool dark) {
	if(dark) {
		switch(role) {
			case Role::Background: return RGB(30, 41, 59);
			case Role::AlternateBackground: return RGB(24, 34, 53);
			case Role::Text: return RGB(226, 232, 240);
			case Role::Timestamp: return RGB(148, 163, 184);
			case Role::Counter: return RGB(148, 163, 184);
			case Role::Incoming: return RGB(74, 222, 128);
			case Role::Outgoing: return RGB(96, 165, 250);
			case Role::Adc: return RGB(96, 165, 250);
			case Role::Nmdc: return RGB(196, 181, 253);
			case Role::Udp: return RGB(251, 191, 36);
			case Role::Dht: return RGB(34, 211, 238);
			case Role::Unknown: return RGB(148, 163, 184);
			case Role::Address: return RGB(94, 234, 212);
			case Role::Port: return RGB(148, 163, 184);
			case Role::Peer: return RGB(196, 181, 253);
			case Role::Message: return RGB(226, 232, 240);
			case Role::SelectionBackground: return RGB(37, 99, 235);
			case Role::SelectionText: return RGB(255, 255, 255);
			case Role::HeaderBackground: return RGB(22, 32, 50);
			case Role::HeaderText: return RGB(148, 163, 184);
			case Role::InspectorBackground: return RGB(30, 41, 59);
			case Role::InspectorText: return RGB(226, 232, 240);
			case Role::InspectorHeading: return RGB(96, 165, 250);
			case Role::InspectorLabel: return RGB(148, 163, 184);
			case Role::InspectorFieldCode: return RGB(196, 181, 253);
			case Role::InspectorValue: return RGB(226, 232, 240);
			case Role::InspectorValid: return RGB(74, 222, 128);
			case Role::InspectorWarning: return RGB(251, 191, 36);
			case Role::InspectorError: return RGB(248, 113, 113);
			case Role::InspectorRaw: return RGB(148, 163, 184);
			case Role::Count: break;
		}
	} else {
		switch(role) {
			case Role::Background: return RGB(255, 255, 255);
			case Role::AlternateBackground: return RGB(248, 250, 252);
			case Role::Text: return RGB(30, 41, 59);
			case Role::Timestamp: return RGB(71, 85, 105);
			case Role::Counter: return RGB(100, 116, 139);
			case Role::Incoming: return RGB(22, 163, 74);
			case Role::Outgoing: return RGB(37, 99, 235);
			case Role::Adc: return RGB(37, 99, 235);
			case Role::Nmdc: return RGB(124, 58, 237);
			case Role::Udp: return RGB(180, 83, 9);
			case Role::Dht: return RGB(8, 145, 178);
			case Role::Unknown: return RGB(100, 116, 139);
			case Role::Address: return RGB(15, 118, 110);
			case Role::Port: return RGB(100, 116, 139);
			case Role::Peer: return RGB(109, 40, 217);
			case Role::Message: return RGB(30, 41, 59);
			case Role::SelectionBackground: return RGB(37, 99, 235);
			case Role::SelectionText: return RGB(255, 255, 255);
			case Role::HeaderBackground: return RGB(241, 245, 249);
			case Role::HeaderText: return RGB(71, 85, 105);
			case Role::InspectorBackground: return RGB(255, 255, 255);
			case Role::InspectorText: return RGB(30, 41, 59);
			case Role::InspectorHeading: return RGB(29, 78, 216);
			case Role::InspectorLabel: return RGB(71, 85, 105);
			case Role::InspectorFieldCode: return RGB(124, 58, 237);
			case Role::InspectorValue: return RGB(15, 23, 42);
			case Role::InspectorValid: return RGB(22, 163, 74);
			case Role::InspectorWarning: return RGB(180, 83, 9);
			case Role::InspectorError: return RGB(220, 38, 38);
			case Role::InspectorRaw: return RGB(100, 116, 139);
			case Role::Count: break;
		}
	}
	return dark ? RGB(226, 232, 240) : RGB(30, 41, 59);
}

struct PaletteCache {
	std::array<COLORREF, static_cast<size_t>(Role::Count)> light {};
	std::array<COLORREF, static_cast<size_t>(Role::Count)> dark {};
	bool initialized = false;
};

inline PaletteCache& cache() {
	static PaletteCache value;
	return value;
}

inline COLORREF highContrastColor(Role role) {
	switch(role) {
		case Role::Background:
		case Role::AlternateBackground:
			return ::GetSysColor(COLOR_WINDOW);
		case Role::SelectionBackground:
			return ::GetSysColor(COLOR_HIGHLIGHT);
		case Role::SelectionText:
			return ::GetSysColor(COLOR_HIGHLIGHTTEXT);
		case Role::HeaderBackground:
			return ::GetSysColor(COLOR_BTNFACE);
		case Role::HeaderText:
			return ::GetSysColor(COLOR_BTNTEXT);
		case Role::InspectorBackground:
			return ::GetSysColor(COLOR_WINDOW);
		default:
			return ::GetSysColor(COLOR_WINDOWTEXT);
	}
}

inline void initialize();

inline COLORREF get(Role role, bool dark) {
	initialize();
	if(ui::isHighContrast()) {
		return highContrastColor(role);
	}
	const auto index = static_cast<size_t>(role);
	return dark ? cache().dark.at(index) : cache().light.at(index);
}

inline COLORREF get(Role role) {
	return get(role, ui::isDarkMode());
}

inline void set(Role role, bool dark, COLORREF color) {
	initialize();
	color &= 0x00ffffff;
	const auto key = configKey(role, dark);
	dcapi::Config::setConfig(key.c_str(), encodeStoredColor(color));
	const auto index = static_cast<size_t>(role);
	if(dark) {
		cache().dark.at(index) = color;
	} else {
		cache().light.at(index) = color;
	}
}

inline void reset(bool dark) {
	for(const auto& role : roles()) {
		const auto color = defaultColor(role.role, dark);
		const auto key = configKey(role.role, dark);
		dcapi::Config::setConfig(key.c_str(), encodeStoredColor(color));
		const auto index = static_cast<size_t>(role.role);
		if(dark) {
			cache().dark[index] = color;
		} else {
			cache().light[index] = color;
		}
	}
}

inline void initialize() {
	auto& value = cache();
	if(value.initialized) {
		return;
	}
	value.initialized = true;

	constexpr int PALETTE_VERSION = 3;
	const auto oldVersion = dcapi::Config::getIntConfig("TablePaletteVersion");
	if(oldVersion < 1) {
		reset(false);
		reset(true);
	} else {
		for(const auto& role : roles()) {
			for(bool dark : { false, true }) {
				const auto key = configKey(role.role, dark);
				const auto raw = dcapi::Config::getIntConfig(key.c_str());
				COLORREF color = defaultColor(role.role, dark);
				bool valid = false;
				if(oldVersion >= PALETTE_VERSION) {
					valid = decodeStoredColor(raw, color);
				} else {
					// Versions 1 and 2 stored an unmarked 24-bit COLORREF.
					// Zero is valid for the roles those versions contained and
					// may intentionally represent black. Inspector roles did not
					// exist yet, so their absent zero-valued keys need defaults.
					const bool inspectorRole =
						role.role >= Role::InspectorBackground &&
						role.role <= Role::InspectorRaw;
					valid = !inspectorRole && raw >= 0 &&
						(static_cast<uint32_t>(raw) & 0xff000000U) == 0;
					if(valid) {
						color = static_cast<COLORREF>(raw);
					}
				}
				const auto index = static_cast<size_t>(role.role);
				if(dark) {
					value.dark[index] = color;
				} else {
					value.light[index] = color;
				}
				if(!valid || oldVersion < PALETTE_VERSION) {
					dcapi::Config::setConfig(
						key.c_str(), encodeStoredColor(color));
				}
			}
		}
	}
	dcapi::Config::setConfig("TablePaletteVersion", PALETTE_VERSION);

	// These settings belonged to the old protocol-only color model.
	dcapi::Config::removeConfig("BgColor");
	dcapi::Config::removeConfig("DarkBgColor");
	dcapi::Config::removeConfig("ADCColor");
	dcapi::Config::removeConfig("NMDCColor");
	dcapi::Config::removeConfig("UDPColor");
	dcapi::Config::removeConfig("DarkThemeInitialized");
}

} // namespace table_colors

#endif
