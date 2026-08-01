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

#ifndef PLUGIN_PLUGIN_H
#define PLUGIN_PLUGIN_H

#include "GUI.h"

#include <atomic>
#include <chrono>
#include <cstdint>
#include <deque>
#include <mutex>
#include <unordered_map>

using std::string;

class Plugin
{
public:
	static Bool DCAPI main(PluginState state, DCCorePtr core, dcptr_t);

private:
	Plugin();
	~Plugin();

	bool onLoad(DCCorePtr core, bool install, bool runtime);
	bool onHubDataIn(HubDataPtr hHub, char* message);
	bool onHubDataOut(HubDataPtr hHub, char* message);
	bool onClientDataIn(ConnectionDataPtr hConn, char* message);
	bool onClientDataOut(ConnectionDataPtr hConn, char* message);
	bool onUDPDataIn(UDPDataPtr data, char* message);
	bool onUDPDataOut(UDPDataPtr data, char* message);
	bool onChatCommand(HubDataPtr hub, CommandDataPtr cmd);
	void showGui(const char* source) noexcept;
	void shutdownCallbacks() noexcept;
	void observeBloomHeader(HubDataPtr hub, bool sending,
		const std::string& message);
	bool consumeExpectedBloomPayload(HubDataPtr hub, bool sending) noexcept;
	void clearBloomHookState() noexcept;

	GUI gui;

	struct BloomHookEndpoint {
		dcptr_t object;
		std::string url;
		std::string ip;
		decltype(HubData().port) port;
		ProtocolType protocol;
		bool sending;
	};

	struct PendingBloomRequest {
		BloomHookEndpoint endpoint;
		uint64_t bytes;
		uint32_t k;
		uint32_t h;
		std::chrono::steady_clock::time_point expires;
	};

	struct PendingBloomPayload {
		BloomHookEndpoint endpoint;
		uint64_t bytes;
		std::chrono::steady_clock::time_point expires;
	};

	struct DownloadRequest {
		uint64_t id;
		uint64_t bytes;
		bool byteCountSaturated;
		bool toFile;
	};

	std::atomic<bool> stopping;
	std::mutex bloomHookMutex;
	std::deque<PendingBloomRequest> pendingBloomRequests;
	std::deque<PendingBloomPayload> pendingBloomPayloads;
	std::mutex downloadMutex;
	std::unordered_map<std::string, DownloadRequest> downloadRequests;
	uint64_t nextDownloadId;
};

#endif
