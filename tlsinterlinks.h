//
//  Copyright © 2026 Gregg Wonderly (W5GGW)
//
// ----------------------------------------------------------------------------
//    This file is part of mrefd.
//
//    This program is free software: you can redistribute it and/or modify
//    it under the terms of the GNU General Public License as published by
//    the Free Software Foundation, either version 3 of the License, or
//    (at your option) any later version.
//
//    This program is distributed in the hope that it will be useful,
//    but WITHOUT ANY WARRANTY; without even the implied warranty of
//    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//    GNU General Public License for more details.
//
//    You should have received a copy of the GNU General Public License
//    with this software.  If not, see <http://www.gnu.org/licenses/>.
// ----------------------------------------------------------------------------

// Top-level orchestration for the TLS interlink layer. Owns:
//   * A single CTLSServer (only spawned if the interlink file has any
//     "key:" entries)
//   * One retry-loop thread per "tls:" field-side target, each managing
//     its own CTLSClient
//   * The per-peer read-loop threads spawned by CTLSServer's callback
//
// Called by CReflector at startup / shutdown and by CGateKeeper on
// interlink hot-reload.

#pragma once

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "tlsclient.h"
#include "tlsserver.h"

class CTLSInterlinks
{
public:
	CTLSInterlinks() = default;
	CTLSInterlinks(const CTLSInterlinks &) = delete;
	CTLSInterlinks &operator=(const CTLSInterlinks &) = delete;
	~CTLSInterlinks();

	// Called once at startup after g_Interlinks has parsed the interlink
	// file. Reads the TLS entries from g_Interlinks, spawns CTLSServer if
	// there are peer regs, and starts one connect-retry thread per field
	// target.
	//
	// server_cert_path / server_key_path are pulled from the reflector's
	// runtime config; empty strings mean "not configured", in which case a
	// peer-reg entry is treated as an error (logged and skipped).
	bool Init(const std::string &server_cert_path,
	          const std::string &server_key_path,
	          const std::string &client_cert_path,
	          const std::string &client_key_path,
	          uint16_t           listen_port,
	          const std::string &bind_addr,
	          uint32_t           timestamp_skew_seconds);

	// Hot-reload path: refresh the server's peer registry snapshot from
	// g_Interlinks. Field-side target lists are not adjusted at runtime
	// (adding/removing a target requires a restart) - keeps 5a small.
	void Reload();

	// Signal all threads to stop and join them.
	void Stop();

	// True if Init() actually stood up either a server or any clients.
	bool IsActive() const { return m_server_running || !m_client_threads.empty(); }

private:
	// Called by CTLSServer after a peer's BIRTH is verified. Registers a
	// per-callsign sender on CProtocol that wraps outbound M17 packets in
	// M17_STREAM frames on the session, then spawns the read loop. The
	// shared_ptr keeps the session alive as long as either side holds it.
	void OnPeerAuthenticated(std::shared_ptr<CTLSSession> session, SBirthMsg birth);

	// Per-target retry loop for field-side outbound connections.
	void ClientRetryLoop(size_t target_index);

	// Consumes frames from an authenticated session. On M17_STREAM /
	// M17_PACKET frames, extracts the raw packet body and injects it into
	// CProtocol's dispatch path so downstream clients receive the audio /
	// data. On PING responds with PONG. On DISCONNECT closes the session.
	void ReadFrameLoop(std::shared_ptr<CTLSSession> session,
	                   const std::string &identity);

	std::unique_ptr<CTLSServer>    m_server;
	std::atomic<bool>              m_server_running{false};

	// Field-side: one CTLSClient + one retry thread per configured target.
	// m_client_targets is a snapshot of g_Interlinks.GetTLSClientTargets()
	// taken at Init() time.
	struct SClientState
	{
		std::unique_ptr<CTLSClient> client;
		std::string                 identity;
		std::string                 modules;
		std::string                 host;
		uint16_t                    port = 0;
	};
	std::vector<SClientState>      m_client_targets;
	std::vector<std::thread>       m_client_threads;
	std::atomic<bool>              m_stop{false};

	std::mutex                     m_worker_mutex;
	std::vector<std::thread>       m_worker_threads;   // detached read loops
};

extern CTLSInterlinks g_TLSInterlinks;
