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

// TLS interlink server. Listens on TCP, accepts incoming peer connections,
// runs the TLS handshake and the BIRTH exchange, then hands the
// authenticated session to a callback for the reflector's own peer-table
// integration to consume.
//
// One CTLSSession per connected peer runs on its own thread. The main
// accept thread does nothing but accept() and spawn.
//
// Peer identity resolution: the server holds a snapshot of the peer registry
// - a map from callsign-<module> string to keyfile path - loaded from mrefd's
// mrefd.interlink parser. When a BIRTH arrives, the server looks up the
// identity string, loads the pubkey from the associated file, and verifies
// the signature. Failure is logged and the session dropped.

#pragma once

#include <atomic>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include <openssl/ssl.h>

#include "birth.h"
#include "tlssession.h"

// Registry entry: for identity "W5GGW-B", the keyfile path is
// "/etc/mrefd/tls/peers/W5GGW-B.pub.pem" and the requested modules are
// "BCD". Loaded from mrefd.interlink at startup and hot-reloaded when the
// file changes.
struct STLSPeerRegistration
{
	std::string keyfile;      // filesystem path to peer's cert (PEM)
	std::string modules;      // shared modules from the interlink entry
};

// Callback fired after a peer's BIRTH is verified. The reflector implements
// this to install a peer entry in its main peer table and start relaying
// traffic.
//
// The session is delivered as a shared_ptr so the outbound sender closure
// (registered on CProtocol so writes go through the SSL session) and the
// per-peer read loop can both hold references safely across threads.
//
// Arguments:
//   session   - authenticated TLS session, ready for framed I/O
//   msg       - the parsed and verified BIRTH message (identity, ts, nonce,
//               modules, etc.)
using TLSPeerAuthenticatedCB =
	std::function<void(std::shared_ptr<CTLSSession> session, SBirthMsg msg)>;

class CTLSServer
{
public:
	CTLSServer() = default;
	CTLSServer(const CTLSServer &) = delete;
	CTLSServer &operator=(const CTLSServer &) = delete;
	~CTLSServer();

	// One-time initialization. Loads the server cert/key from disk, builds
	// the SSL_CTX. Returns false with a stderr message on failure.
	bool Init(const std::string &server_cert_path,
	          const std::string &server_key_path);

	// Bind and start listening. `bind_addr` is an IPv4/IPv6 literal
	// (0.0.0.0, ::, 44.61.17.20, ...). Returns false on failure.
	bool Listen(const std::string &bind_addr, uint16_t port);

	// Replace the peer registry snapshot. Safe to call at any time from
	// the interlink hot-reload path; per-peer worker threads use only
	// the identity they were authenticated with at BIRTH time, so an
	// in-flight session is unaffected by a registry update.
	void SetRegistry(std::map<std::string, STLSPeerRegistration> registry);

	// Register the peer-authenticated callback. Must be set before Start().
	void SetAuthenticatedCallback(TLSPeerAuthenticatedCB cb)
	{
		m_on_authenticated = std::move(cb);
	}

	// Configurable BIRTH acceptance window in seconds. Default 300.
	void SetTimestampSkew(uint32_t seconds) { m_ts_skew_seconds = seconds; }

	// Start the accept thread. Returns immediately.
	bool Start();

	// Signal the accept loop to exit and wait for the accept thread.
	// Currently-active per-peer sessions are NOT forcibly terminated -
	// they run until the peer disconnects or the process exits. Use the
	// admin socket / iptables path documented in
	// docs/tls-interlink-design.md §7.7 to close individual sessions.
	void Stop();

private:
	void AcceptLoop();
	void HandleConnection(int fd);

	// Look up an identity in the current registry snapshot. Returns nullptr
	// if the identity isn't registered. Holds m_registry_mutex.
	std::shared_ptr<STLSPeerRegistration>
	FindRegistration(const std::string &identity);

	SSL_CTX                  *m_ctx = nullptr;   // owned
	int                       m_listen_fd = -1;
	std::atomic<bool>         m_running{false};
	std::thread               m_accept_thread;
	uint32_t                  m_ts_skew_seconds = 300;

	std::mutex                m_registry_mutex;
	std::map<std::string, std::shared_ptr<STLSPeerRegistration>> m_registry;

	TLSPeerAuthenticatedCB    m_on_authenticated;
};
