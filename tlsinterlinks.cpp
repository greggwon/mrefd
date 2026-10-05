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

#include "tlsinterlinks.h"
#include "framing.h"
#include "interlinks.h"
#include "packet.h"
#include "reflector.h"

#include <chrono>
#include <cstring>
#include <iostream>

// g_Interlinks is defined in reflector.cpp (or main.cpp); this file only
// consumes it for the initial snapshot and hot-reload calls.
extern CInterlinks g_Interlinks;
extern CReflector  g_Reflector;

CTLSInterlinks g_TLSInterlinks;

// ---------------------------------------------------------------------------
// dtor
// ---------------------------------------------------------------------------
CTLSInterlinks::~CTLSInterlinks()
{
	Stop();
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
namespace
{
	std::map<std::string, STLSPeerRegistration>
	MakeRegistryFromInterlinks(const std::vector<STLSPeerReg> &regs)
	{
		std::map<std::string, STLSPeerRegistration> out;
		for (const auto &r : regs)
		{
			STLSPeerRegistration entry;
			entry.keyfile = r.keyfile;
			entry.modules = r.modules;
			out.emplace(r.identity, std::move(entry));
		}
		return out;
	}
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------
bool CTLSInterlinks::Init(const std::string &server_cert_path,
                          const std::string &server_key_path,
                          const std::string &client_cert_path,
                          const std::string &client_key_path,
                          uint16_t           listen_port,
                          const std::string &bind_addr,
                          uint32_t           timestamp_skew_seconds)
{
	m_stop = false;

	const auto &peer_regs      = g_Interlinks.GetTLSPeerRegs();
	const auto &client_targets = g_Interlinks.GetTLSClientTargets();

	// ---- home-side: CTLSServer, if any peer regs present -----------------
	if (!peer_regs.empty())
	{
		if (server_cert_path.empty() || server_key_path.empty())
		{
			std::cerr << "TLS interlinks: peer registrations found in "
			             "mrefd.interlink but no TLSServerCert/TLSServerKey "
			             "configured in mrefd.cfg; skipping the TLS server."
			          << std::endl;
		}
		else
		{
			m_server = std::make_unique<CTLSServer>();
			if (!m_server->Init(server_cert_path, server_key_path))
			{
				std::cerr << "TLS interlinks: server Init failed" << std::endl;
				m_server.reset();
			}
			else
			{
				m_server->SetTimestampSkew(timestamp_skew_seconds);
				m_server->SetRegistry(MakeRegistryFromInterlinks(peer_regs));
				m_server->SetAuthenticatedCallback(
					[this](std::shared_ptr<CTLSSession> s, SBirthMsg b) {
						this->OnPeerAuthenticated(std::move(s), std::move(b));
					});
				if (!m_server->Listen(bind_addr, listen_port))
				{
					std::cerr << "TLS interlinks: server Listen failed" << std::endl;
					m_server.reset();
				}
				else if (!m_server->Start())
				{
					std::cerr << "TLS interlinks: server Start failed" << std::endl;
					m_server.reset();
				}
				else
				{
					m_server_running = true;
					std::cout << "TLS interlinks: listening for "
					          << peer_regs.size() << " registered peer(s)"
					          << std::endl;
				}
			}
		}
	}

	// ---- field-side: one CTLSClient + retry thread per target -----------
	if (!client_targets.empty())
	{
		if (client_cert_path.empty() || client_key_path.empty())
		{
			std::cerr << "TLS interlinks: 'tls:' targets found in "
			             "mrefd.interlink but no TLSClientCert/TLSClientKey "
			             "configured; skipping field-side connect."
			          << std::endl;
		}
		else
		{
			for (const auto &t : client_targets)
			{
				SClientState st;
				st.client   = std::make_unique<CTLSClient>();
				st.identity = t.identity;
				st.modules  = t.modules;
				st.host     = t.host;
				st.port     = t.port;

				if (t.servercert.empty())
				{
					std::cerr << "TLS interlinks: target '" << t.identity
					          << "' has no servercert: pin; skipping." << std::endl;
					continue;
				}
				if (!st.client->Init(client_cert_path, client_key_path, t.servercert))
				{
					std::cerr << "TLS interlinks: client Init failed for '"
					          << t.identity << "'" << std::endl;
					continue;
				}
				m_client_targets.push_back(std::move(st));
			}

			for (size_t i = 0; i < m_client_targets.size(); ++i)
			{
				m_client_threads.emplace_back(
					&CTLSInterlinks::ClientRetryLoop, this, i);
			}
			std::cout << "TLS interlinks: starting outbound connects to "
			          << m_client_targets.size() << " target(s)" << std::endl;
		}
	}

	return IsActive();
}

// ---------------------------------------------------------------------------
// Reload
// ---------------------------------------------------------------------------
void CTLSInterlinks::Reload()
{
	if (!m_server) return;
	m_server->SetRegistry(MakeRegistryFromInterlinks(g_Interlinks.GetTLSPeerRegs()));
}

// ---------------------------------------------------------------------------
// Stop
// ---------------------------------------------------------------------------
void CTLSInterlinks::Stop()
{
	m_stop = true;

	if (m_server)
	{
		m_server->Stop();
		m_server_running = false;
	}
	for (auto &t : m_client_threads)
	{
		if (t.joinable()) t.join();
	}
	m_client_threads.clear();

	// Worker threads are detached; they exit on their own when the
	// underlying session closes. On process shutdown they are cleaned up
	// with the process.
}

// ---------------------------------------------------------------------------
// OnPeerAuthenticated  (server-side callback)
// ---------------------------------------------------------------------------
void CTLSInterlinks::OnPeerAuthenticated(std::shared_ptr<CTLSSession> session,
                                         SBirthMsg birth)
{
	std::cout << "TLS interlinks: peer '" << birth.identity
	          << "' connected from " << session->GetPeerAddress()
	          << ":" << session->GetPeerPort()
	          << " modules=" << birth.modules << std::endl;

	// Register a per-callsign sender so any CClient::SendPacket destined
	// for this peer routes through the TLS session instead of UDP. The
	// closure captures the session shared_ptr - it stays alive as long as
	// the map holds a reference to the closure.
	const std::string identity = birth.identity;
	auto sess_ref = session;
	g_Reflector.GetProtocol().RegisterSender(
		identity,
		[sess_ref](const uint8_t *buf, size_t size) -> bool {
			// Wrap the M17 packet body in an M17_STREAM frame. The wire
			// payload is identical to the UDP wire format so the receiving
			// peer's dispatch code paths are unchanged.
			std::vector<uint8_t> payload;
			payload.reserve(1 + size);
			payload.push_back(static_cast<uint8_t>(EMsgType::M17Stream));
			payload.insert(payload.end(), buf, buf + size);
			return sess_ref->WriteFrame(payload);
		});

	// Install one CClient per shared module in g_Reflector.GetClients() so
	// SendToClients iterates through them when dispatching module traffic.
	// The synthetic CIp uses the TCP source address; actual writes go
	// through the sender map above, so the socket reference held by each
	// CClient is never used.
	CCallsign cs(identity);
	CIp cip(session->GetPeerAddress().find(':') == std::string::npos
	            ? AF_INET : AF_INET6,
	        session->GetPeerPort(),
	        session->GetPeerAddress().c_str());
	g_Reflector.GetProtocol().AddInterlinkPeerClients(cs, cip, birth.modules);

	// Hand the read loop off to a detached worker. The worker unregisters
	// the sender AND removes the peer clients when the session closes.
	std::thread(&CTLSInterlinks::ReadFrameLoop, this,
	            session, identity).detach();
}

// ---------------------------------------------------------------------------
// ClientRetryLoop  (field-side worker)
// ---------------------------------------------------------------------------
void CTLSInterlinks::ClientRetryLoop(size_t idx)
{
	using namespace std::chrono_literals;

	auto &st = m_client_targets[idx];
	// Exponential backoff bounded at 60s.
	std::chrono::seconds backoff = 2s;

	while (!m_stop)
	{
		CTLSSession session;
		auto rc = st.client->Connect(st.host, st.port,
		                             st.identity, st.modules, session);
		if (rc == ETLSConnectResult::Ok)
		{
			std::cout << "TLS interlinks: connected to '" << st.identity
			          << "' at " << st.host << ":" << st.port << std::endl;
			backoff = 2s;

			// Wrap in shared_ptr so the sender-map closure and the read
			// loop can both hold references. Same shape as the server side.
			auto sp = std::make_shared<CTLSSession>(std::move(session));

			// Register outbound-write sender before draining the read loop.
			auto identity = st.identity;
			auto sess_ref = sp;
			g_Reflector.GetProtocol().RegisterSender(
				identity,
				[sess_ref](const uint8_t *buf, size_t size) -> bool {
					std::vector<uint8_t> payload;
					payload.reserve(1 + size);
					payload.push_back(static_cast<uint8_t>(EMsgType::M17Stream));
					payload.insert(payload.end(), buf, buf + size);
					return sess_ref->WriteFrame(payload);
				});

			// Install CClient entries so SendToClients dispatches through
			// this peer for each shared module.
			CCallsign cs(identity);
			CIp cip(sp->GetPeerAddress().find(':') == std::string::npos
			            ? AF_INET : AF_INET6,
			        sp->GetPeerPort(),
			        sp->GetPeerAddress().c_str());
			g_Reflector.GetProtocol().AddInterlinkPeerClients(cs, cip, st.modules);

			// Blocks until the session drops.
			ReadFrameLoop(sp, identity);
			// ReadFrameLoop already cleans up sender + peer clients on exit;
			// this belt-and-suspenders unregister covers the retry-loop path.
			g_Reflector.GetProtocol().UnregisterSender(identity);
			g_Reflector.GetProtocol().RemoveInterlinkPeerClients(cs);
			std::cout << "TLS interlinks: session with '" << st.identity
			          << "' closed; will retry" << std::endl;
		}
		else
		{
			std::cerr << "TLS interlinks: connect to '" << st.identity
			          << "' at " << st.host << ":" << st.port
			          << " failed (rc=" << static_cast<unsigned>(rc)
			          << "); retrying in " << backoff.count() << "s"
			          << std::endl;
		}

		// Sleep with early wake on stop.
		for (int i = 0; i < backoff.count() * 10 && !m_stop; ++i)
			std::this_thread::sleep_for(100ms);

		if (backoff < 60s) backoff *= 2;
		if (backoff > 60s) backoff = 60s;
	}
}

// ---------------------------------------------------------------------------
// ReadFrameLoop
// ---------------------------------------------------------------------------
void CTLSInterlinks::ReadFrameLoop(std::shared_ptr<CTLSSession> session,
                                   const std::string &identity)
{
	while (session->IsOpen() && !m_stop)
	{
		std::vector<uint8_t> payload;
		if (!session->ReadFrame(payload))
			break;

		if (payload.empty())
			continue;

		auto msg = static_cast<EMsgType>(payload[0]);
		switch (msg)
		{
			case EMsgType::Ping:
			{
				// echo PONG with the same sequence bytes.
				std::vector<uint8_t> pong = payload;
				pong[0] = static_cast<uint8_t>(EMsgType::Pong);
				session->WriteFrame(pong);
				break;
			}
			case EMsgType::Pong:
				break;
			case EMsgType::Disconnect:
				std::cout << "TLS interlinks: peer '" << identity
				          << "' sent DISCONNECT" << std::endl;
				g_Reflector.GetProtocol().UnregisterSender(identity);
				g_Reflector.GetProtocol().RemoveInterlinkPeerClients(CCallsign(identity));
				return;
			case EMsgType::M17Stream:
			case EMsgType::M17Packet:
			{
				// Payload after the msg_type byte is the on-the-wire M17
				// packet body, byte-identical to what would have arrived
				// via UDP. Copy into a CPacket, then feed to the SAME
				// receive-dispatch that Task() runs, using the TLS peer's
				// TCP source IP as the packet's ip.
				const size_t body_len = payload.size() - 1;
				if (body_len == 0 || body_len > MAX_PACKET_SIZE)
				{
					std::cerr << "TLS interlinks: dropping oversized/empty "
					          << "M17 frame from '" << identity
					          << "' (" << body_len << " bytes)" << std::endl;
					break;
				}
				CPacket pack;
				std::memcpy(pack.GetData(), &payload[1], body_len);
				pack.SetSize(body_len);
				CIp ip(session->GetPeerAddress().find(':') == std::string::npos
				           ? AF_INET : AF_INET6,
				       session->GetPeerPort(),
				       session->GetPeerAddress().c_str());
				g_Reflector.GetProtocol().ProcessDataPacket(
				    pack, static_cast<unsigned>(body_len), ip);
				break;
			}
			default:
				std::cerr << "TLS interlinks: unexpected msg_type 0x"
				          << std::hex << static_cast<unsigned>(payload[0])
				          << std::dec << " from '" << identity << "'"
				          << std::endl;
				break;
		}
	}
	// Loop exited due to read error or session close; make sure the sender
	// map and the client list don't hold stale entries.
	g_Reflector.GetProtocol().UnregisterSender(identity);
	g_Reflector.GetProtocol().RemoveInterlinkPeerClients(CCallsign(identity));
	std::cout << "TLS interlinks: read loop for '" << identity
	          << "' exiting" << std::endl;
}
