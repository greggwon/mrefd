//
//  cprotocol.h
//  mrefd
//
//  Created by Jean-Luc Deltombe (LX3JL) on 01/11/2015.
//  Copyright © 2015 Jean-Luc Deltombe (LX3JL). All rights reserved.
//  Copyright © 2022-2025 Thomas A. Early, N7TAE
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
//    along with Foobar.  If not, see <http://www.gnu.org/licenses/>.
// ----------------------------------------------------------------------------

#pragma once

#include <atomic>
#include <functional>
#include <future>
#include <mutex>
#include <unordered_map>
#include <regex>

#include "packetstream.h"
#include "udpsocket.h"
#include "clients.h"
#include "packet.h"
#include "parrot.h"
#include "base.h"

// Signature for a per-callsign outbound sender. Return true on success;
// false lets the caller fall back to the default UDP send path.
// Used by the TLS interlink layer to redirect writes destined for a
// TLS-authenticated peer into the peer's SSL session.
using TSendMapped = std::function<bool(const uint8_t *buf, size_t size)>;


using SInterConnect = struct __attribute__((__packed__)) interconnect_tag {
	uint8_t magic[4];
	uint8_t fromcs[6];
	uint8_t mods[27];
}; // 37 bytes

class CProtocol : public CBase
{
public:
	// constructor
	CProtocol();

	// destructor
	virtual ~CProtocol();

	// initialization
	bool Initialize(const uint16_t port, const std::string &ipv4bind, const std::string &ipv6bind);
	void Close(void);

	// get
	const CCallsign &GetReflectorCallsign(void)const { return m_ReflectorCallsign; }

	// task
	void Thread(void);
	void Task(void);

	// -- pluggable outbound routing ------------------------------------
	// Any registered sender is consulted before the default UDP send.
	// An empty map (the default) preserves the pre-existing UDP behavior
	// exactly. Callsigns keyed as the printable "GetCS()" form so no
	// hash/less specialization for CCallsign is required.
	void RegisterSender  (const std::string &callsign, TSendMapped sender);
	void UnregisterSender(const std::string &callsign);
	// Returns true if a mapped sender handled the write; false = caller
	// should fall through to UDP.
	bool TrySendMapped(const std::string &callsign,
	                   const uint8_t *buf, size_t size) const;

	// Register / unregister CClient entries in g_Reflector.GetClients() for
	// a TLS-authenticated peer. Called by the TLS interlink layer at BIRTH
	// time (add) and session-close time (remove). Uses this protocol's own
	// UDP sockets as the CClient socket reference; actual writes are
	// diverted via the sender map (RegisterSender above), so the socket
	// reference is never used for a TLS peer.
	void AddInterlinkPeerClients   (const CCallsign &identity,
	                                const CIp &ip,
	                                const std::string &mods);
	void RemoveInterlinkPeerClients(const CCallsign &identity);

	// Process one already-received M17 data packet (Stream Mode or Packet
	// Mode) exactly as if it arrived over UDP. Called from Task() for real
	// UDP receives and from the TLS interlink layer when an M17_STREAM /
	// M17_PACKET frame arrives on an authenticated session (payload after
	// the msg_type byte is the same on-the-wire M17 packet body).
	void ProcessDataPacket(CPacket &pack, unsigned len, const CIp &ip);

protected:
	// queue helper
	void SendToClients(CPacket &, const SPClient &, const CCallsign &dst);
	// dashboard data
	void UpdateDashData(const CCallsign &src, const CCallsign &dst, SPClient client, const CPacket &pack);

	// keepalive helpers
	void HandlePeerLinks(void);
	void HandleKeepalives(void);

	// stream helpers
	CPacketStream *OpenStream(CPacket &, SPClient);
	void CloseStream(char mod);
	bool OnPacketIn(CPacket &, const SPClient);
	CPacketStream *GetStream(CPacket &, const SPClient);
	void CheckStreamsTimeout(void);

	// packet decoding helpers
	SPClient GetClient(const CIp &ip, const unsigned size, CPacket &p, CCallsign &dst, CCallsign &src);
	bool IsValidConnect(const uint8_t *, const CIp &, CCallsign &, char &);
	bool IsValidDisconnect(const uint8_t *, CCallsign &);
	bool IsValidKeepAlive(const uint8_t *, CCallsign &);
	bool IsValidNAcknowledge(const uint8_t *, CCallsign &);
	bool IsValidInterlinkConnect(const uint8_t *, const CIp &, CCallsign &, char *);
	bool IsValidInterlinkAcknowledge(const uint8_t *, CCallsign &, char *);

	// packet encoding helpers
	void EncodeKeepAlivePacket(uint8_t *);
	void EncodeConnectAckPacket(uint8_t *);
	void EncodeConnectNackPacket(uint8_t *);
	void EncodeDisconnectPacket(uint8_t *, char);
	void EncodeDisconnectedPacket(uint8_t *);
	void EncodeInterlinkConnectPacket(SInterConnect &, const std::string &);
	void EncodeInterlinkAckPacket(SInterConnect &, const char *);
	void EncodeInterlinkNackPacket(uint8_t *);

	// syntax helper
	bool IsNumber(char) const;
	bool IsLetter(char) const;
	bool IsSpace(char) const;

	unsigned Receive6(uint8_t *buf, CIp &Ip, int time_ms);
	unsigned Receive4(uint8_t *buf, CIp &Ip, int time_ms);
	unsigned ReceiveDS(uint8_t *buf, CIp &Ip, int time_ms);
	unsigned (CProtocol::*Receive)(uint8_t *buf, CIp &Ip, int time_ms);

	void Send(const uint8_t *buf, size_t size, const CIp &Ip) const;

	// socket
	CUdpSocket m_Socket4;
	CUdpSocket m_Socket6;

	// streams
	std::unordered_map<char, std::unique_ptr<CPacketStream>> m_streamMap;

	// thread
	std::atomic<bool> keep_running;
	std::future<void> m_Future;

	// identity
	CCallsign       m_ReflectorCallsign;

	// debug
	CTimer      m_DebugTimer;

	// time
	CTimer m_LastKeepaliveTime;
	CTimer m_LastPeersLinkTime;

	// for PutDHTInfo
	bool publish;

private:
	std::regex clientRegEx, peerRegEx, lstnRegEx;
	std::unordered_map<SPClient, std::unique_ptr<CParrot>> parrotMap;

	mutable std::mutex                            m_SenderMutex;
	std::unordered_map<std::string, TSendMapped>  m_SenderMap;
};
