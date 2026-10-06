//
//  Created by Jean-Luc Deltombe (LX3JL) on 30/12/2015.
//  Copyright © 2015 Jean-Luc Deltombe (LX3JL). All rights reserved.
//  Copyright © 2025 Thomas A. Early, N7TAE
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

#pragma once

#include <cstdint>
#include <mutex>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "interlink.h"

using InterlinkMap = std::unordered_map<std::string, std::unique_ptr<CInterlink>>;

// TLS interlink entries parsed out of mrefd.interlink. Kept in a separate
// list from the UDP map (m_Imap) so the existing UDP path is untouched by
// TLS lines; consumed by CTLSServer / CTLSClient at reflector startup.
//
// Home-side entry: registers one operator's key. Any node presenting that
// key may connect, asserting one of the listed modules, and is named
// "<callsign>-<module>". The callsign must be the cert's Subject CN.
//     Example: "W5GGW  BCD  key:/etc/mrefd/tls/peers/W5GGW.pub.pem"
struct STLSPeerReg
{
	std::string identity;    // operator's bare callsign, e.g. "W5GGW"
	std::string modules;     // modules its nodes may assert, e.g. "BCD"
	std::string keyfile;     // filesystem path to the operator's cert (PEM)
};

// Field-side entry: this reflector will initiate an outbound TLS
// connection to `host:port`, present its own client cert, expect the server
// cert to match `servercert`, and assert ONE module for this link.
//     Example: "M17-HOM  B  tls:home.example.org:17000  servercert:/etc/mrefd/home.pem"
struct STLSClientTarget
{
	std::string identity;    // name of the remote reflector, e.g. "M17-HOM"
	std::string modules;     // the single module this node asserts, e.g. "B"
	std::string host;        // hostname or IPv4/IPv6 literal
	uint16_t    port = 17000;
	std::string servercert;  // pinned server cert file (PEM)
};

////////////////////////////////////////////////////////////////////////////////////////
// class

class CInterlinks
{
public:
	// constructor
	CInterlinks();

	// destructor
	~CInterlinks();

	// file io
	virtual bool LoadFromFile(const char *);
	bool ReloadFromFile(void);
	bool NeedReload(void);

	#ifndef NO_DHT
	void Update(const std::string &cs, const std::string &cmods, const std::string &emods, const std::string &ipv4, const std::string &ipv6, uint16_t port, bool islegacy);
	#endif

	// pass-through
	bool empty() const { return m_Imap.empty(); }
	auto begin() { return m_Imap.begin(); }
	auto end()   { return m_Imap.end(); }

	const CInterlink *Find(const std::string &) const;

	// TLS entry accessors. Both lists are populated by LoadFromFile from
	// lines containing "key:", "tls:" or "servercert:" tokens; classic UDP
	// lines never appear here.
	const std::vector<STLSPeerReg>      &GetTLSPeerRegs()      const { return m_TLSPeerRegs; }
	const std::vector<STLSClientTarget> &GetTLSClientTargets() const { return m_TLSClientTargets; }

protected:
#ifndef NO_DHT
	void Emplace(const std::string &cs, const std::string &mods);
#endif
	void Emplace(const std::string &cs, const std::string &mods, const std::string &addr, uint16_t port, bool islegacy);
	bool GetLastModTime(time_t *);
	void ToUpper(std::string &s);

	// Parse a TLS-form line. `tokens` is the whitespace-separated token
	// vector; presence of a "key:", "tls:", or "servercert:" prefix in any
	// token has already triggered this path.
	void ParseTLSLine(const std::vector<std::string> &tokens, unsigned line_no);

	// data
	mutable std::mutex m_Mutex;
	const char *m_Filename;
	time_t m_LastModTime;
	InterlinkMap m_Imap;

	std::vector<STLSPeerReg>       m_TLSPeerRegs;
	std::vector<STLSClientTarget>  m_TLSClientTargets;
};
