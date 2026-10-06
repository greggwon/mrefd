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

// TLS interlink client. Used by the field-side of an interlink to reach a
// home reflector at a known hostname or IP. One CTLSClient per field
// interlink entry; the field's cert/key is shared across all outbound
// connections since a single field mrefd has one identity.
//
// Trust anchor: the server's cert is pinned by pointing load_verify_locations
// at the local copy the operator distributed out-of-band. No system CA
// bundle involvement.

#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include <openssl/ssl.h>

#include "birth.h"
#include "tlssession.h"

// Reason codes returned by Connect() when the server sends REJECT. Codes
// mirror docs/tls-interlink-design.md §3.4.
enum class ETLSConnectResult : uint8_t
{
	Ok                       = 0,
	TCPConnectFailed         = 1,
	TLSHandshakeFailed       = 2,
	BirthBuildFailed         = 3,
	BirthWriteFailed         = 4,
	AcceptReadFailed         = 5,
	// Server-side rejects:
	RejectUnknownIdentity    = 0x11,
	RejectSignatureFailed    = 0x12,
	RejectTimestampOutOfWindow = 0x13,
	RejectModulesNotPermitted  = 0x14,
	RejectBadVersion           = 0x15,
	RejectOther                = 0x1F,
};

class CTLSClient
{
public:
	CTLSClient() = default;
	CTLSClient(const CTLSClient &) = delete;
	CTLSClient &operator=(const CTLSClient &) = delete;
	~CTLSClient();

	// One-time initialization. Loads the field's own client cert/key AND
	// the pinned server cert used as trust anchor. Returns false on any
	// load failure (with stderr messages).
	bool Init(const std::string &client_cert_path,
	          const std::string &client_key_path,
	          const std::string &server_cert_path);

	// This node's callsign: the Subject CN of the client certificate loaded
	// by Init(). Valid after a successful Init().
	const std::string &GetCallsign() const { return m_callsign; }

	// Dial the server, negotiate TLS, and send a signed BIRTH.
	// Returns Ok on ACCEPT; a specific error otherwise.
	//
	//   host       - hostname or IPv4/IPv6 literal
	//   port       - TCP port (typically 17000)
	//   identity   - "<GetCallsign()>-<module>" to authenticate as
	//   modules    - the one module being asserted, e.g. "B"
	//   out_session- on success, the caller receives ownership of the
	//                authenticated session for post-BIRTH traffic.
	ETLSConnectResult Connect(const std::string &host,
	                          uint16_t port,
	                          const std::string &identity,
	                          const std::string &modules,
	                          CTLSSession &out_session);

private:
	SSL_CTX    *m_ctx = nullptr;              // owned
	std::string m_client_key_path;            // for signing BIRTH
	std::string m_callsign;                   // client cert's Subject CN
};
