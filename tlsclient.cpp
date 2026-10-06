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

#include "tlsclient.h"
#include "birth.h"
#include "framing.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <iostream>

#include <openssl/err.h>

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
namespace
{
	uint64_t NowMs()
	{
		using namespace std::chrono;
		return duration_cast<milliseconds>(
			system_clock::now().time_since_epoch()).count();
	}

	void LogSSLError(const char *when)
	{
		unsigned long e;
		while ((e = ERR_get_error()) != 0)
		{
			char buf[256];
			ERR_error_string_n(e, buf, sizeof(buf));
			std::cerr << "TLS " << when << ": " << buf << std::endl;
		}
	}

	// Resolve host:port to a connected TCP socket. Tries every getaddrinfo
	// candidate in order (typical order is IPv6 first, then IPv4, matching
	// the modern dual-stack posture the design assumes). Returns fd on
	// success, -1 on failure.
	int TCPConnect(const std::string &host, uint16_t port)
	{
		struct addrinfo hints;
		memset(&hints, 0, sizeof(hints));
		hints.ai_family   = AF_UNSPEC;
		hints.ai_socktype = SOCK_STREAM;

		struct addrinfo *ai = nullptr;
		std::string port_s = std::to_string(port);
		int rc = getaddrinfo(host.c_str(), port_s.c_str(), &hints, &ai);
		if (rc != 0)
		{
			std::cerr << "TLS client: getaddrinfo(" << host << "): "
			          << gai_strerror(rc) << std::endl;
			return -1;
		}

		int fd = -1;
		for (auto *p = ai; p != nullptr; p = p->ai_next)
		{
			fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
			if (fd < 0) continue;
			if (connect(fd, p->ai_addr, p->ai_addrlen) == 0)
				break;
			close(fd);
			fd = -1;
		}
		freeaddrinfo(ai);
		if (fd < 0)
			std::cerr << "TLS client: connect(" << host << ":" << port
			          << ") failed: " << strerror(errno) << std::endl;
		return fd;
	}

	ETLSConnectResult MapRejectReason(uint8_t code)
	{
		switch (code)
		{
			case 0x01: return ETLSConnectResult::RejectUnknownIdentity;
			case 0x02: return ETLSConnectResult::RejectSignatureFailed;
			case 0x03: return ETLSConnectResult::RejectTimestampOutOfWindow;
			case 0x04: return ETLSConnectResult::RejectModulesNotPermitted;
			case 0x05: return ETLSConnectResult::RejectBadVersion;
			default:   return ETLSConnectResult::RejectOther;
		}
	}
}

// ---------------------------------------------------------------------------
// dtor
// ---------------------------------------------------------------------------
CTLSClient::~CTLSClient()
{
	if (m_ctx)
	{
		SSL_CTX_free(m_ctx);
		m_ctx = nullptr;
	}
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------
bool CTLSClient::Init(const std::string &client_cert_path,
                      const std::string &client_key_path,
                      const std::string &server_cert_path)
{
	m_ctx = SSL_CTX_new(TLS_client_method());
	if (!m_ctx)
	{
		LogSSLError("SSL_CTX_new");
		return false;
	}
	SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION);

	// Present the client cert during the TLS handshake. The hub identifies
	// this node by the key in it; BIRTH then proves possession of that key
	// and names the module being asserted.
	if (SSL_CTX_use_certificate_file(m_ctx, client_cert_path.c_str(),
	                                 SSL_FILETYPE_PEM) <= 0)
	{
		LogSSLError("use_certificate_file");
		std::cerr << "  cert path: " << client_cert_path << std::endl;
		return false;
	}
	if (SSL_CTX_use_PrivateKey_file(m_ctx, client_key_path.c_str(),
	                                SSL_FILETYPE_PEM) <= 0)
	{
		LogSSLError("use_PrivateKey_file");
		std::cerr << "  key path: " << client_key_path << std::endl;
		return false;
	}

	// Pin the server cert as our trust anchor. This is the only server
	// identity we'll accept.
	if (SSL_CTX_load_verify_locations(m_ctx, server_cert_path.c_str(), nullptr) <= 0)
	{
		LogSSLError("load_verify_locations");
		std::cerr << "  server cert path: " << server_cert_path << std::endl;
		return false;
	}
	SSL_CTX_set_verify(m_ctx, SSL_VERIFY_PEER, nullptr);

	// Our callsign is whatever our certificate says; the module is chosen
	// per connection by the caller.
	std::string fingerprint;
	if (!TLSCertIdentityFromFile(client_cert_path, m_callsign, fingerprint)
	    || !TLSIsBareCallsign(m_callsign))
	{
		std::cerr << "TLS client: certificate " << client_cert_path
		          << " must have the operator's bare callsign as its CN (got '"
		          << m_callsign << "')" << std::endl;
		return false;
	}

	m_client_key_path = client_key_path;
	return true;
}

// ---------------------------------------------------------------------------
// Connect
// ---------------------------------------------------------------------------
ETLSConnectResult CTLSClient::Connect(const std::string &host,
                                     uint16_t port,
                                     const std::string &identity,
                                     const std::string &modules,
                                     CTLSSession &out_session)
{
	int fd = TCPConnect(host, port);
	if (fd < 0)
		return ETLSConnectResult::TCPConnectFailed;

	CTLSSession session = CTLSSession::CreateClient(fd, m_ctx);
	if (!session.IsOpen())
	{
		return ETLSConnectResult::TLSHandshakeFailed;
	}

	// The self-signed server cert's Subject CN is not the hostname we
	// resolved, so we don't request SNI-based hostname verification.
	// Trust comes from load_verify_locations pinning the cert directly.
	if (!session.DoClientHandshake())
	{
		return ETLSConnectResult::TLSHandshakeFailed;
	}

	// Build and send BIRTH.
	std::vector<uint8_t> nonce;
	if (!TLSMakeNonce(nonce))
	{
		std::cerr << "TLS client: nonce generation failed" << std::endl;
		return ETLSConnectResult::BirthBuildFailed;
	}
	std::vector<uint8_t> payload;
	auto berr = TLSBuildBirth(identity, NowMs(), nonce, modules,
	                          m_client_key_path, payload);
	if (berr != EBirthError::Ok)
	{
		std::cerr << "TLS client: TLSBuildBirth failed ("
		          << static_cast<unsigned>(berr) << ")" << std::endl;
		return ETLSConnectResult::BirthBuildFailed;
	}
	if (!session.WriteFrame(payload))
	{
		std::cerr << "TLS client: WriteFrame(BIRTH) failed" << std::endl;
		return ETLSConnectResult::BirthWriteFailed;
	}

	// Read ACCEPT / REJECT.
	std::vector<uint8_t> reply;
	if (!session.ReadFrame(reply))
	{
		std::cerr << "TLS client: read reply failed" << std::endl;
		return ETLSConnectResult::AcceptReadFailed;
	}
	if (reply.empty())
	{
		std::cerr << "TLS client: empty reply" << std::endl;
		return ETLSConnectResult::AcceptReadFailed;
	}
	switch (static_cast<EMsgType>(reply[0]))
	{
		case EMsgType::Accept:
			session.SetIdentity(identity);
			out_session = std::move(session);
			return ETLSConnectResult::Ok;

		case EMsgType::Reject:
		{
			uint8_t reason = (reply.size() > 1) ? reply[1] : 0xFF;
			std::cerr << "TLS client: server rejected BIRTH, reason=0x"
			          << std::hex << static_cast<unsigned>(reason)
			          << std::dec << std::endl;
			return MapRejectReason(reason);
		}

		default:
			std::cerr << "TLS client: unexpected reply msg_type=0x"
			          << std::hex << static_cast<unsigned>(reply[0])
			          << std::dec << std::endl;
			return ETLSConnectResult::AcceptReadFailed;
	}
}
