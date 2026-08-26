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

#include "tlsserver.h"
#include "framing.h"

#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
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
}

// ---------------------------------------------------------------------------
// dtor
// ---------------------------------------------------------------------------
CTLSServer::~CTLSServer()
{
	Stop();
	if (m_ctx)
	{
		SSL_CTX_free(m_ctx);
		m_ctx = nullptr;
	}
}

// ---------------------------------------------------------------------------
// Init
// ---------------------------------------------------------------------------
bool CTLSServer::Init(const std::string &server_cert_path,
                      const std::string &server_key_path)
{
	m_ctx = SSL_CTX_new(TLS_server_method());
	if (!m_ctx)
	{
		LogSSLError("SSL_CTX_new");
		return false;
	}
	// TLS 1.2 minimum; OpenSSL 3 defaults are otherwise reasonable.
	SSL_CTX_set_min_proto_version(m_ctx, TLS1_2_VERSION);

	if (SSL_CTX_use_certificate_file(m_ctx, server_cert_path.c_str(),
	                                 SSL_FILETYPE_PEM) <= 0)
	{
		LogSSLError("use_certificate_file");
		std::cerr << "  cert path: " << server_cert_path << std::endl;
		return false;
	}
	if (SSL_CTX_use_PrivateKey_file(m_ctx, server_key_path.c_str(),
	                                SSL_FILETYPE_PEM) <= 0)
	{
		LogSSLError("use_PrivateKey_file");
		std::cerr << "  key path: " << server_key_path << std::endl;
		return false;
	}
	if (SSL_CTX_check_private_key(m_ctx) != 1)
	{
		std::cerr << "TLS: server private key does not match certificate" << std::endl;
		return false;
	}
	return true;
}

// ---------------------------------------------------------------------------
// Listen
// ---------------------------------------------------------------------------
bool CTLSServer::Listen(const std::string &bind_addr, uint16_t port)
{
	if (m_listen_fd >= 0)
	{
		std::cerr << "TLS server: Listen() called twice" << std::endl;
		return false;
	}

	// Try IPv6 first (accepts v4-mapped when the wildcard is used with
	// IPV6_V6ONLY off). Fall back to IPv4 if the address is a v4 literal.
	int family = bind_addr.find(':') != std::string::npos ? AF_INET6 : AF_INET;
	int fd = socket(family, SOCK_STREAM, 0);
	if (fd < 0)
	{
		std::cerr << "TLS server: socket: " << strerror(errno) << std::endl;
		return false;
	}

	int one = 1;
	setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	// For IPv6, disable V6ONLY so a bind on :: accepts v4 connections too.
	if (family == AF_INET6)
	{
		int off = 0;
		setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &off, sizeof(off));
	}

	if (family == AF_INET)
	{
		struct sockaddr_in sin;
		memset(&sin, 0, sizeof(sin));
		sin.sin_family = AF_INET;
		sin.sin_port   = htons(port);
		if (inet_pton(AF_INET, bind_addr.c_str(), &sin.sin_addr) != 1)
		{
			std::cerr << "TLS server: bad IPv4 bind_addr '" << bind_addr << "'" << std::endl;
			close(fd);
			return false;
		}
		if (bind(fd, reinterpret_cast<struct sockaddr*>(&sin), sizeof(sin)) < 0)
		{
			std::cerr << "TLS server: bind: " << strerror(errno) << std::endl;
			close(fd);
			return false;
		}
	}
	else
	{
		struct sockaddr_in6 sin6;
		memset(&sin6, 0, sizeof(sin6));
		sin6.sin6_family = AF_INET6;
		sin6.sin6_port   = htons(port);
		if (inet_pton(AF_INET6, bind_addr.c_str(), &sin6.sin6_addr) != 1)
		{
			std::cerr << "TLS server: bad IPv6 bind_addr '" << bind_addr << "'" << std::endl;
			close(fd);
			return false;
		}
		if (bind(fd, reinterpret_cast<struct sockaddr*>(&sin6), sizeof(sin6)) < 0)
		{
			std::cerr << "TLS server: bind: " << strerror(errno) << std::endl;
			close(fd);
			return false;
		}
	}

	if (listen(fd, 32) < 0)
	{
		std::cerr << "TLS server: listen: " << strerror(errno) << std::endl;
		close(fd);
		return false;
	}

	m_listen_fd = fd;
	std::cerr << "TLS server: listening on " << bind_addr << ":" << port << std::endl;
	return true;
}

// ---------------------------------------------------------------------------
// registry management
// ---------------------------------------------------------------------------
void CTLSServer::SetRegistry(std::map<std::string, STLSPeerRegistration> registry)
{
	std::lock_guard<std::mutex> lock(m_registry_mutex);
	m_registry.clear();
	for (auto &kv : registry)
	{
		m_registry[kv.first] =
			std::make_shared<STLSPeerRegistration>(std::move(kv.second));
	}
}

std::shared_ptr<STLSPeerRegistration>
CTLSServer::FindRegistration(const std::string &identity)
{
	std::lock_guard<std::mutex> lock(m_registry_mutex);
	auto it = m_registry.find(identity);
	return (it != m_registry.end()) ? it->second : nullptr;
}

// ---------------------------------------------------------------------------
// lifecycle
// ---------------------------------------------------------------------------
bool CTLSServer::Start()
{
	if (m_ctx == nullptr || m_listen_fd < 0 || !m_on_authenticated)
	{
		std::cerr << "TLS server: not fully configured; call "
		             "Init/Listen/SetAuthenticatedCallback first" << std::endl;
		return false;
	}
	m_running = true;
	m_accept_thread = std::thread([this] { this->AcceptLoop(); });
	return true;
}

void CTLSServer::Stop()
{
	if (!m_running.exchange(false)) return;

	// Closing the listen fd causes accept() to fail out of the loop.
	if (m_listen_fd >= 0)
	{
		shutdown(m_listen_fd, SHUT_RDWR);
		close(m_listen_fd);
		m_listen_fd = -1;
	}
	if (m_accept_thread.joinable())
		m_accept_thread.join();
}

// ---------------------------------------------------------------------------
// accept loop
// ---------------------------------------------------------------------------
void CTLSServer::AcceptLoop()
{
	while (m_running)
	{
		struct sockaddr_storage sa;
		socklen_t sl = sizeof(sa);
		int fd = accept(m_listen_fd, reinterpret_cast<struct sockaddr*>(&sa), &sl);
		if (fd < 0)
		{
			if (!m_running) break;
			if (errno == EINTR || errno == EAGAIN) continue;
			std::cerr << "TLS server: accept: " << strerror(errno) << std::endl;
			break;
		}
		// Handle in a dedicated thread; detach so it manages its own lifetime.
		std::thread(&CTLSServer::HandleConnection, this, fd).detach();
	}
}

// ---------------------------------------------------------------------------
// per-connection worker
// ---------------------------------------------------------------------------
void CTLSServer::HandleConnection(int fd)
{
	CTLSSession session = CTLSSession::CreateServer(fd, m_ctx);
	if (!session.IsOpen())
	{
		std::cerr << "TLS server: CreateServer failed" << std::endl;
		return;
	}
	if (!session.DoServerHandshake())
	{
		std::cerr << "TLS server: handshake failed from "
		          << session.GetPeerAddress() << std::endl;
		return;
	}

	// Read the BIRTH frame.
	std::vector<uint8_t> payload;
	if (!session.ReadFrame(payload))
	{
		std::cerr << "TLS server: read BIRTH failed from "
		          << session.GetPeerAddress() << std::endl;
		return;
	}
	SBirthMsg birth;
	auto perr = TLSParseBirth(payload, birth);
	if (perr != EBirthError::Ok)
	{
		std::cerr << "TLS server: BIRTH parse failed (" << static_cast<unsigned>(perr)
		          << ") from " << session.GetPeerAddress() << std::endl;
		return;
	}

	// Identity lookup.
	auto reg = FindRegistration(birth.identity);
	if (!reg)
	{
		std::cerr << "TLS server: unknown identity '" << birth.identity
		          << "' from " << session.GetPeerAddress()
		          << " (not in registry)" << std::endl;
		// Send a REJECT so the client knows why.
		std::vector<uint8_t> reject = {
			static_cast<uint8_t>(EMsgType::Reject),
			0x01,           // reason code: Unknown identity
		};
		session.WriteFrame(reject);
		return;
	}

	// Signature + skew check.
	auto verr = TLSVerifyBirth(birth, reg->keyfile, NowMs(), m_ts_skew_seconds);
	if (verr != EBirthError::Ok)
	{
		std::cerr << "TLS server: BIRTH verify failed (" << static_cast<unsigned>(verr)
		          << ") for identity '" << birth.identity
		          << "' from " << session.GetPeerAddress() << std::endl;
		std::vector<uint8_t> reject = {
			static_cast<uint8_t>(EMsgType::Reject),
			// map birth error to REJECT reason code
			(verr == EBirthError::TimestampOutOfWindow) ? static_cast<uint8_t>(0x03) :
			(verr == EBirthError::SignatureInvalid)     ? static_cast<uint8_t>(0x02) :
			                                              static_cast<uint8_t>(0xFF)
		};
		session.WriteFrame(reject);
		return;
	}

	// Cross-check requested modules against the registration.
	for (char m : birth.modules)
	{
		if (reg->modules.find(m) == std::string::npos)
		{
			std::cerr << "TLS server: identity '" << birth.identity
			          << "' requested module '" << m
			          << "' not in registration (" << reg->modules << ")" << std::endl;
			std::vector<uint8_t> reject = {
				static_cast<uint8_t>(EMsgType::Reject),
				0x04,   // Requested modules not permitted for this identity
			};
			session.WriteFrame(reject);
			return;
		}
	}

	// Success: send ACCEPT.
	std::vector<uint8_t> accept = { static_cast<uint8_t>(EMsgType::Accept) };
	if (!session.WriteFrame(accept))
	{
		std::cerr << "TLS server: write ACCEPT failed for '" << birth.identity
		          << "'" << std::endl;
		return;
	}
	session.SetIdentity(birth.identity);

	std::cerr << "TLS server: peer '" << birth.identity << "' authenticated from "
	          << session.GetPeerAddress() << ":" << session.GetPeerPort()
	          << " modules=" << birth.modules << std::endl;

	// Wrap into a shared_ptr so both the read-loop thread and the
	// sender-map closure can hold references. From here on the callback
	// owns the read loop and any teardown.
	auto sp = std::make_shared<CTLSSession>(std::move(session));
	m_on_authenticated(std::move(sp), std::move(birth));
}
