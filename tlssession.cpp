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

#include "tlssession.h"
#include "framing.h"

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cstring>
#include <iostream>

#include <openssl/err.h>

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
namespace
{
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
// ctor / move / dtor
// ---------------------------------------------------------------------------
CTLSSession::CTLSSession(int fd, SSL_CTX *ctx)
	: m_fd(fd), m_write_mutex(std::make_unique<std::mutex>())
{
	m_ssl = SSL_new(ctx);
	if (m_ssl == nullptr)
	{
		LogSSLError("SSL_new");
		if (m_fd >= 0) { close(m_fd); m_fd = -1; }
		return;
	}
	SSL_set_fd(m_ssl, fd);
	PopulatePeerAddress();
}

CTLSSession::CTLSSession(CTLSSession &&o) noexcept
	: m_fd       (o.m_fd),
	  m_ssl      (o.m_ssl),
	  m_peer_addr(std::move(o.m_peer_addr)),
	  m_peer_port(o.m_peer_port),
	  m_identity (std::move(o.m_identity))
{
	o.m_fd        = -1;
	o.m_ssl       = nullptr;
	o.m_peer_port = 0;
}

CTLSSession &CTLSSession::operator=(CTLSSession &&o) noexcept
{
	if (this != &o)
	{
		Close();
		m_fd         = o.m_fd;
		m_ssl        = o.m_ssl;
		m_peer_addr  = std::move(o.m_peer_addr);
		m_peer_port  = o.m_peer_port;
		m_identity   = std::move(o.m_identity);
		o.m_fd       = -1;
		o.m_ssl      = nullptr;
		o.m_peer_port= 0;
	}
	return *this;
}

CTLSSession::~CTLSSession()
{
	Close();
}

// ---------------------------------------------------------------------------
// factories
// ---------------------------------------------------------------------------
CTLSSession CTLSSession::CreateServer(int fd, SSL_CTX *ctx)
{
	return CTLSSession(fd, ctx);
}

CTLSSession CTLSSession::CreateClient(int fd, SSL_CTX *ctx)
{
	return CTLSSession(fd, ctx);
}

// ---------------------------------------------------------------------------
// handshakes
// ---------------------------------------------------------------------------
bool CTLSSession::DoServerHandshake()
{
	if (m_ssl == nullptr) return false;
	if (SSL_accept(m_ssl) <= 0)
	{
		LogSSLError("SSL_accept");
		Close();
		return false;
	}
	return true;
}

bool CTLSSession::DoClientHandshake()
{
	if (m_ssl == nullptr) return false;
	if (SSL_connect(m_ssl) <= 0)
	{
		LogSSLError("SSL_connect");
		Close();
		return false;
	}
	return true;
}

// ---------------------------------------------------------------------------
// framed read/write
// ---------------------------------------------------------------------------
namespace
{
	// Read exactly `need` bytes from an SSL session into `out`.
	bool SSLReadExact(SSL *ssl, size_t need, std::vector<uint8_t> &out)
	{
		out.clear();
		out.reserve(need);
		while (out.size() < need)
		{
			uint8_t buf[4096];
			size_t want = need - out.size();
			if (want > sizeof(buf)) want = sizeof(buf);
			int got = SSL_read(ssl, buf, static_cast<int>(want));
			if (got <= 0) return false;
			out.insert(out.end(), buf, buf + got);
		}
		return true;
	}

	bool SSLWriteAll(SSL *ssl, const uint8_t *data, size_t len)
	{
		while (len > 0)
		{
			int wrote = SSL_write(ssl, data, static_cast<int>(len));
			if (wrote <= 0) return false;
			data += wrote;
			len  -= static_cast<size_t>(wrote);
		}
		return true;
	}
}

bool CTLSSession::ReadFrame(std::vector<uint8_t> &payload)
{
	if (m_ssl == nullptr) return false;

	std::vector<uint8_t> header;
	if (!SSLReadExact(m_ssl, FRAME_HEADER_BYTES, header))
		return false;

	const uint8_t version   = header[0];
	const uint8_t reserved  = static_cast<uint8_t>((header[1] >> 4) & 0x0F);
	const uint32_t length =
		(static_cast<uint32_t>(header[1] & 0x0F) << 16) |
		(static_cast<uint32_t>(header[2])        <<  8) |
		 static_cast<uint32_t>(header[3]);

	if (version != FRAME_VERSION)
	{
		std::cerr << "TLS session: bad frame version 0x"
		          << std::hex << static_cast<unsigned>(version) << std::dec
		          << " from " << m_peer_addr << std::endl;
		return false;
	}
	if (reserved != 0)
	{
		std::cerr << "TLS session: reserved bits set from " << m_peer_addr << std::endl;
		return false;
	}

	std::vector<uint8_t> body;
	if (length > 0)
	{
		if (!SSLReadExact(m_ssl, length, body))
			return false;
	}
	payload = std::move(body);
	return true;
}

bool CTLSSession::WriteFrame(const std::vector<uint8_t> &payload)
{
	// Serialize concurrent writes from the main mrefd thread (SendPacket via
	// the sender-map override) and any other writer (PING/PONG from the read
	// loop, DISCONNECT, etc.). SSL_read remains exclusive to the read loop
	// and is safe to run concurrently with a locked SSL_write.
	if (m_ssl == nullptr || !m_write_mutex) return false;
	std::lock_guard<std::mutex> lock(*m_write_mutex);

	std::vector<uint8_t> frame;
	if (TLSSerializeFrame(FRAME_VERSION, payload, frame) != EFrameError::Ok)
		return false;

	return SSLWriteAll(m_ssl, frame.data(), frame.size());
}

// ---------------------------------------------------------------------------
// shutdown
// ---------------------------------------------------------------------------
void CTLSSession::Close()
{
	if (m_ssl != nullptr)
	{
		SSL_shutdown(m_ssl);
		SSL_free(m_ssl);
		m_ssl = nullptr;
	}
	if (m_fd >= 0)
	{
		close(m_fd);
		m_fd = -1;
	}
}

// ---------------------------------------------------------------------------
// peer address discovery
// ---------------------------------------------------------------------------
void CTLSSession::PopulatePeerAddress()
{
	if (m_fd < 0) return;

	struct sockaddr_storage sa;
	socklen_t sl = sizeof(sa);
	if (getpeername(m_fd, reinterpret_cast<struct sockaddr*>(&sa), &sl) != 0)
		return;

	char buf[INET6_ADDRSTRLEN] = {0};
	if (sa.ss_family == AF_INET)
	{
		auto *s = reinterpret_cast<struct sockaddr_in*>(&sa);
		inet_ntop(AF_INET, &s->sin_addr, buf, sizeof(buf));
		m_peer_addr = buf;
		m_peer_port = ntohs(s->sin_port);
	}
	else if (sa.ss_family == AF_INET6)
	{
		auto *s = reinterpret_cast<struct sockaddr_in6*>(&sa);
		inet_ntop(AF_INET6, &s->sin6_addr, buf, sizeof(buf));
		m_peer_addr = buf;
		m_peer_port = ntohs(s->sin6_port);
	}
}
