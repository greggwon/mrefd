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

// One TLS interlink session. Owns an (fd, SSL*) pair and exposes framed
// read/write built on top of the framing primitives in framing.h.
//
// Blocking I/O: SSL_read/SSL_write are called on a blocking fd, so a
// caller's thread parks in the read path until either a frame arrives or
// the peer disconnects. Each accepted / initiated TLS peer therefore runs
// on its own thread inside mrefd; the reflector's central thread never
// blocks on network I/O.
//
// The class is move-only; ownership of the fd and SSL* is uniquely held.

#pragma once

#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include <openssl/ssl.h>

class CTLSSession
{
public:
	CTLSSession() = default;
	// Non-copyable, move-only.
	CTLSSession(const CTLSSession &) = delete;
	CTLSSession &operator=(const CTLSSession &) = delete;
	CTLSSession(CTLSSession &&other) noexcept;
	CTLSSession &operator=(CTLSSession &&other) noexcept;
	~CTLSSession();

	// Construct a server-side session over an already-accept()'d fd. The
	// SSL_CTX is borrowed (must outlive the session). DoServerHandshake()
	// must be called before ReadFrame/WriteFrame.
	static CTLSSession CreateServer(int fd, SSL_CTX *ctx);

	// Construct a client-side session over an already-connect()'d fd.
	// Same lifetime rules as CreateServer.
	static CTLSSession CreateClient(int fd, SSL_CTX *ctx);

	// Perform the TLS handshake. Returns true on success. On failure the
	// session's fd is closed and the object becomes valueless.
	bool DoServerHandshake();
	bool DoClientHandshake();

	// Read exactly one framed message from the session. The message-type
	// byte is the first byte of `payload`. Returns true on success; false
	// on protocol/wire error or peer disconnect.
	bool ReadFrame(std::vector<uint8_t> &payload);

	// Write one framed message. `payload` starts with the message-type
	// byte. Returns true on success.
	bool WriteFrame(const std::vector<uint8_t> &payload);

	// Gracefully close the session (SSL_shutdown + close fd). Safe to
	// call multiple times; the destructor calls this.
	void Close();

	// Accessors
	bool IsOpen() const           { return m_ssl != nullptr; }
	int  GetFd()  const           { return m_fd; }
	const std::string &GetPeerAddress() const { return m_peer_addr; }
	uint16_t GetPeerPort() const  { return m_peer_port; }

	// Callsign (Subject CN) and SPKI SHA-256 fingerprint of the certificate
	// the peer presented in the handshake. False if none was presented.
	bool GetPeerCertIdentity(std::string &callsign, std::string &spki_fingerprint) const;

	// Identity is assigned by the caller after a BIRTH exchange, so the
	// dashboard / logging code can name a session by its authenticated
	// identity rather than by socket address.
	void SetIdentity(const std::string &id) { m_identity = id; }
	const std::string &GetIdentity() const  { return m_identity; }

private:
	// Private ctor used by the factory methods.
	CTLSSession(int fd, SSL_CTX *ctx);

	// Discover the peer's address and port from the connected fd; stashed
	// into m_peer_addr / m_peer_port for logging and BIRTH bookkeeping.
	void PopulatePeerAddress();

	int         m_fd        = -1;
	SSL        *m_ssl       = nullptr;    // owned
	std::string m_peer_addr;
	uint16_t    m_peer_port = 0;
	std::string m_identity;               // set by caller after BIRTH

	// OpenSSL requires that concurrent SSL_write calls on the same SSL*
	// be serialized. SSL_read stays exclusive to the read-loop thread and
	// is safe to run concurrently with a locked SSL_write.
	// Held via unique_ptr so CTLSSession stays movable (std::mutex is not).
	std::unique_ptr<std::mutex> m_write_mutex;
};
