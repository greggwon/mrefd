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

// End-to-end self-test for the TLS interlink primitives.
//
// Exercised:
//   1. Framing round-trip (build+parse) for every message type
//   2. Framing error paths (short-read, bad-version, reserved-bits)
//   3. BIRTH build → parse → verify round-trip
//   4. BIRTH signature-tamper detection
//   5. BIRTH timestamp-skew enforcement
//   6. Full TLS network flow between two processes: parent forks a child;
//      parent = home reflector (TLS server), child = field reflector (TLS
//      client). All identities are generated in-memory; the exchange runs
//      over loopback. Validates handshake, framed BIRTH, framed ACCEPT.
//
// No mrefd runtime state is involved; this binary is standalone and does not
// touch the reflector daemon itself.

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>

#include "../framing.h"
#include "../birth.h"

// ---------------------------------------------------------------------------
// Test scoreboard
// ---------------------------------------------------------------------------
static int g_pass = 0;
static int g_fail = 0;

#define EXPECT(cond, ...)                                                    \
	do {                                                                     \
		if (cond) { ++g_pass; }                                              \
		else {                                                               \
			++g_fail;                                                        \
			fprintf(stderr, "\033[31mFAIL\033[0m  %s:%d: ",                  \
			        __FILE__, __LINE__);                                     \
			fprintf(stderr, __VA_ARGS__);                                    \
			fputc('\n', stderr);                                             \
		}                                                                    \
	} while (0)

static void section(const char *name)
{
	fprintf(stderr, "\n\033[1m== %s ==\033[0m\n", name);
}

// ---------------------------------------------------------------------------
// RAII wrappers for OpenSSL handles used only in this test file
// ---------------------------------------------------------------------------
namespace
{
	struct EVPFree     { void operator()(EVP_PKEY *k)     const { if (k) EVP_PKEY_free(k); } };
	struct EVPCtxFree  { void operator()(EVP_PKEY_CTX *c) const { if (c) EVP_PKEY_CTX_free(c); } };
	struct X509Free    { void operator()(X509 *x)         const { if (x) X509_free(x); } };
	struct BIOFree     { void operator()(BIO *b)          const { if (b) BIO_free_all(b); } };
	struct SSLCtxFree  { void operator()(SSL_CTX *c)      const { if (c) SSL_CTX_free(c); } };
	struct SSLFree     { void operator()(SSL *s)          const { if (s) SSL_free(s); } };
	struct FileClose   { void operator()(FILE *f)         const { if (f) fclose(f); } };

	using PKey     = std::unique_ptr<EVP_PKEY,      EVPFree>;
	using PKeyCtx  = std::unique_ptr<EVP_PKEY_CTX,  EVPCtxFree>;
	using Cert     = std::unique_ptr<X509,          X509Free>;
	using BIOPtr   = std::unique_ptr<BIO,           BIOFree>;
	using SSLCtxP  = std::unique_ptr<SSL_CTX,       SSLCtxFree>;
	using SSLP     = std::unique_ptr<SSL,           SSLFree>;
	using FilePtr  = std::unique_ptr<FILE,          FileClose>;
}

// ---------------------------------------------------------------------------
// Identity helpers
// ---------------------------------------------------------------------------
static PKey GenEd25519Keypair()
{
	PKeyCtx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, nullptr));
	if (!ctx) return {};
	if (EVP_PKEY_keygen_init(ctx.get()) <= 0) return {};
	EVP_PKEY *raw = nullptr;
	if (EVP_PKEY_keygen(ctx.get(), &raw) <= 0) return {};
	return PKey(raw);
}

static Cert MakeSelfSignedCert(EVP_PKEY *pkey, const std::string &cn, int days = 3650)
{
	Cert x(X509_new());
	if (!x) return {};
	X509_set_version(x.get(), 2);   // v3
	ASN1_INTEGER_set(X509_get_serialNumber(x.get()), 1);
	X509_gmtime_adj(X509_getm_notBefore(x.get()), 0);
	X509_gmtime_adj(X509_getm_notAfter(x.get()), 60L * 60L * 24L * days);
	X509_set_pubkey(x.get(), pkey);
	X509_NAME *name = X509_get_subject_name(x.get());
	X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
	                           reinterpret_cast<const unsigned char*>(cn.c_str()),
	                           -1, -1, 0);
	X509_set_issuer_name(x.get(), name);   // self-signed
	// Ed25519 signs with EVP_MD == nullptr.
	if (X509_sign(x.get(), pkey, nullptr) <= 0) return {};
	return x;
}

static bool WritePEMPrivateKey(EVP_PKEY *k, const std::string &path)
{
	FilePtr fp(fopen(path.c_str(), "w"));
	if (!fp) return false;
	return 1 == PEM_write_PrivateKey(fp.get(), k, nullptr, nullptr, 0, nullptr, nullptr);
}

static bool WritePEMCert(X509 *x, const std::string &path)
{
	FilePtr fp(fopen(path.c_str(), "w"));
	if (!fp) return false;
	return 1 == PEM_write_X509(fp.get(), x);
}

// Generate an identity (keypair + self-signed cert) and write both to disk.
static bool MakeIdentity(const std::string &cn,
                         const std::string &key_path,
                         const std::string &cert_path,
                         PKey &out_pkey,
                         Cert &out_cert)
{
	PKey pkey = GenEd25519Keypair();
	if (!pkey) return false;
	Cert cert = MakeSelfSignedCert(pkey.get(), cn);
	if (!cert) return false;
	if (!WritePEMPrivateKey(pkey.get(), key_path)) return false;
	if (!WritePEMCert(cert.get(), cert_path)) return false;
	out_pkey = std::move(pkey);
	out_cert = std::move(cert);
	return true;
}

// ---------------------------------------------------------------------------
// Time / random
// ---------------------------------------------------------------------------
static uint64_t NowMs()
{
	using namespace std::chrono;
	return duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count();
}

// ---------------------------------------------------------------------------
// TESTS 1-2: framing
// ---------------------------------------------------------------------------
static void TestFramingRoundtrip()
{
	section("framing round-trip");

	std::vector<std::vector<uint8_t>> payloads = {
		{},                                          // zero-length
		{0x00},                                      // one byte
		{0x01, 0x02, 0x03, 0x04},                    // small
	};
	// Add a larger payload approaching but under FRAME_MAX_PAYLOAD.
	{
		std::vector<uint8_t> big(64 * 1024);
		for (size_t i = 0; i < big.size(); ++i) big[i] = static_cast<uint8_t>(i & 0xFF);
		payloads.push_back(std::move(big));
	}

	for (const auto &payload : payloads)
	{
		std::vector<uint8_t> frame;
		auto rc = TLSSerializeFrame(FRAME_VERSION, payload, frame);
		EXPECT(rc == EFrameError::Ok, "serialize failed (rc=%u payload=%zu)",
		       static_cast<unsigned>(rc), payload.size());
		EXPECT(frame.size() == FRAME_HEADER_BYTES + payload.size(),
		       "frame length wrong for payload=%zu", payload.size());

		SFrameHeader hdr;
		std::vector<uint8_t> parsed_payload;
		size_t consumed = 0;
		rc = TLSParseFrame(frame.data(), frame.size(), hdr, parsed_payload, consumed);
		EXPECT(rc == EFrameError::Ok, "parse failed (rc=%u payload=%zu)",
		       static_cast<unsigned>(rc), payload.size());
		EXPECT(hdr.version == FRAME_VERSION, "version mismatch");
		EXPECT(hdr.length == payload.size(), "length mismatch");
		EXPECT(parsed_payload == payload, "payload mismatch (size=%zu)", payload.size());
		EXPECT(consumed == frame.size(), "bytes_consumed wrong");
	}
}

static void TestFramingErrors()
{
	section("framing error paths");

	// Short read on header
	{
		uint8_t tiny[2] = {0x01, 0x00};
		SFrameHeader hdr;
		std::vector<uint8_t> pl;
		size_t consumed = 0;
		auto rc = TLSParseFrame(tiny, 2, hdr, pl, consumed);
		EXPECT(rc == EFrameError::ShortRead, "expected ShortRead, got %u",
		       static_cast<unsigned>(rc));
	}

	// Short read on payload
	{
		uint8_t header_only[FRAME_HEADER_BYTES] = { FRAME_VERSION, 0x00, 0x00, 0x08 };
		SFrameHeader hdr;
		std::vector<uint8_t> pl;
		size_t consumed = 0;
		auto rc = TLSParseFrame(header_only, sizeof(header_only), hdr, pl, consumed);
		EXPECT(rc == EFrameError::ShortRead, "expected ShortRead for missing payload, got %u",
		       static_cast<unsigned>(rc));
	}

	// Bad version
	{
		uint8_t bad_ver[FRAME_HEADER_BYTES] = { 0xEE, 0x00, 0x00, 0x00 };
		SFrameHeader hdr;
		std::vector<uint8_t> pl;
		size_t consumed = 0;
		auto rc = TLSParseFrame(bad_ver, sizeof(bad_ver), hdr, pl, consumed);
		EXPECT(rc == EFrameError::BadVersion, "expected BadVersion, got %u",
		       static_cast<unsigned>(rc));
	}

	// Reserved bits set
	{
		uint8_t rsv[FRAME_HEADER_BYTES] = { FRAME_VERSION, 0xF0, 0x00, 0x00 };
		SFrameHeader hdr;
		std::vector<uint8_t> pl;
		size_t consumed = 0;
		auto rc = TLSParseFrame(rsv, sizeof(rsv), hdr, pl, consumed);
		EXPECT(rc == EFrameError::ReservedBitsSet, "expected ReservedBitsSet, got %u",
		       static_cast<unsigned>(rc));
	}
}

// ---------------------------------------------------------------------------
// TESTS 3-5: BIRTH
// ---------------------------------------------------------------------------
static void TestBirthRoundtrip(const std::string &key_path, const std::string &cert_path)
{
	section("BIRTH round-trip");

	std::vector<uint8_t> nonce;
	EXPECT(TLSMakeNonce(nonce), "make nonce failed");

	std::vector<uint8_t> payload;
	uint64_t ts = NowMs();
	auto rc = TLSBuildBirth("W5GGW-B", ts, nonce, "BCD", key_path, payload);
	EXPECT(rc == EBirthError::Ok, "build failed (rc=%u)", static_cast<unsigned>(rc));

	SBirthMsg parsed;
	rc = TLSParseBirth(payload, parsed);
	EXPECT(rc == EBirthError::Ok, "parse failed (rc=%u)", static_cast<unsigned>(rc));
	EXPECT(parsed.identity == "W5GGW-B", "identity mismatch");
	EXPECT(parsed.timestamp_ms == ts, "timestamp mismatch");
	EXPECT(parsed.modules == "BCD", "modules mismatch");
	EXPECT(parsed.nonce == nonce, "nonce mismatch");

	rc = TLSVerifyBirth(parsed, cert_path, NowMs(), 300);
	EXPECT(rc == EBirthError::Ok, "verify failed (rc=%u)", static_cast<unsigned>(rc));
}

static void TestBirthTamper(const std::string &key_path, const std::string &cert_path)
{
	section("BIRTH tamper detection");

	std::vector<uint8_t> nonce;
	TLSMakeNonce(nonce);
	std::vector<uint8_t> payload;
	auto rc = TLSBuildBirth("W5GGW-B", NowMs(), nonce, "BCD", key_path, payload);
	EXPECT(rc == EBirthError::Ok, "build failed");

	// Flip a byte in the middle of the signature. Signature starts at:
	//   1 (msg) + 1 (id_len) + 7 (identity) + 8 (ts) + 32 (nonce) + 1 (sig_len)
	//   = 50
	// So byte 50 is the first byte of the signature; flip byte 60.
	payload[60] ^= 0xFF;

	SBirthMsg parsed;
	rc = TLSParseBirth(payload, parsed);
	EXPECT(rc == EBirthError::Ok, "parse of tampered payload should still succeed");

	rc = TLSVerifyBirth(parsed, cert_path, NowMs(), 300);
	EXPECT(rc == EBirthError::SignatureInvalid,
	       "expected SignatureInvalid, got %u", static_cast<unsigned>(rc));
}

static void TestBirthSkew(const std::string &key_path, const std::string &cert_path)
{
	section("BIRTH timestamp skew");

	// Build a BIRTH with a timestamp 1 hour in the past.
	std::vector<uint8_t> nonce;
	TLSMakeNonce(nonce);
	uint64_t old_ts = NowMs() - 3600ULL * 1000ULL;

	std::vector<uint8_t> payload;
	TLSBuildBirth("W5GGW-B", old_ts, nonce, "BCD", key_path, payload);
	SBirthMsg parsed;
	TLSParseBirth(payload, parsed);

	// 300-second window: rejected
	auto rc = TLSVerifyBirth(parsed, cert_path, NowMs(), 300);
	EXPECT(rc == EBirthError::TimestampOutOfWindow,
	       "expected TimestampOutOfWindow, got %u", static_cast<unsigned>(rc));

	// 2-hour window: accepted (signature is still valid; only skew was the issue)
	rc = TLSVerifyBirth(parsed, cert_path, NowMs(), 7200);
	EXPECT(rc == EBirthError::Ok,
	       "expected Ok with wide window, got %u", static_cast<unsigned>(rc));
}

// ---------------------------------------------------------------------------
// TEST 6: full TLS network round-trip (fork'd)
// ---------------------------------------------------------------------------
static bool DrainSSL(SSL *s, std::vector<uint8_t> &out, size_t need)
{
	// Read exactly `need` bytes.
	out.clear();
	out.reserve(need);
	while (out.size() < need)
	{
		uint8_t buf[4096];
		size_t want = need - out.size();
		if (want > sizeof(buf)) want = sizeof(buf);
		int got = SSL_read(s, buf, static_cast<int>(want));
		if (got <= 0) return false;
		out.insert(out.end(), buf, buf + got);
	}
	return true;
}

static bool SSLWriteAll(SSL *s, const std::vector<uint8_t> &data)
{
	const uint8_t *p = data.data();
	size_t left = data.size();
	while (left > 0)
	{
		int wrote = SSL_write(s, p, static_cast<int>(left));
		if (wrote <= 0) return false;
		p    += wrote;
		left -= wrote;
	}
	return true;
}

// Read one framed message from the SSL session (header first, then payload).
static EFrameError ReadFrame(SSL *s, std::vector<uint8_t> &payload)
{
	std::vector<uint8_t> header;
	if (!DrainSSL(s, header, FRAME_HEADER_BYTES))
		return EFrameError::ShortRead;

	// Parse just the header to learn payload length.
	uint32_t length =
		(static_cast<uint32_t>(header[1] & 0x0F) << 16) |
		(static_cast<uint32_t>(header[2])        <<  8) |
		 static_cast<uint32_t>(header[3]);

	std::vector<uint8_t> body;
	if (length > 0 && !DrainSSL(s, body, length))
		return EFrameError::ShortRead;

	std::vector<uint8_t> combined;
	combined.reserve(header.size() + body.size());
	combined.insert(combined.end(), header.begin(), header.end());
	combined.insert(combined.end(), body.begin(),   body.end());

	SFrameHeader hdr;
	size_t consumed = 0;
	return TLSParseFrame(combined.data(), combined.size(), hdr, payload, consumed);
}

static bool WriteFrame(SSL *s, const std::vector<uint8_t> &payload)
{
	std::vector<uint8_t> frame;
	if (TLSSerializeFrame(FRAME_VERSION, payload, frame) != EFrameError::Ok)
		return false;
	return SSLWriteAll(s, frame);
}

// Server side of the network test. Runs in the parent process.
// Returns 0 on success, nonzero on failure.
static int RunServer(int listen_fd,
                     const std::string &server_cert_path,
                     const std::string &server_key_path,
                     const std::string &peer_cert_path)
{
	SSLCtxP ctx(SSL_CTX_new(TLS_server_method()));
	if (!ctx) { fprintf(stderr, "server: SSL_CTX_new failed\n"); return 1; }
	SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);

	if (SSL_CTX_use_certificate_file(ctx.get(), server_cert_path.c_str(), SSL_FILETYPE_PEM) <= 0
	    || SSL_CTX_use_PrivateKey_file(ctx.get(), server_key_path.c_str(), SSL_FILETYPE_PEM) <= 0)
	{
		fprintf(stderr, "server: could not load cert/key\n");
		return 1;
	}

	int fd = accept(listen_fd, nullptr, nullptr);
	if (fd < 0) { fprintf(stderr, "server: accept: %s\n", strerror(errno)); return 1; }

	SSLP s(SSL_new(ctx.get()));
	SSL_set_fd(s.get(), fd);
	if (SSL_accept(s.get()) <= 0)
	{
		fprintf(stderr, "server: SSL_accept failed\n");
		ERR_print_errors_fp(stderr);
		close(fd);
		return 1;
	}

	// Read framed BIRTH.
	std::vector<uint8_t> payload;
	auto ferr = ReadFrame(s.get(), payload);
	if (ferr != EFrameError::Ok)
	{
		fprintf(stderr, "server: ReadFrame failed (%u)\n", static_cast<unsigned>(ferr));
		close(fd); return 1;
	}

	SBirthMsg birth;
	auto berr = TLSParseBirth(payload, birth);
	if (berr != EBirthError::Ok)
	{
		fprintf(stderr, "server: ParseBirth failed (%u)\n", static_cast<unsigned>(berr));
		close(fd); return 1;
	}

	// Verify against the peer's registered cert (loaded from disk).
	berr = TLSVerifyBirth(birth, peer_cert_path, NowMs(), 300);
	if (berr != EBirthError::Ok)
	{
		fprintf(stderr, "server: VerifyBirth failed (%u)\n", static_cast<unsigned>(berr));
		close(fd); return 1;
	}

	fprintf(stderr, "  \033[32mserver\033[0m: BIRTH from '%s' verified (modules=%s)\n",
	        birth.identity.c_str(), birth.modules.c_str());

	// Send ACCEPT (just a single msg_type byte, no fields).
	std::vector<uint8_t> accept_payload = { static_cast<uint8_t>(EMsgType::Accept) };
	if (!WriteFrame(s.get(), accept_payload))
	{
		fprintf(stderr, "server: WriteFrame(ACCEPT) failed\n");
		close(fd); return 1;
	}

	SSL_shutdown(s.get());
	close(fd);
	return 0;
}

// Client side. Runs in the forked child.
static int RunClient(uint16_t port,
                     const std::string &server_cert_path,
                     const std::string &client_key_path,
                     const std::string &identity)
{
	SSLCtxP ctx(SSL_CTX_new(TLS_client_method()));
	if (!ctx) { fprintf(stderr, "client: SSL_CTX_new failed\n"); return 1; }
	SSL_CTX_set_min_proto_version(ctx.get(), TLS1_2_VERSION);

	// Pin the server cert by loading it as the ONLY trust anchor.
	if (SSL_CTX_load_verify_locations(ctx.get(), server_cert_path.c_str(), nullptr) <= 0)
	{
		fprintf(stderr, "client: load_verify_locations failed\n");
		return 1;
	}
	SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);

	int fd = socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) { fprintf(stderr, "client: socket: %s\n", strerror(errno)); return 1; }

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port   = htons(port);
	inet_pton(AF_INET, "127.0.0.1", &sin.sin_addr);
	if (connect(fd, reinterpret_cast<struct sockaddr*>(&sin), sizeof(sin)) < 0)
	{
		fprintf(stderr, "client: connect: %s\n", strerror(errno));
		close(fd); return 1;
	}

	SSLP s(SSL_new(ctx.get()));
	SSL_set_fd(s.get(), fd);
	// Since the server cert is self-signed and its Subject CN is not a
	// hostname the client resolved, disable hostname checking for this test
	// and rely on cert-pinning alone via load_verify_locations.
	SSL_set_verify(s.get(), SSL_VERIFY_PEER, nullptr);
	if (SSL_connect(s.get()) <= 0)
	{
		fprintf(stderr, "client: SSL_connect failed\n");
		ERR_print_errors_fp(stderr);
		close(fd); return 1;
	}

	// Build and send BIRTH.
	std::vector<uint8_t> nonce;
	TLSMakeNonce(nonce);
	std::vector<uint8_t> payload;
	auto berr = TLSBuildBirth(identity, NowMs(), nonce, "BCD", client_key_path, payload);
	if (berr != EBirthError::Ok)
	{
		fprintf(stderr, "client: BuildBirth failed (%u)\n", static_cast<unsigned>(berr));
		close(fd); return 1;
	}
	if (!WriteFrame(s.get(), payload))
	{
		fprintf(stderr, "client: WriteFrame(BIRTH) failed\n");
		close(fd); return 1;
	}

	// Read ACCEPT.
	std::vector<uint8_t> accept_payload;
	auto ferr = ReadFrame(s.get(), accept_payload);
	if (ferr != EFrameError::Ok)
	{
		fprintf(stderr, "client: ReadFrame failed (%u)\n", static_cast<unsigned>(ferr));
		close(fd); return 1;
	}
	if (accept_payload.empty()
	    || accept_payload[0] != static_cast<uint8_t>(EMsgType::Accept))
	{
		fprintf(stderr, "client: expected ACCEPT, got msg_type=%u\n",
		        accept_payload.empty() ? 0u : accept_payload[0]);
		close(fd); return 1;
	}

	fprintf(stderr, "  \033[32mclient\033[0m: got ACCEPT for '%s'\n", identity.c_str());

	SSL_shutdown(s.get());
	close(fd);
	return 0;
}

static void TestNetworkFlow()
{
	section("full TLS network flow (parent = server, child = client)");

	const char *tmpdir = "/tmp/mrefd-tls-selftest";
	mkdir(tmpdir, 0700);
	std::string server_cert = std::string(tmpdir) + "/server.crt";
	std::string server_key  = std::string(tmpdir) + "/server.key";
	std::string client_cert = std::string(tmpdir) + "/client.crt";
	std::string client_key  = std::string(tmpdir) + "/client.key";

	PKey spk, cpk;
	Cert sc,  cc;
	EXPECT(MakeIdentity("M17-HOM", server_key, server_cert, spk, sc),
	       "generate server identity failed");
	EXPECT(MakeIdentity("W5GGW-B", client_key, client_cert, cpk, cc),
	       "generate client identity failed");

	// Set up listening socket first so the child can connect without a race.
	int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
	EXPECT(listen_fd >= 0, "socket() failed: %s", strerror(errno));

	int one = 1;
	setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

	struct sockaddr_in sin;
	memset(&sin, 0, sizeof(sin));
	sin.sin_family      = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_port        = 0;             // let the kernel pick
	if (bind(listen_fd, reinterpret_cast<struct sockaddr*>(&sin), sizeof(sin)) < 0)
	{
		EXPECT(false, "bind failed: %s", strerror(errno));
		close(listen_fd);
		return;
	}
	socklen_t sl = sizeof(sin);
	getsockname(listen_fd, reinterpret_cast<struct sockaddr*>(&sin), &sl);
	uint16_t port = ntohs(sin.sin_port);
	listen(listen_fd, 1);

	pid_t child = fork();
	EXPECT(child >= 0, "fork failed: %s", strerror(errno));
	if (child == 0)
	{
		// Child: TLS client.
		close(listen_fd);
		int rc = RunClient(port, server_cert, client_key, "W5GGW-B");
		_exit(rc);
	}

	// Parent: TLS server.
	int server_rc = RunServer(listen_fd, server_cert, server_key, client_cert);
	close(listen_fd);
	EXPECT(server_rc == 0, "server side reported failure");

	int status = 0;
	waitpid(child, &status, 0);
	EXPECT(WIFEXITED(status) && WEXITSTATUS(status) == 0,
	       "client exited with status=%d", WEXITSTATUS(status));

	// Clean up tmp files.
	unlink(server_cert.c_str());
	unlink(server_key.c_str());
	unlink(client_cert.c_str());
	unlink(client_key.c_str());
	rmdir(tmpdir);
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main(int argc, char **argv)
{
	OpenSSL_add_all_algorithms();
	SSL_library_init();

	// Whether to run the fork/TLS network test. Skip via --no-network for
	// environments where loopback binds are blocked (some CI sandboxes).
	bool run_network = true;
	for (int i = 1; i < argc; ++i)
	{
		if (std::string(argv[i]) == "--no-network")
			run_network = false;
	}

	// Persistent tmp identity used by BIRTH tests 3-5 (in-memory keypair
	// written to a tmp file so TLSBuildBirth / TLSVerifyBirth can find it).
	const char *tmpdir = "/tmp/mrefd-tls-selftest-crypto";
	mkdir(tmpdir, 0700);
	std::string key_path  = std::string(tmpdir) + "/id.key";
	std::string cert_path = std::string(tmpdir) + "/id.crt";
	PKey pk;
	Cert cx;
	if (!MakeIdentity("W5GGW-B", key_path, cert_path, pk, cx))
	{
		fprintf(stderr, "setup: failed to create test identity\n");
		return 1;
	}

	TestFramingRoundtrip();
	TestFramingErrors();
	TestBirthRoundtrip(key_path, cert_path);
	TestBirthTamper   (key_path, cert_path);
	TestBirthSkew     (key_path, cert_path);
	if (run_network)
		TestNetworkFlow();

	unlink(key_path.c_str());
	unlink(cert_path.c_str());
	rmdir(tmpdir);

	fprintf(stderr, "\n\033[1msummary:\033[0m \033[32m%d passed\033[0m, "
	        "\033[31m%d failed\033[0m\n", g_pass, g_fail);
	return g_fail == 0 ? 0 : 1;
}
