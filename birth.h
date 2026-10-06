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

// BIRTH message (design doc §3.3): the first message a field reflector
// sends over the TLS interlink session. Authenticated with an Ed25519
// signature that covers identity || timestamp_ms (BE 8 bytes) || nonce.
// The home verifies the signature against the peer's registered public
// key, checks the timestamp against a clock-skew window, and installs a
// peer entry using the source address of the incoming TCP session.
//
// Wire layout of the payload (msg_type = 0x01 = BIRTH):
//
//     +-------------+---------------------------------------------+
//     |  0x01       |  msg_type                     (uint8)       |
//     +-------------+---------------------------------------------+
//     |  id_len     |  identity length, bytes       (uint8)       |
//     +-------------+---------------------------------------------+
//     |  identity   |  ASCII "callsign-<module>"                  |
//     +-------------+---------------------------------------------+
//     |  ts_ms      |  Unix time, milliseconds      (uint64 BE)   |
//     +-------------+---------------------------------------------+
//     |  nonce      |  32 bytes of random                         |
//     +-------------+---------------------------------------------+
//     |  sig_len    |  signature length, bytes      (uint8)       |
//     |             |  Ed25519 => 64                              |
//     +-------------+---------------------------------------------+
//     |  signature  |  Ed25519 signature over                     |
//     |             |    identity || ts_ms || nonce               |
//     +-------------+---------------------------------------------+
//     |  mod_len    |  modules string length        (uint8)       |
//     +-------------+---------------------------------------------+
//     |  modules    |  ASCII string, requested shared modules     |
//     +-------------+---------------------------------------------+

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>

// Sizes fixed by the protocol.
constexpr size_t BIRTH_NONCE_BYTES     = 32;
constexpr size_t BIRTH_ED25519_SIG_LEN = 64;
constexpr size_t BIRTH_MAX_IDENTITY    = 32;   // callsign-<module> is short
constexpr size_t BIRTH_MAX_MODULES     = 26;   // A..Z max

struct SBirthMsg
{
	std::string          identity;      // "<cert CN>-<module>", e.g. "W5GGW-B"
	uint64_t             timestamp_ms;  // ms since Unix epoch
	std::vector<uint8_t> nonce;         // size BIRTH_NONCE_BYTES
	std::vector<uint8_t> signature;     // size BIRTH_ED25519_SIG_LEN
	std::string          modules;       // the one module asserted, e.g. "B"
};

enum class EBirthError : uint8_t
{
	Ok = 0,
	NotBirthMessage,          // payload[0] != EMsgType::Birth
	Truncated,                // payload ended before a required field
	IdentityTooLong,
	IdentityInvalid,          // wrong shape (missing '-', bad chars)
	ModulesTooLong,
	NonceLengthInvalid,       // must be BIRTH_NONCE_BYTES
	SignatureLengthInvalid,   // must be BIRTH_ED25519_SIG_LEN
	KeyLoadFailed,            // OpenSSL couldn't parse the supplied key blob
	SignFailed,               // OpenSSL signing operation failed
	SignatureInvalid,         // signature did not verify against pubkey
	TimestampOutOfWindow,     // timestamp outside allowed skew window
};

// Serialize a signed BIRTH payload. Signs identity || ts_ms (8-byte BE) ||
// nonce with the Ed25519 private key at `private_key_pem_path`, then
// assembles the full payload (starting with msg_type = 0x01).
//
// Returns Ok on success, KeyLoadFailed if the key file can't be loaded,
// SignFailed if the signing operation fails, and length errors if the
// input fields are out of range.
EBirthError TLSBuildBirth(const std::string &identity,
                          uint64_t timestamp_ms,
                          const std::vector<uint8_t> &nonce,
                          const std::string &modules,
                          const std::string &private_key_pem_path,
                          std::vector<uint8_t> &out);

// Parse a BIRTH payload. `payload` is the frame body starting with the
// msg_type byte. Fills `msg` on success. Does not verify the signature -
// call TLSVerifyBirth for that.
EBirthError TLSParseBirth(const std::vector<uint8_t> &payload,
                          SBirthMsg &msg);

// Verify a parsed BIRTH against a public key and a clock-skew window.
//
// `peer_public_key_pem_path` is the path to the PEM-encoded X.509 cert
// (or bare PUBLIC KEY) for the peer whose identity matches `msg.identity`.
// The signed data is reconstructed as identity || ts_ms (8-byte BE) ||
// nonce and passed to Ed25519 verify.
//
// `timestamp_now_ms` is the caller's current time in ms; `skew_seconds`
// is the allowed clock-skew window on either side of it.
EBirthError TLSVerifyBirth(const SBirthMsg &msg,
                           const std::string &peer_public_key_pem_path,
                           uint64_t timestamp_now_ms,
                           uint32_t skew_seconds);

// Fill `out` with BIRTH_NONCE_BYTES of cryptographically random data.
// Returns true on success. Wraps OpenSSL's RAND_bytes.
bool TLSMakeNonce(std::vector<uint8_t> &out);

// ---------------------------------------------------------------------------
// Certificate identity
//
// The key decides who a peer is. An operator holds ONE certificate whose
// Subject CN is their bare callsign (e.g. "W5GGW"); every node they run
// presents that same certificate and asserts, per connection, the single
// module it is linking - the way a radio picks a module when connecting to a
// reflector. The node's name on the far end is therefore "<CN>-<module>"
// (e.g. "W5GGW-B"), where the callsign half always comes from the
// certificate and never from what the peer claims.
// ---------------------------------------------------------------------------

// Read the Subject CN and the SPKI SHA-256 fingerprint (base64, the same
// form scripts/tls-genkey.sh prints) from a PEM X.509 certificate file.
// Returns false if the file can't be read or has no CN.
bool TLSCertIdentityFromFile(const std::string &cert_pem_path,
                             std::string &callsign,
                             std::string &spki_fingerprint);

// Same, for an in-memory certificate (e.g. the one a peer presented in the
// TLS handshake). `x509` is an X509*; typed void* so callers that don't
// otherwise include OpenSSL headers can use this declaration.
bool TLSCertIdentity(const void *x509,
                     std::string &callsign,
                     std::string &spki_fingerprint);

// True if `cs` is a bare callsign: A-Z, 0-9 and '/', at least 3 chars, no
// '-'. Expects upper case.
bool TLSIsBareCallsign(const std::string &cs);

// Split a BIRTH identity "<callsign>-<module>" into its parts. Returns false
// unless it is exactly a bare callsign, one '-', and one letter A-Z.
bool TLSSplitIdentity(const std::string &identity,
                      std::string &callsign,
                      char &module);
