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

#include "birth.h"
#include "framing.h"

#include <cctype>
#include <cstdint>
#include <cstring>
#include <cstdlib>
#include <memory>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/x509.h>

// ---------------------------------------------------------------------------
// RAII wrappers for OpenSSL handles so early returns can't leak.
// ---------------------------------------------------------------------------
namespace
{
	struct FileCloser  { void operator()(FILE *f) const { if (f) fclose(f); } };
	struct EVPKeyFree  { void operator()(EVP_PKEY *k) const { if (k) EVP_PKEY_free(k); } };
	struct EVPCtxFree  { void operator()(EVP_MD_CTX *c) const { if (c) EVP_MD_CTX_free(c); } };
	struct X509Free    { void operator()(X509 *x) const { if (x) X509_free(x); } };

	using FilePtr   = std::unique_ptr<FILE,       FileCloser>;
	using PKeyPtr   = std::unique_ptr<EVP_PKEY,   EVPKeyFree>;
	using CtxPtr    = std::unique_ptr<EVP_MD_CTX, EVPCtxFree>;
	using X509Ptr   = std::unique_ptr<X509,       X509Free>;

	// Serialize a uint64 as 8 big-endian bytes into `out`.
	void PutU64BE(uint64_t v, std::vector<uint8_t> &out)
	{
		for (int i = 7; i >= 0; --i)
			out.push_back(static_cast<uint8_t>((v >> (i * 8)) & 0xFF));
	}

	// Read a uint64 from 8 big-endian bytes at `p`.
	uint64_t GetU64BE(const uint8_t *p)
	{
		uint64_t v = 0;
		for (int i = 0; i < 8; ++i)
			v = (v << 8) | p[i];
		return v;
	}

	// Build the signed data blob: identity || ts_ms(BE) || nonce.
	// Kept in a helper so BuildBirth and VerifyBirth agree byte-for-byte.
	std::vector<uint8_t> BuildSignedData(const std::string &identity,
	                                     uint64_t ts_ms,
	                                     const std::vector<uint8_t> &nonce)
	{
		std::vector<uint8_t> signed_data;
		signed_data.reserve(identity.size() + 8 + nonce.size());
		signed_data.insert(signed_data.end(), identity.begin(), identity.end());
		PutU64BE(ts_ms, signed_data);
		signed_data.insert(signed_data.end(), nonce.begin(), nonce.end());
		return signed_data;
	}

	// Load an Ed25519 private key from a PEM file.
	PKeyPtr LoadPrivateKeyPem(const std::string &path)
	{
		FilePtr fp(fopen(path.c_str(), "r"));
		if (!fp)
			return {};
		PKeyPtr key(PEM_read_PrivateKey(fp.get(), nullptr, nullptr, nullptr));
		return key;
	}

	// Load an Ed25519 public key from a PEM file. The file may contain
	// either a bare "-----BEGIN PUBLIC KEY-----" block or a full X.509
	// certificate (typical for our peer registry). Try cert first, then
	// fall back to raw pubkey.
	PKeyPtr LoadPublicKeyPem(const std::string &path)
	{
		FilePtr fp(fopen(path.c_str(), "r"));
		if (!fp)
			return {};

		// Try X.509 cert first.
		X509Ptr cert(PEM_read_X509(fp.get(), nullptr, nullptr, nullptr));
		if (cert)
			return PKeyPtr(X509_get_pubkey(cert.get()));

		// Rewind and try bare public key.
		if (0 != fseek(fp.get(), 0, SEEK_SET))
			return {};
		return PKeyPtr(PEM_read_PUBKEY(fp.get(), nullptr, nullptr, nullptr));
	}
} // anonymous namespace

// ---------------------------------------------------------------------------
// TLSMakeNonce
// ---------------------------------------------------------------------------
bool TLSMakeNonce(std::vector<uint8_t> &out)
{
	out.assign(BIRTH_NONCE_BYTES, 0);
	return 1 == RAND_bytes(out.data(), static_cast<int>(out.size()));
}

// ---------------------------------------------------------------------------
// TLSBuildBirth
// ---------------------------------------------------------------------------
EBirthError TLSBuildBirth(const std::string &identity,
                          uint64_t timestamp_ms,
                          const std::vector<uint8_t> &nonce,
                          const std::string &modules,
                          const std::string &private_key_pem_path,
                          std::vector<uint8_t> &out)
{
	if (identity.empty() || identity.size() > BIRTH_MAX_IDENTITY)
		return EBirthError::IdentityTooLong;
	if (modules.size() > BIRTH_MAX_MODULES)
		return EBirthError::ModulesTooLong;
	if (nonce.size() != BIRTH_NONCE_BYTES)
		return EBirthError::NonceLengthInvalid;

	// Verify shape: must contain exactly one '-' and only allowed chars.
	{
		auto dash = identity.find('-');
		if (dash == std::string::npos
		    || dash == 0
		    || dash == identity.size() - 1
		    || identity.find('-', dash + 1) != std::string::npos)
			return EBirthError::IdentityInvalid;
	}

	// Load key + sign.
	PKeyPtr key = LoadPrivateKeyPem(private_key_pem_path);
	if (!key)
		return EBirthError::KeyLoadFailed;

	CtxPtr ctx(EVP_MD_CTX_new());
	if (!ctx)
		return EBirthError::SignFailed;

	// Ed25519 uses PureEdDSA - no hash algorithm passed to DigestSignInit.
	if (1 != EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()))
		return EBirthError::SignFailed;

	auto signed_data = BuildSignedData(identity, timestamp_ms, nonce);

	size_t sig_len = 0;
	if (1 != EVP_DigestSign(ctx.get(),
	                        nullptr, &sig_len,
	                        signed_data.data(), signed_data.size()))
		return EBirthError::SignFailed;
	if (sig_len != BIRTH_ED25519_SIG_LEN)
		return EBirthError::SignFailed;

	std::vector<uint8_t> signature(sig_len);
	if (1 != EVP_DigestSign(ctx.get(),
	                        signature.data(), &sig_len,
	                        signed_data.data(), signed_data.size()))
		return EBirthError::SignFailed;

	// Assemble the payload.
	out.clear();
	out.reserve(1 + 1 + identity.size() + 8 + nonce.size()
	            + 1 + signature.size() + 1 + modules.size());

	out.push_back(static_cast<uint8_t>(EMsgType::Birth));
	out.push_back(static_cast<uint8_t>(identity.size()));
	out.insert(out.end(), identity.begin(), identity.end());
	PutU64BE(timestamp_ms, out);
	out.insert(out.end(), nonce.begin(), nonce.end());
	out.push_back(static_cast<uint8_t>(signature.size()));
	out.insert(out.end(), signature.begin(), signature.end());
	out.push_back(static_cast<uint8_t>(modules.size()));
	out.insert(out.end(), modules.begin(), modules.end());

	return EBirthError::Ok;
}

// ---------------------------------------------------------------------------
// TLSParseBirth
// ---------------------------------------------------------------------------
EBirthError TLSParseBirth(const std::vector<uint8_t> &payload,
                          SBirthMsg &msg)
{
	if (payload.empty())
		return EBirthError::Truncated;
	if (payload[0] != static_cast<uint8_t>(EMsgType::Birth))
		return EBirthError::NotBirthMessage;

	size_t off = 1;
	auto need = [&](size_t n) -> bool {
		return off + n <= payload.size();
	};

	if (!need(1))                    return EBirthError::Truncated;
	uint8_t id_len = payload[off++];
	if (id_len == 0 || id_len > BIRTH_MAX_IDENTITY)
		return EBirthError::IdentityTooLong;
	if (!need(id_len))               return EBirthError::Truncated;
	msg.identity.assign(reinterpret_cast<const char*>(&payload[off]), id_len);
	off += id_len;

	if (!need(8))                    return EBirthError::Truncated;
	msg.timestamp_ms = GetU64BE(&payload[off]);
	off += 8;

	if (!need(BIRTH_NONCE_BYTES))    return EBirthError::Truncated;
	msg.nonce.assign(&payload[off], &payload[off + BIRTH_NONCE_BYTES]);
	off += BIRTH_NONCE_BYTES;

	if (!need(1))                    return EBirthError::Truncated;
	uint8_t sig_len = payload[off++];
	if (sig_len != BIRTH_ED25519_SIG_LEN)
		return EBirthError::SignatureLengthInvalid;
	if (!need(sig_len))              return EBirthError::Truncated;
	msg.signature.assign(&payload[off], &payload[off + sig_len]);
	off += sig_len;

	if (!need(1))                    return EBirthError::Truncated;
	uint8_t mod_len = payload[off++];
	if (mod_len > BIRTH_MAX_MODULES)
		return EBirthError::ModulesTooLong;
	if (!need(mod_len))              return EBirthError::Truncated;
	msg.modules.assign(reinterpret_cast<const char*>(&payload[off]), mod_len);
	// off += mod_len; // trailing; ignored

	return EBirthError::Ok;
}

// ---------------------------------------------------------------------------
// TLSVerifyBirth
// ---------------------------------------------------------------------------
EBirthError TLSVerifyBirth(const SBirthMsg &msg,
                           const std::string &peer_public_key_pem_path,
                           uint64_t timestamp_now_ms,
                           uint32_t skew_seconds)
{
	if (msg.nonce.size() != BIRTH_NONCE_BYTES)
		return EBirthError::NonceLengthInvalid;
	if (msg.signature.size() != BIRTH_ED25519_SIG_LEN)
		return EBirthError::SignatureLengthInvalid;

	// Timestamp skew check first - it's cheap and catches the replay case
	// before we do any crypto work.
	const uint64_t skew_ms = static_cast<uint64_t>(skew_seconds) * 1000ULL;
	uint64_t delta_ms;
	if (msg.timestamp_ms > timestamp_now_ms)
		delta_ms = msg.timestamp_ms - timestamp_now_ms;
	else
		delta_ms = timestamp_now_ms - msg.timestamp_ms;
	if (delta_ms > skew_ms)
		return EBirthError::TimestampOutOfWindow;

	PKeyPtr key = LoadPublicKeyPem(peer_public_key_pem_path);
	if (!key)
		return EBirthError::KeyLoadFailed;

	CtxPtr ctx(EVP_MD_CTX_new());
	if (!ctx)
		return EBirthError::SignatureInvalid;

	if (1 != EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()))
		return EBirthError::SignatureInvalid;

	auto signed_data = BuildSignedData(msg.identity, msg.timestamp_ms, msg.nonce);

	int rc = EVP_DigestVerify(ctx.get(),
	                          msg.signature.data(), msg.signature.size(),
	                          signed_data.data(),   signed_data.size());
	if (rc == 1)
		return EBirthError::Ok;
	return EBirthError::SignatureInvalid;
}

// ---------------------------------------------------------------------------
// Certificate identity
// ---------------------------------------------------------------------------
bool TLSCertIdentity(const void *x509,
                     std::string &callsign,
                     std::string &spki_fingerprint)
{
	X509 *cert = const_cast<X509 *>(static_cast<const X509 *>(x509));
	if (cert == nullptr)
		return false;

	// Subject CN.
	char cn[128] = {0};
	X509_NAME *subj = X509_get_subject_name(cert);
	if (subj == nullptr
	    || X509_NAME_get_text_by_NID(subj, NID_commonName, cn, sizeof(cn)) <= 0)
		return false;
	callsign = cn;
	for (auto &c : callsign)
		c = static_cast<char>(toupper(static_cast<unsigned char>(c)));

	// SHA-256 over the DER SubjectPublicKeyInfo, base64-encoded. Matches
	//   openssl x509 -pubkey -noout | openssl pkey -pubin -outform DER
	//     | openssl dgst -sha256 -binary | openssl base64
	unsigned char *der = nullptr;
	int der_len = i2d_PUBKEY(X509_get0_pubkey(cert), &der);
	if (der_len <= 0)
		return false;
	unsigned char digest[SHA256_DIGEST_LENGTH];
	SHA256(der, static_cast<size_t>(der_len), digest);
	OPENSSL_free(der);

	unsigned char b64[4 * ((SHA256_DIGEST_LENGTH + 2) / 3) + 1] = {0};
	EVP_EncodeBlock(b64, digest, SHA256_DIGEST_LENGTH);
	spki_fingerprint = reinterpret_cast<char *>(b64);
	return true;
}

bool TLSCertIdentityFromFile(const std::string &cert_pem_path,
                             std::string &callsign,
                             std::string &spki_fingerprint)
{
	FilePtr fp(fopen(cert_pem_path.c_str(), "r"));
	if (!fp)
		return false;
	X509Ptr cert(PEM_read_X509(fp.get(), nullptr, nullptr, nullptr));
	if (!cert)
		return false;
	return TLSCertIdentity(cert.get(), callsign, spki_fingerprint);
}

bool TLSIsBareCallsign(const std::string &cs)
{
	if (cs.size() < 3 || cs.size() > BIRTH_MAX_IDENTITY - 2)
		return false;
	for (char c : cs)
	{
		if (!((c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '/'))
			return false;
	}
	return true;
}

bool TLSSplitIdentity(const std::string &identity,
                      std::string &callsign,
                      char &module)
{
	auto dash = identity.find('-');
	if (dash == std::string::npos || dash + 2 != identity.size())
		return false;
	callsign = identity.substr(0, dash);
	module   = identity[dash + 1];
	return TLSIsBareCallsign(callsign) && module >= 'A' && module <= 'Z';
}
