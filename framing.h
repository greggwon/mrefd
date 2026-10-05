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

// Wire framing for the TLS interlink protocol. Every message on the TLS
// session is a 32-bit big-endian header followed by a payload:
//
//   byte 0     : version              (1 byte)
//   byte 1 hi4 : reserved             (must be zero on transmit; ignored on rx)
//   byte 1 lo4 : length[19:16]        (high 4 bits of a 20-bit length)
//   byte 2..3  : length[15:0]         (low 16 bits of the length, big-endian)
//   payload    : (length bytes)
//
// The 20-bit length field caps a single frame at ~1 MB, well above any
// realistic M17 packet.
//
// The first byte of every payload is a message-type identifier (see
// EMsgType) which selects the per-type parser.

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>

// Protocol version emitted by this build. Peers negotiating a session
// exchange one BIRTH/ACCEPT round with FRAME_VERSION; a mismatch is a
// hard failure (design: no fallback).
constexpr uint8_t  FRAME_VERSION      = 0x01;

// 20-bit length field maximum.
constexpr uint32_t FRAME_MAX_PAYLOAD  = (1u << 20) - 1;

// Bytes consumed by the header (version + reserved-nibble + length).
constexpr size_t   FRAME_HEADER_BYTES = 4;

enum class EFrameError : uint8_t
{
	Ok = 0,
	ShortRead,           // input has fewer bytes than the frame requires
	BadVersion,          // version byte does not match this build
	ReservedBitsSet,     // high nibble of byte 1 is non-zero
	PayloadTooLarge,     // length exceeds FRAME_MAX_PAYLOAD (should never happen
	                     // because we mask, but reserved for future extensions)
};

struct SFrameHeader
{
	uint8_t  version;
	uint32_t length;         // valid range: 0 .. FRAME_MAX_PAYLOAD
};

// Message-type identifiers (first byte of every payload).
enum class EMsgType : uint8_t
{
	Birth      = 0x01,
	Accept     = 0x02,
	Reject     = 0x03,
	Ping       = 0x10,
	Pong       = 0x11,
	M17Stream  = 0x20,
	M17Packet  = 0x21,
	Disconnect = 0x7F,
};

// Serialize a payload as a full frame. Appends header + payload bytes to
// `out`. Payload must fit within FRAME_MAX_PAYLOAD or PayloadTooLarge is
// returned and `out` is not modified.
EFrameError TLSSerializeFrame(uint8_t version,
                              const std::vector<uint8_t> &payload,
                              std::vector<uint8_t> &out);

// Try to parse one frame from the start of the input buffer.
//
// On Ok: `header` describes the frame, `payload_out` is assigned the
//        payload bytes (copied, not aliased), and `bytes_consumed` is set
//        to (FRAME_HEADER_BYTES + header.length).
// On ShortRead: outputs are unchanged; caller should wait for more data.
// On any other error: outputs are unchanged and the session should be torn
//        down; the peer speaks an incompatible protocol.
EFrameError TLSParseFrame(const uint8_t *input,
                          size_t input_size,
                          SFrameHeader &header,
                          std::vector<uint8_t> &payload_out,
                          size_t &bytes_consumed);
