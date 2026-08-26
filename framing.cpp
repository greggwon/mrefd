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

#include "framing.h"

EFrameError TLSSerializeFrame(uint8_t version,
                              const std::vector<uint8_t> &payload,
                              std::vector<uint8_t> &out)
{
	if (payload.size() > FRAME_MAX_PAYLOAD)
		return EFrameError::PayloadTooLarge;

	const uint32_t len = static_cast<uint32_t>(payload.size());

	out.reserve(out.size() + FRAME_HEADER_BYTES + payload.size());
	out.push_back(version);
	// byte 1: reserved nibble (0) | length[19:16]
	out.push_back(static_cast<uint8_t>((len >> 16) & 0x0F));
	out.push_back(static_cast<uint8_t>((len >>  8) & 0xFF));
	out.push_back(static_cast<uint8_t>( len        & 0xFF));
	out.insert(out.end(), payload.begin(), payload.end());
	return EFrameError::Ok;
}

EFrameError TLSParseFrame(const uint8_t *input,
                          size_t input_size,
                          SFrameHeader &header,
                          std::vector<uint8_t> &payload_out,
                          size_t &bytes_consumed)
{
	if (input_size < FRAME_HEADER_BYTES)
		return EFrameError::ShortRead;

	const uint8_t version   = input[0];
	const uint8_t reserved  = static_cast<uint8_t>((input[1] >> 4) & 0x0F);
	const uint32_t length   =
		(static_cast<uint32_t>(input[1] & 0x0F) << 16) |
		(static_cast<uint32_t>(input[2])        <<  8) |
		 static_cast<uint32_t>(input[3]);

	if (version != FRAME_VERSION)
		return EFrameError::BadVersion;
	if (reserved != 0)
		return EFrameError::ReservedBitsSet;

	// length is 20 bits by construction so it cannot exceed FRAME_MAX_PAYLOAD.

	if (input_size < FRAME_HEADER_BYTES + length)
		return EFrameError::ShortRead;

	header.version = version;
	header.length  = length;
	payload_out.assign(input + FRAME_HEADER_BYTES,
	                   input + FRAME_HEADER_BYTES + length);
	bytes_consumed = FRAME_HEADER_BYTES + length;
	return EFrameError::Ok;
}
