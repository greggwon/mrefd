//
//  ccallsignlist.cpp
//  mrefd
//
//  Created by Jean-Luc Deltombe (LX3JL) on 30/12/2015.
//  Copyright © 2015 Jean-Luc Deltombe (LX3JL). All rights reserved.
//  Copyright © 2025 Thomas A. Early, N7TAE
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

#include <fstream>
#include <sstream>
#include <string>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <vector>
#include <regex>

#include "configure.h"
#include "interlinks.h"

// the global object
CInterlinks g_Interlinks;
extern CConfigure g_CFG;

CInterlinks::CInterlinks()
{
	m_Filename = nullptr;
	::memset(&m_LastModTime, 0, sizeof(time_t));
}

CInterlinks::~CInterlinks()
{
	std::lock_guard<std::mutex> lock(m_Mutex);
	for (auto &item : m_Imap)
	{
		item.second.reset();
	}
	m_Imap.clear();
}

bool CInterlinks::LoadFromFile(const char *filename)
{
	std::lock_guard<std::mutex> lock(m_Mutex);
	bool ok = false;
	std::string line;

	auto desregex = std::regex("^M17-([A-Z0-9]){3,3}[L]?$", std::regex::extended);

	// and load
	std::ifstream file(filename);
	if ( file.is_open() )
	{
		// empty list
		m_Imap.clear();
		m_TLSPeerRegs.clear();
		m_TLSClientTargets.clear();
		// fill with file content
		unsigned count = 0;
		while (std::getline(file, line))
		{
			count++;
			std::stringstream ss(line);
			std::vector<std::string> v;
			std::string item;
			while (ss >> item)
				v.push_back(item);
			if (0 == v.size() or '#' == v[0][0])
				continue;

			// Detect TLS-form line before any of the legacy uppercase/regex
			// normalization runs, since those would corrupt file paths and
			// non-M17 identity strings.
			bool is_tls = false;
			for (const auto &tok : v)
			{
				if (tok.compare(0, 4, "key:")        == 0 ||
				    tok.compare(0, 4, "tls:")        == 0 ||
				    tok.compare(0, 11, "servercert:") == 0)
				{
					is_tls = true;
					break;
				}
			}
			if (is_tls)
			{
				ParseTLSLine(v, count);
				continue;
			}

			// make sure the callsign and modules are uppercase
			ToUpper(v[0]);        // the first word
			ToUpper(*v.rbegin()); // the last word
			// check for self-linking
			if (std::string::npos != v[0].find(g_CFG.GetCallsign()))
			{
				std::cerr << m_Filename << " line #" << count << ": Self linking is not allowed! You cannot use " << v[0] << std::endl;
				continue;
			}
			if (not std::regex_match(v[0], desregex))
			{
				std::cerr << m_Filename << " line #" << count << ": malformed reflect :" << v[0] << std::endl;
				continue;
			}

			bool islegacy = false;

			if (v[0].size() > 7)
			{
				islegacy = true;
				v[0].resize(7);
			}

			switch(v.size())
			{
			default:
				std::cerr << m_Filename << " line #" << count << ": Bad input line in " << filename << ": " << line << std::endl;
				break;
			case 2:	// only for DHT-enabled systems
#ifdef NO_DHT
				std::cout << "ERROR: You haven't enabled DHT support, so you can't connect to " << v[0] << " with just two paramters" << std::endl;
#else
				Emplace(v[0], v[1]);
#endif
				break;
			case 3:	// supply the default connection port
				Emplace(v[0], v[2], v[1], 17000u, islegacy);
				break;
			case 4:
				uint16_t port = std::stoul(v[2]);
				if (port < 1024u or port > 49000u)
				{
					std::cout << m_Filename << " line #" << count << ": Resetting port for " << v[0] << " from " << v[2] << " to 17000" << std::endl;
					port = 17000u;
				}
				Emplace(v[0], v[3], v[1], port, islegacy);
				break;
			}
		}
		// close file
		file.close();

		// keep file path
		m_Filename = filename;

		// update time
		GetLastModTime(&m_LastModTime);

		// and done
		ok = true;
		std::cout << "Gatekeeper loaded " << m_Imap.size() << " UDP interlink lines"
		          << " (+" << m_TLSPeerRegs.size() << " TLS peer registrations, "
		          << m_TLSClientTargets.size() << " TLS client targets)"
		          << " from " << filename << std::endl;
	}
	else
	{
		std::cout << "Gatekeeper cannot find " << filename <<  std::endl;
	}

	return ok;
}

// Parse a TLS-form line. The token vector is one of:
//
//   Home-side (accept incoming):
//       IDENT  MODS  key:/path/to/peer.pem
//
//   Field-side (initiate outbound):
//       IDENT  MODS  tls:host:port  servercert:/path/to/server.pem
//
// where IDENT is "callsign-module" (e.g. "W5GGW-B") and MODS is a string
// of uppercase A-Z letters. Token order is not fixed; we sniff each token
// for its role by prefix.
void CInterlinks::ParseTLSLine(const std::vector<std::string> &tokens, unsigned line_no)
{
	std::string identity, modules, keyfile, tls_endpoint, servercert;

	for (const auto &tok : tokens)
	{
		if (tok.compare(0, 4, "key:") == 0)
			keyfile = tok.substr(4);
		else if (tok.compare(0, 4, "tls:") == 0)
			tls_endpoint = tok.substr(4);
		else if (tok.compare(0, 11, "servercert:") == 0)
			servercert = tok.substr(11);
		else if (identity.empty())
			identity = tok;
		else if (modules.empty())
			modules = tok;
		// silently ignore trailing tokens that don't match; keeps future
		// additions backwards-compatible.
	}

	// Uppercase identity's callsign portion (before the '-') and modules.
	// The keyfile / tls: / servercert: values are left as-is.
	ToUpper(identity);
	ToUpper(modules);

	if (identity.empty() || modules.empty())
	{
		std::cerr << m_Filename << " line #" << line_no
		          << ": TLS entry missing identity or modules" << std::endl;
		return;
	}

	// Basic identity shape: at least one letter/digit, a single '-', at
	// least one letter/digit after. Callers still validate the full form
	// on the wire in TLSBuildBirth / ParseBirth.
	auto dash = identity.find('-');
	if (dash == std::string::npos || dash == 0 || dash == identity.size() - 1)
	{
		std::cerr << m_Filename << " line #" << line_no
		          << ": TLS identity '" << identity
		          << "' is not in 'callsign-module' shape" << std::endl;
		return;
	}

	if (!keyfile.empty() && tls_endpoint.empty())
	{
		// Home-side registration
		STLSPeerReg reg{identity, modules, keyfile};
		m_TLSPeerRegs.push_back(std::move(reg));
	}
	else if (!tls_endpoint.empty() && keyfile.empty())
	{
		// Field-side outbound target. Split tls_endpoint into host + port.
		std::string host = tls_endpoint;
		uint16_t    port = 17000;
		auto colon = tls_endpoint.rfind(':');
		if (colon != std::string::npos && colon != 0
		    && tls_endpoint.find(':') == colon)   // single colon = host:port
		{
			host = tls_endpoint.substr(0, colon);
			try
			{
				port = static_cast<uint16_t>(std::stoul(tls_endpoint.substr(colon + 1)));
			}
			catch (...)
			{
				std::cerr << m_Filename << " line #" << line_no
				          << ": bad port in tls:" << tls_endpoint << std::endl;
				return;
			}
		}
		// IPv6 literals or bracketed forms deferred until we hit one.

		STLSClientTarget tgt;
		tgt.identity   = identity;
		tgt.modules    = modules;
		tgt.host       = host;
		tgt.port       = port;
		tgt.servercert = servercert;
		m_TLSClientTargets.push_back(std::move(tgt));
	}
	else if (!keyfile.empty() && !tls_endpoint.empty())
	{
		std::cerr << m_Filename << " line #" << line_no
		          << ": TLS line mixes both key: and tls: which is not allowed" << std::endl;
	}
	else
	{
		std::cerr << m_Filename << " line #" << line_no
		          << ": TLS line has neither key: nor tls: token" << std::endl;
	}
}

bool CInterlinks::ReloadFromFile(void)
{
	bool ok = false;

	if ( m_Filename !=  nullptr )
	{
		ok = LoadFromFile(m_Filename);
	}
	return ok;
}

bool CInterlinks::NeedReload(void)
{
	bool needReload = false;

	time_t time;
	if ( GetLastModTime(&time) )
	{
		needReload = time != m_LastModTime;
	}
	return needReload;
}

const CInterlink *CInterlinks::Find(const std::string &cs) const
{
	std::lock_guard<std::mutex> lock(m_Mutex);
	auto item = m_Imap.find(cs);
	if (m_Imap.end() == item)
		return nullptr;
	else
		return item->second.get();
}

bool CInterlinks::GetLastModTime(time_t *time)
{
	bool ok = false;

	if ( m_Filename != nullptr )
	{
		struct stat fileStat;
		if( ::stat(m_Filename, &fileStat) != -1 )
		{
			*time = fileStat.st_mtime;
			ok = true;
		}
	}
	return ok;
}

void CInterlinks::ToUpper(std::string &str)
{
	for (auto p=str.begin(); p!=str.end(); p++)
	{
		if (islower(*p))
			*p = toupper(*p);
	}
}

#ifndef NO_DHT
void CInterlinks::Update(const std::string &cs, const std::string &cmods, const std::string &emods, const std::string &ipv4, const std::string &ipv6, uint16_t port, bool islegacy)
{
	std::lock_guard<std::mutex> lock(m_Mutex);
	auto item = m_Imap.find(cs);
	if (m_Imap.end() != item)
	{
		item->second->UpdateItem(cmods, emods, ipv4, ipv6, port, islegacy);
		return;
	}
	std::cerr << "ERROR: Can't Update CInterlinks item '" << cs << "' because it doesn't exist!";
}

void CInterlinks::Emplace(const std::string &cs, const std::string &mods)
{
	auto item = m_Imap.emplace(cs, std::make_unique<CInterlink>(cs, mods));
	if (not item.second)
		std::cout << cs << " was already defined earlier. This will be ignored." << std::endl;
}
#endif

void CInterlinks::Emplace(const std::string &cs, const std::string &mods, const std::string &addr, uint16_t port, bool islegacy)
{
	auto item = m_Imap.emplace(cs, std::make_unique<CInterlink>(cs, mods, addr, port, islegacy));
	if (not item.second)
		std::cout << cs << " was already defined earlier. This will be ignored." << std::endl;
}
