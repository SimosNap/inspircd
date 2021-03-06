/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2015 Daniel Vassdal <shutter@canternet.org>
 *   Copyright (C) 2013, 2017-2019 Sadie Powell <sadie@witchery.services>
 *   Copyright (C) 2012-2015 Attila Molnar <attilamolnar@hush.com>
 *   Copyright (C) 2012, 2019 Robby <robby@chatbelgie.be>
 *   Copyright (C) 2009-2010 Daniel De Graaf <danieldg@inspircd.org>
 *   Copyright (C) 2007-2008 Robin Burchell <robin+git@viroteck.net>
 *   Copyright (C) 2007 Dennis Friis <peavey@inspircd.org>
 *   Copyright (C) 2005, 2007-2008, 2010 Craig Edwards <brain@inspircd.org>
 *
 * This file is part of InspIRCd.  InspIRCd is free software: you can
 * redistribute it and/or modify it under the terms of the GNU General Public
 * License as published by the Free Software Foundation, version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */


#include "inspircd.h"
#include "modules/sql.h"
#include "modules/hash.h"
#include "modules/ssl.h"

enum AuthState {
	AUTH_STATE_NONE = 0,
	AUTH_STATE_BUSY = 1,
	AUTH_STATE_FAIL = 2
};

class AuthQuery : public SQL::Query
{
 public:
	const std::string uid;
	IntExtItem& pendingExt;
	bool verbose;
	const std::string& kdf;
	const std::string& pwcolumn;

	AuthQuery(Module* me, const std::string& u, IntExtItem& e, bool v, const std::string& kd, const std::string& pwcol)
		: SQL::Query(me)
		, uid(u)
		, pendingExt(e)
		, verbose(v)
		, kdf(kd)
		, pwcolumn(pwcol)
	{
	}

	void OnResult(SQL::Result& res) override
	{
		LocalUser* user = IS_LOCAL(ServerInstance->Users.FindUUID(uid));
		if (!user)
			return;

		if (res.Rows())
		{
			if (!kdf.empty())
			{
				HashProvider* hashprov = ServerInstance->Modules.FindDataService<HashProvider>("hash/" + kdf);
				if (!hashprov)
				{
					if (verbose)
						ServerInstance->SNO.WriteGlobalSno('a', "Forbidden connection from %s (a provider for %s was not loaded)", user->GetFullRealHost().c_str(), kdf.c_str());
					pendingExt.Set(user, AUTH_STATE_FAIL);
					return;
				}

				size_t colindex = 0;
				if (!pwcolumn.empty() && !res.HasColumn(pwcolumn, colindex))
				{
					if (verbose)
						ServerInstance->SNO.WriteGlobalSno('a', "Forbidden connection from %s (the column specified (%s) was not returned)", user->GetFullRealHost().c_str(), pwcolumn.c_str());
					pendingExt.Set(user, AUTH_STATE_FAIL);
					return;
				}

				SQL::Row row;
				while (res.GetRow(row))
				{
					if (row[colindex].has_value() && hashprov->Compare(user->password, *row[colindex]))
					{
						pendingExt.Set(user, AUTH_STATE_NONE);
						return;
					}
				}

				if (verbose)
					ServerInstance->SNO.WriteGlobalSno('a', "Forbidden connection from %s (password from the SQL query did not match the user provided password)", user->GetFullRealHost().c_str());
				pendingExt.Set(user, AUTH_STATE_FAIL);
				return;
			}

			pendingExt.Set(user, AUTH_STATE_NONE);
		}
		else
		{
			if (verbose)
				ServerInstance->SNO.WriteGlobalSno('a', "Forbidden connection from %s (SQL query returned no matches)", user->GetFullRealHost().c_str());
			pendingExt.Set(user, AUTH_STATE_FAIL);
		}
	}

	void OnError(SQL::Error& error) override
	{
		User* user = ServerInstance->Users.Find(uid);
		if (!user)
			return;
		pendingExt.Set(user, AUTH_STATE_FAIL);
		if (verbose)
			ServerInstance->SNO.WriteGlobalSno('a', "Forbidden connection from %s (SQL query failed: %s)", user->GetFullRealHost().c_str(), error.ToString());
	}
};

class ModuleSQLAuth : public Module
{
	IntExtItem pendingExt;
	dynamic_reference<SQL::Provider> SQL;
	UserCertificateAPI sslapi;

	std::string freeformquery;
	std::string killreason;
	std::string allowpattern;
	bool verbose;
	std::vector<std::string> hash_algos;
	std::string kdf;
	std::string pwcolumn;

 public:
	ModuleSQLAuth()
		: Module(VF_VENDOR, "Allows connecting users to be authenticated against an arbitrary SQL table.")
		, pendingExt(this, "sqlauth-wait", ExtensionItem::EXT_USER)
		, SQL(this, "SQL")
		, sslapi(this)
	{
	}

	void ReadConfig(ConfigStatus& status) override
	{
		auto conf = ServerInstance->Config->ConfValue("sqlauth");
		std::string dbid = conf->getString("dbid");
		if (dbid.empty())
			SQL.SetProvider("SQL");
		else
			SQL.SetProvider("SQL/" + dbid);
		freeformquery = conf->getString("query");
		killreason = conf->getString("killreason");
		allowpattern = conf->getString("allowpattern");
		verbose = conf->getBool("verbose");
		kdf = conf->getString("kdf");
		pwcolumn = conf->getString("column");

		hash_algos.clear();
		irc::commasepstream algos(conf->getString("hash", "md5,sha256"));
		std::string algo;
		while (algos.GetToken(algo))
			hash_algos.push_back(algo);
	}

	ModResult OnUserRegister(LocalUser* user) override
	{
		// Note this is their initial (unresolved) connect block
		std::shared_ptr<ConfigTag> tag = user->GetClass()->config;
		if (!tag->getBool("usesqlauth", true))
			return MOD_RES_PASSTHRU;

		if (!allowpattern.empty() && InspIRCd::Match(user->nick,allowpattern))
			return MOD_RES_PASSTHRU;

		if (pendingExt.Get(user))
			return MOD_RES_PASSTHRU;

		if (!SQL)
		{
			ServerInstance->SNO.WriteGlobalSno('a', "Forbidden connection from %s (SQL database not present)", user->GetFullRealHost().c_str());
			ServerInstance->Users.QuitUser(user, killreason);
			return MOD_RES_PASSTHRU;
		}

		pendingExt.Set(user, AUTH_STATE_BUSY);

		SQL::ParamMap userinfo;
		SQL::PopulateUserInfo(user, userinfo);
		userinfo["pass"] = user->password;
		userinfo["certfp"] = sslapi ? sslapi->GetFingerprint(user) : "";

		for (const auto& algo : hash_algos)
		{
			HashProvider* hashprov = ServerInstance->Modules.FindDataService<HashProvider>("hash/" + algo);
			if (hashprov && !hashprov->IsKDF())
				userinfo[algo + "pass"] = hashprov->Generate(user->password);
		}

		SQL->Submit(new AuthQuery(this, user->uuid, pendingExt, verbose, kdf, pwcolumn), freeformquery, userinfo);

		return MOD_RES_PASSTHRU;
	}

	ModResult OnCheckReady(LocalUser* user) override
	{
		switch (pendingExt.Get(user))
		{
			case AUTH_STATE_NONE:
				return MOD_RES_PASSTHRU;
			case AUTH_STATE_BUSY:
				return MOD_RES_DENY;
			case AUTH_STATE_FAIL:
				ServerInstance->Users.QuitUser(user, killreason);
				return MOD_RES_DENY;
		}
		return MOD_RES_PASSTHRU;
	}
};

MODULE_INIT(ModuleSQLAuth)
