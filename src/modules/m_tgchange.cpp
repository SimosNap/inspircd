/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2016 Adam <Adam@anope.org>
 *   Copyright (C) 2020 Elizabeth Myers <elizabeth@interlinked.me>
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

/// $ModAuthor: Adam <Adam@anope.org>
/// $ModDesc: Implements "target change" detection to help prevent spam bots
/// $ModDepends: core 4

/*
 * tgchange. Detects users messaging many different targets rapidly.
 * Ported from Charybdis's tgchange.c
 */

#include "inspircd.h"
#include "extension.h"
#include "modules/account.h"
#include <cctype>
#include <functional>
#include <unordered_set>

enum
{
	ERR_TARGCHANGE = 707
};

namespace
{
	unsigned TGCHANGE_NUM;
	unsigned TGCHANGE_REPLY;
	unsigned TGCHANGE_REPEAT;
	unsigned TGCHANGE_MINLENGTH;
	time_t TGCHANGE_REPEATWINDOW;
	bool TGCHANGE_REPEATNOTIFY;
	time_t TGCHANGE_NOTIFYCOOLDOWN;

	// Progressive command penalties.
	time_t TGCHANGE_PENALTY;
	time_t TGCHANGE_PENALTYSTEP;
	unsigned TGCHANGE_MAXWARNINGS;
	time_t TGCHANGE_PENALTYWINDOW;
	time_t TGCHANGE_PENALTYCOOLDOWN;
	bool TGCHANGE_DISCONNECT;
}

typedef void Target;

class TGInfo
{
	time_t last;

	std::deque<Target *> targets;
	std::deque<Target *> reply_targets;

	struct RepeatEntry
	{
		size_t hash;
		size_t length;
		std::string target_uuid;
		time_t timestamp;
	};

	std::deque<RepeatEntry> repeat_history;
	time_t last_repeat_notify;

	std::deque<time_t> penalty_warnings;

	public:
		TGInfo() : last(0), last_repeat_notify(0)
		{
		}

		unsigned RegisterPenaltyViolation()
		{
			const time_t now = ServerInstance->Time();

			// Remove warnings outside the configured time window.
			while (!penalty_warnings.empty() &&
				now - penalty_warnings.front() >= TGCHANGE_PENALTYWINDOW)
			{
				penalty_warnings.pop_front();
			}

			// Respect the current limit after a configuration reload.
			while (penalty_warnings.size() > TGCHANGE_MAXWARNINGS)
			{
				penalty_warnings.pop_front();
			}

			// Do not count multiple violations during cooldown.
			if (!penalty_warnings.empty() &&
				now - penalty_warnings.back() < TGCHANGE_PENALTYCOOLDOWN)
			{
				return 0;
			}

			// Register a new violation.
			penalty_warnings.push_back(now);

			// Keep the warning history bounded.
			if (penalty_warnings.size() > TGCHANGE_MAXWARNINGS)
				penalty_warnings.pop_front();

			return static_cast<unsigned>(penalty_warnings.size());
		}

	bool CheckRepeat(const std::string& message, const std::string& targetuuid, bool& saturated)
	{
		saturated = false;

		if (!TGCHANGE_REPEAT)
			return false;

		// Normalize case and whitespace.
		std::string normalized;
		normalized.reserve(message.size());

		bool space = false;

		for (unsigned char c : message)
		{
			if (std::isspace(c))
			{
				if (!normalized.empty())
					space = true;
				continue;
			}

			if (space)
			{
				normalized.push_back(' ');
				space = false;
			}

			normalized.push_back(static_cast<char>(std::tolower(c)));
		}

		if (normalized.size() < TGCHANGE_MINLENGTH)
			return false;

		const time_t now = ServerInstance->Time();

		// Remove expired entries.
		while (!repeat_history.empty() &&
			now - repeat_history.front().timestamp >= TGCHANGE_REPEATWINDOW)
		{
			repeat_history.pop_front();
		}

		const size_t hash = std::hash<std::string>{}(normalized);

		// Keep only one entry per message and recipient.
		for (auto it = repeat_history.begin(); it != repeat_history.end(); ++it)
		{
			if (it->hash == hash &&
				it->length == normalized.size() &&
				it->target_uuid == targetuuid)
			{
				repeat_history.erase(it);
				break;
			}
		}

		// Do not discard valid entries when history is full.
		if (repeat_history.size() >= 128)
		{
			saturated = true;
			return true;
		}

		// Store the current attempt.
		repeat_history.push_back({
			hash,
			normalized.size(),
			targetuuid,
			now
		});

		// Count distinct recipients of the same message.
		std::unordered_set<std::string> recipients;

		for (const auto& entry : repeat_history)
		{
			if (entry.hash == hash && entry.length == normalized.size())
				recipients.insert(entry.target_uuid);
		}

		return recipients.size() > TGCHANGE_REPEAT;
	}

	bool IsReplyTarget(::Target* target) const
	{
		// Reply exemptions are disabled.
		if (!TGCHANGE_REPLY)
			return false;

		// Only consider entries within the current configured limit.
		unsigned checked = 0;

		for (::Target* reply_target : reply_targets)
		{
			if (checked >= TGCHANGE_REPLY)
				break;

			if (reply_target == target)
				return true;

			++checked;
		}

		return false;
	}

	bool ShouldNotifyRepeat()
	{
		const time_t now = ServerInstance->Time();

		if (last_repeat_notify &&
			now - last_repeat_notify < TGCHANGE_NOTIFYCOOLDOWN)
			return false;

		last_repeat_notify = now;
		return true;
	}

	bool AddTarget(Target* target)
	{
		// Respect the current reply limit after a configuration reload.
		while (reply_targets.size() > TGCHANGE_REPLY)
		{
			reply_targets.pop_back();
		}

		/* already exists? */
		std::deque<Target*>::iterator it = std::find(targets.begin(), targets.end(), target);
		if (it != targets.end())
		{
			/* yes. move it to the beginning */
			targets.erase(it);
			targets.push_front(target);
			return true;
		}

		/* or as a reply target? */
		it = std::find(reply_targets.begin(), reply_targets.end(), target);
		if (it != reply_targets.end())
		{
			reply_targets.erase(it);
			reply_targets.push_front(target);
			return true;
		}

		/* try to clear some old targets */
		time_t t = (ServerInstance->Time() - last) / 60;
		if (t > 0)
		{
			/* clear one target per minute */
			size_t sz = targets.size();
			if (static_cast<size_t>(t) > sz)
				sz = 0;
			else
				sz -= t;

			targets.resize(sz);
			last = ServerInstance->Time();
		}

		if (targets.size() >= TGCHANGE_NUM)
		{
			/* still no free targets? */
			return false;
		}

		/* add new target */
		targets.push_front(target);

		return true;
	}

	void AddReply(User* target)
	{
		// Reply exemptions are disabled.
		if (!TGCHANGE_REPLY)
			return;

		// Respect the current limit after a configuration reload.
		while (reply_targets.size() > TGCHANGE_REPLY)
		{
			reply_targets.pop_back();
		}

		std::deque<Target*>::iterator it = std::find(reply_targets.begin(), reply_targets.end(), target);

		if (it != reply_targets.end())
		{
			// Already exists, move to front.
			reply_targets.erase(it);
		}
		else if (reply_targets.size() >= TGCHANGE_REPLY)
		{
			// List growing too large?
			reply_targets.pop_back();
		}

		reply_targets.push_front(target);
	}

};

class TGExtInfo : public SimpleExtItem<TGInfo>
{
 public:
	TGExtInfo(const std::string& Key, Module* Creator)
		: SimpleExtItem<TGInfo>(Creator, Key, ExtensionType::USER)
	{
	}

	TGInfo *get_user(LocalUser *user)
	{
		TGInfo *t = Get(user);
		if (!t)
		{
			t = new TGInfo();
			Set(user, t);
		}
		return t;
	}
};

class ModuleTGChange final
	: public Module
{
	TGExtInfo tginfo;
	Account::API accountapi;

public:
	ModuleTGChange()
		: Module(VF_NONE, "Implements \"target change\" detection to help prevent spam bots")
		, tginfo("tginfo", this)
		, accountapi(this)
	{
	}

	void ReadConfig(ConfigStatus& config) override
	{
		const auto& tag = ServerInstance->Config->ConfValue("tgchange");

		// Original target change protection.
		TGCHANGE_NUM = tag->getNum<unsigned>("num", 10);
		TGCHANGE_REPLY = tag->getNum<unsigned>("reply", 5);

		// Repeated private message protection.
		TGCHANGE_REPEAT = tag->getNum<unsigned>("repeat", 0, 0, 127);
		TGCHANGE_MINLENGTH = tag->getNum<unsigned>("minlength", 15);
		TGCHANGE_REPEATWINDOW = tag->getDuration("repeatwindow", 60, 1);
		TGCHANGE_REPEATNOTIFY = tag->getBool("repeatnotify", true);
		TGCHANGE_NOTIFYCOOLDOWN = tag->getDuration("notifycooldown", 60, 1);

		// Progressive penalty configuration.
		TGCHANGE_PENALTY = tag->getDuration("penalty", 0);
		TGCHANGE_PENALTYSTEP = tag->getDuration("penaltystep", 5);
		TGCHANGE_MAXWARNINGS = tag->getNum<unsigned>("maxwarnings", 3, 1, 20);
		TGCHANGE_PENALTYWINDOW = tag->getDuration("penaltywindow", 180, 1);
		TGCHANGE_PENALTYCOOLDOWN = tag->getDuration("penaltycooldown", 15, 1);
		TGCHANGE_DISCONNECT = tag->getBool("disconnect", true);
	}

	ModResult OnUserPreMessage(User* user, MessageTarget& target, MessageDetails& details) override
	{
		/* don't count ctcp replies */
		if (details.type == MessageType::NOTICE || details.IsCTCP())
			return MOD_RES_PASSTHRU;

		switch (target.type)
		{
			case MessageTarget::TYPE_USER:
			{
				User* dest = target.Get<User>();

				if (LocalUser* lsource = IS_LOCAL(user))
				{
					// Calculate the exemption only once.
					const bool exempt =
						user == dest ||
						dest->server->IsService() ||
						user->IsOper() ||
						Allowed(lsource, dest);

					if (TGCHANGE_REPEAT && !exempt)
					{
						TGInfo* tg = tginfo.get_user(lsource);
						bool saturated = false;

						if (!tg->IsReplyTarget(dest) &&
							tg->CheckRepeat(details.text, dest->uuid, saturated))
						{
							// Count the attempted target.
							tg->AddTarget(dest);

							// Apply progressive command penalties.
							const PenaltyResult penalty = ApplyPenalty(lsource, tg);

							// Log repeated messages and history saturation.
							if (TGCHANGE_REPEATNOTIFY && tg->ShouldNotifyRepeat())
							{
								if (saturated)
								{
									ServerInstance->SNO.WriteGlobalSno('a',
										"TGCHANGE: Private message history saturated for {} ({}) "
										"while messaging {} - 128 entries in {} seconds",
										lsource->nick,
										lsource->GetAddress(),
										dest->nick,
										TGCHANGE_REPEATWINDOW);
								}
								else
								{
									ServerInstance->SNO.WriteGlobalSno('a',
										"TGCHANGE: Repeated private message blocked from {} ({}) "
										"to {} - at least {} different recipients in {} seconds",
										lsource->nick,
										lsource->GetAddress(),
										dest->nick,
										TGCHANGE_REPEAT + 1,
										TGCHANGE_REPEATWINDOW);
								}
							}

							// Handle penalty warnings and disconnection.
							if (penalty.warning)
							{
								if (TGCHANGE_REPEATNOTIFY)
								{
									ServerInstance->SNO.WriteGlobalSno('a',
										"TGCHANGE: {} ({}) - Warning {}/{} - "
										"{} while messaging {}",
										lsource->nick,
										lsource->GetAddress(),
										penalty.warning,
										TGCHANGE_MAXWARNINGS,
										penalty.disconnected
											? "User disconnected"
											: "Command penalty applied",
										dest->nick);
								}

								if (penalty.disconnected)
								{
									ServerInstance->Users.QuitUser(lsource,
										"Excessive private messaging");

									return MOD_RES_DENY;
								}

								if (saturated)
								{
									lsource->WriteNumeric(ERR_TARGCHANGE, dest->nick,
										INSP_FORMAT(
											"Private message history limit reached, message dropped. "
											"Warning {}/{}: You have received a {}-second command penalty.",
											penalty.warning,
											TGCHANGE_MAXWARNINGS,
											penalty.seconds));
								}
								else
								{
									lsource->WriteNumeric(ERR_TARGCHANGE, dest->nick,
										INSP_FORMAT(
											"Repeated private message blocked. "
											"Warning {}/{}: You have received a {}-second command penalty.",
											penalty.warning,
											TGCHANGE_MAXWARNINGS,
											penalty.seconds));
								}

								return MOD_RES_DENY;
							}

							// Normal blocking when penalties are disabled
							// or the current violation is within cooldown.
							lsource->WriteNumeric(ERR_TARGCHANGE, dest->nick,
								saturated
									? "Private message history limit reached, message dropped"
									: "Repeated message to multiple recipients, message dropped");

							return MOD_RES_DENY;
						}
					}

					// Reuse the exemption already calculated.
					return Target(user, dest, true, true, exempt);
				}

				return Target(user, dest, true);
			}

			case MessageTarget::TYPE_CHANNEL:
				return Target(user, target.Get<Channel>());

			default:
				return MOD_RES_PASSTHRU;
		}
	}

	ModResult OnUserPreInvite(User* source, User* dest, Channel* channel, time_t timeout) override
	{
		return Target(source, dest);
	}

 private:
 	struct PenaltyResult
	{
		unsigned warning = 0;
		uint64_t seconds = 0;
		bool disconnected = false;
	};

	PenaltyResult ApplyPenalty(LocalUser* source, TGInfo* tg)
	{
		// Penalties are disabled by default.
		if (!TGCHANGE_PENALTY)
			return {};

		const unsigned warning = tg->RegisterPenaltyViolation();

		// Ignore violations during the cooldown.
		if (!warning)
			return {};

		// Signal that the user must be disconnected.
		// The caller will log the event and disconnect the user.
		if (TGCHANGE_DISCONNECT && warning >= TGCHANGE_MAXWARNINGS)
			return { warning, 0, true };

		// Calculate the progressive penalty in seconds.
		const uint64_t seconds =
			static_cast<uint64_t>(TGCHANGE_PENALTY) +
			static_cast<uint64_t>(warning - 1) * TGCHANGE_PENALTYSTEP;

		// Convert to milliseconds and prevent integer overflow.
		const uint64_t available =
			static_cast<uint64_t>(~0U) - source->CommandFloodPenalty;

		const uint64_t milliseconds =
			seconds > available / 1000
				? available
				: seconds * 1000;

		// Apply the native InspIRCd command penalty.
		source->CommandFloodPenalty +=
			static_cast<unsigned int>(milliseconds);

		return { warning, seconds, false };
	}

	bool Allowed(LocalUser* source, User* target)
	{
		// Only users logged in to a services account can be exempt.
		if (!accountapi || !accountapi->GetAccountName(source))
			return false;

		for (Membership* membership : source->chans)
		{
			// The sender must have at least halfop.
			if (membership->GetRank() < HALFOP_VALUE)
				continue;

			// Check whether the recipient shares this channel.
			if (membership->chan->HasUser(target))
				return true;
		}

		return false;
	}

	ModResult Target(User* source, User* dest, bool isprivmsg = false,
		bool exemptionchecked = false, bool exempt = false)
	{
		if (LocalUser* lsource = IS_LOCAL(source))
		{
			if (source != dest && !dest->server->IsService() && !source->IsOper() &&
				!(exemptionchecked ? exempt : Allowed(lsource, dest)))
			{
				ModResult m = Target(lsource, dest, dest->nick, isprivmsg);
				if (m != MOD_RES_PASSTHRU)
					return m;
			}
		}

		if (LocalUser* ldest = IS_LOCAL(dest))
		{
			if (source != dest && !source->server->IsService() && !dest->IsOper())
			{
				TGInfo* tg = tginfo.get_user(ldest);
				tg->AddReply(source);
			}
		}

		return MOD_RES_PASSTHRU;
	}

	ModResult Target(User *source, Channel *dest)
	{
		return IS_LOCAL(source) && !source->IsOper() ? Target(IS_LOCAL(source), dest, dest->name) : MOD_RES_PASSTHRU;
	}

	ModResult Target(LocalUser *source, ::Target *target, const std::string &name, bool isprivmsg = false)
	{
		TGInfo *tg = tginfo.get_user(source);

		if (!tg->AddTarget(target))
		{
			// Preserve the original behavior for channels and INVITEs.
			if (!isprivmsg)
			{
				source->WriteNumeric(ERR_TARGCHANGE, name,
					"Targets changing too fast, message dropped");

				return MOD_RES_DENY;
			}

			// Apply progressive penalties only to private messages.
			const PenaltyResult penalty = ApplyPenalty(source, tg);

			if (penalty.warning)
			{
				if (TGCHANGE_REPEATNOTIFY)
				{
					ServerInstance->SNO.WriteGlobalSno('a',
						"TGCHANGE: Too many private message targets from {} ({}) "
						"to {} - Warning {}/{} - {}",
						source->nick,
						source->GetAddress(),
						name,
						penalty.warning,
						TGCHANGE_MAXWARNINGS,
						penalty.disconnected
							? "User disconnected"
							: "Command penalty applied");
				}

				if (penalty.disconnected)
				{
					ServerInstance->Users.QuitUser(source,
						"Excessive private messaging");

					return MOD_RES_DENY;
				}

				source->WriteNumeric(ERR_TARGCHANGE, name,
					INSP_FORMAT(
						"Targets changing too fast, message dropped. "
						"Warning {}/{}: You have received a {}-second command penalty.",
						penalty.warning,
						TGCHANGE_MAXWARNINGS,
						penalty.seconds));

				return MOD_RES_DENY;
			}

			// Penalties disabled or violation within cooldown.
			source->WriteNumeric(ERR_TARGCHANGE, name,
				"Targets changing too fast, message dropped");

			return MOD_RES_DENY;
		}

		return MOD_RES_PASSTHRU;
	}

};

MODULE_INIT(ModuleTGChange)
