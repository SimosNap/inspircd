/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2017-2020 Sadie Powell <sadie@witchery.services>
 *   Copyright (C) 2014-2015 Attila Molnar <attilamolnar@hush.com>
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


#pragma once

#include "inspircd.h"
#include "listmode.h"
#include "modules/exemption.h"
#include "modules/extban.h"

namespace Topic
{
	void ShowTopic(LocalUser* user, Channel* chan);
}

namespace Invite
{
	class APIImpl;

	/** Used to indicate who we announce invites to on a channel. */
	enum AnnounceState
	{
		/** Don't send invite announcements. */
		ANNOUNCE_NONE,

		/** Send invite announcements to all users. */
		ANNOUNCE_ALL,

		/** Send invite announcements to channel operators and higher. */
		ANNOUNCE_OPS,

		/** Send invite announcements to channel half-operators (if available) and higher. */
		ANNOUNCE_DYNAMIC
	};
}

enum
{
	// From RFC 1459.
	RPL_BANLIST = 367,
	RPL_ENDOFBANLIST = 368,
	ERR_KEYSET = 467
};

/** Handle /INVITE.
 */
class CommandInvite : public Command
{
	Invite::APIImpl& invapi;

 public:
	Invite::AnnounceState announceinvites;

	/** Constructor for invite.
	 */
	CommandInvite(Module* parent, Invite::APIImpl& invapiimpl);

	/** Handle command.
	 * @param parameters The parameters to the command
	 * @param user The user issuing the command
	 * @return A value from CmdResult to indicate command success or failure.
	 */
	CmdResult Handle(User* user, const Params& parameters) override;
	RouteDescriptor GetRouting(User* user, const Params& parameters) override;
};

/** Handle /JOIN.
 */
class CommandJoin : public SplitCommand
{
 public:
	/** Constructor for join.
	 */
	CommandJoin(Module* parent);

	/** Handle command.
	 * @param parameters The parameters to the command
	 * @param user The user issuing the command
	 * @return A value from CmdResult to indicate command success or failure.
	 */
	CmdResult HandleLocal(LocalUser* user, const Params& parameters) override;
};

/** Handle /TOPIC.
 */
class CommandTopic : public SplitCommand
{
	CheckExemption::EventProvider exemptionprov;
	ChanModeReference secretmode;
	ChanModeReference topiclockmode;

 public:
	/** Constructor for topic.
	 */
	CommandTopic(Module* parent);

	/** Handle command.
	 * @param parameters The parameters to the command
	 * @param user The user issuing the command
	 * @return A value from CmdResult to indicate command success or failure.
	 */
	CmdResult HandleLocal(LocalUser* user, const Params& parameters) override;
};

/** Handle /NAMES.
 */
class CommandNames : public SplitCommand
{
 private:
	ChanModeReference secretmode;
	ChanModeReference privatemode;
	UserModeReference invisiblemode;
	Events::ModuleEventProvider namesevprov;

 public:
	/** Constructor for names.
	 */
	CommandNames(Module* parent);

	/** Handle command.
	 * @param parameters The parameters to the command
	 * @param user The user issuing the command
	 * @return A value from CmdResult to indicate command success or failure.
	 */
	CmdResult HandleLocal(LocalUser* user, const Params& parameters) override;

	/** Spool the NAMES list for a given channel to the given user
	 * @param user User to spool the NAMES list to
	 * @param chan Channel whose nicklist to send
	 * @param show_invisible True to show invisible (+i) members to the user, false to omit them from the list
	 */
	void SendNames(LocalUser* user, Channel* chan, bool show_invisible);
};

/** Handle /KICK.
 */
class CommandKick : public Command
{
 public:
	/** Constructor for kick.
	 */
	CommandKick(Module* parent);

	/** Handle command.
	 * @param parameters The parameters to the command
	 * @param user The user issuing the command
	 * @return A value from CmdResult to indicate command success or failure.
	 */
	CmdResult Handle(User* user, const Params& parameters) override;
	RouteDescriptor GetRouting(User* user, const Params& parameters) override;
};

/** Channel mode +b
 */
class ModeChannelBan : public ListModeBase
{
 public:
	ModeChannelBan(Module* Creator)
		: ListModeBase(Creator, "ban", 'b', "End of channel ban list", RPL_BANLIST, RPL_ENDOFBANLIST, true)
	{
		syntax = "<mask>";
	}
};

/** Channel mode +k
 */
class ModeChannelKey : public ParamMode<ModeChannelKey, StringExtItem>
{
 public:
	static const std::string::size_type maxkeylen;
	ModeChannelKey(Module* Creator);
	ModeAction OnModeChange(User* source, User* dest, Channel* channel, Modes::Change& change) override;
	void SerializeParam(Channel* chan, const std::string* key, std::string& out);
	ModeAction OnSet(User* source, Channel* chan, std::string& param) override;
	bool IsParameterSecret() override;
};

/** Channel mode +l
 */
class ModeChannelLimit : public ParamMode<ModeChannelLimit, IntExtItem>
{
 public:
	ModeChannelLimit(Module* Creator);
	bool ResolveModeConflict(const std::string& their_param, const std::string& our_param, Channel* channel) override;
	void SerializeParam(Channel* chan, intptr_t n, std::string& out);
	ModeAction OnSet(User* source, Channel* channel, std::string& parameter) override;
};

/** Channel mode +o
 */
class ModeChannelOp : public PrefixMode
{
 public:
	ModeChannelOp(Module* Creator)
		: PrefixMode(Creator, "op", 'o', OP_VALUE, '@')
	{
		ranktoset = ranktounset = OP_VALUE;
	}
};

/** Channel mode +v
 */
class ModeChannelVoice : public PrefixMode
{
 public:
	ModeChannelVoice(Module* Creator)
		: PrefixMode(Creator, "voice", 'v', VOICE_VALUE, '+')
	{
		selfremove = false;
		ranktoset = ranktounset = HALFOP_VALUE;
	}
};

class ExtBanManager : public ExtBan::Manager
{
 private:
	ModeChannelBan& banmode;
	Events::ModuleEventProvider evprov;
	LetterMap byletter;
	NameMap byname;

 public:
	ExtBanManager(Module* Creator, ModeChannelBan& bm)
		: ExtBan::Manager(Creator)
		, banmode(bm)
		, evprov(Creator, "event/extban")
	{
	}

	void AddExtBan(ExtBan::Base* extban) override;
	void DelExtBan(ExtBan::Base* extban) override;
	const LetterMap& GetLetterMap() const override { return byletter; }
	const NameMap& GetNameMap() const override { return byname; }
	ModResult GetStatus(ExtBan::Acting* extban, User* user, Channel* channel) const override;
	ExtBan::Base* FindName(const std::string& name) const override;
	ExtBan::Base* FindLetter(unsigned char letter) const override;
	void BuildISupport(std::string& out);
};
