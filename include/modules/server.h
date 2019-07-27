/*
 * InspIRCd -- Internet Relay Chat Daemon
 *
 *   Copyright (C) 2009 Daniel De Graaf <danieldg@inspircd.org>
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

#include "event.h"

namespace ServerProtocol
{
	class BroadcastEventListener;
	class LinkEventListener;
	class MessageEventListener;
	class SyncEventListener;
}

class ServerProtocol::BroadcastEventListener
	: public Events::ModuleEventListener
{
 public:
	BroadcastEventListener(Module* mod)
		: ModuleEventListener(mod, "event/server-broadcast")
	{
	}

	/** Fired when a channel message is being broadcast across the network.
	 * @param channel The channel which is having a message sent to it.
	 * @param server The server which might have a message broadcast to it.
	 * @return Either MOD_RES_ALLOW to always send the message to the server, MOD_RES_DENY to never
	 *         send the message to the server or MOD_RES_PASSTHRU if no module handled the event.
	 */
	virtual ModResult OnBroadcastMessage(Channel* channel, const Server* server) { return MOD_RES_PASSTHRU; }
};

class ServerProtocol::LinkEventListener
	: public Events::ModuleEventListener
{
 public:
	LinkEventListener(Module* mod)
		: ModuleEventListener(mod, "event/server-link")
	{
	}

	/** Fired when a server finishes burst
	 * @param server Server that recently linked and finished burst
	 */
	virtual void OnServerLink(const Server* server) { }

	 /** Fired when a server splits
	  * @param server Server that split
	  */
	virtual void OnServerSplit(const Server* server) { }
};

class ServerProtocol::MessageEventListener
	: public Events::ModuleEventListener
{
 public:
	MessageEventListener(Module* mod)
		: ModuleEventListener(mod, "event/server-message")
	{
	}

	/** Fired when a server message is being sent by a user.
	 * @param source The user who sent the message.
	 * @param name The name of the command which was sent.
	 * @param tags The tags which will be sent with the message.
	 */
	virtual void OnBuildMessage(User* source, const char* name, ClientProtocol::TagMap& tags) { }

	/** Fired when a server message is being sent by a server.
	 * @param source The server who sent the message.
	 * @param name The name of the command which was sent.
	 * @param tags The tags which will be sent with the message.
	 */
	virtual void OnBuildMessage(Server* source, const char* name, ClientProtocol::TagMap& tags) { }
};

class ServerProtocol::SyncEventListener
	: public Events::ModuleEventListener
{
 public:
	SyncEventListener(Module* mod)
		: ModuleEventListener(mod, "event/server-sync")
	{
	}

	/** Allows modules to synchronize user metadata during a netburst. This will
	 * be called for every user visible on your side of the burst.
	 * @param user The user being synchronized.
	 * @param server The target of the burst.
	 */
	virtual void OnSyncUser(User* user, ProtocolServer& server) { }

	/** Allows modules to synchronize channel metadata during a netburst. This will
	 * be called for every channel visible on your side of the burst.
	 * @param chan The channel being synchronized.
	 * @param server The target of the burst.
	 */
	virtual void OnSyncChannel(Channel* chan, ProtocolServer& server) { }

	/** Allows modules to synchronize network metadata during a netburst.
	 * @param server The target of the burst.
	 */
	virtual void OnSyncNetwork(ProtocolServer& server) { }
};
