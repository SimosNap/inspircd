#include "inspircd.h"
#include "extension.h"
#include "modules/account.h"
#include "modules/httpd.h"

#include <set>
#include <limits>
#include <map>
#include <cstdint>
#include <deque>
#include <sstream>

using VroomChannels = std::set<std::string, irc::insensitive_swo>;

namespace
{
    std::string GetJoinTime(Membership* membership)
    {
        auto* item = ServerInstance->Extensions.GetItem("join-time");
        if (!item || item->extype != ExtensionType::MEMBERSHIP ||
            item->creator != ServerInstance->Modules.Find("ircv3_extjwt"))
            return {};

        const auto& extensions = membership->GetExtList();
        const auto it = extensions.find(item);
        if (it == extensions.end() || !it->second)
            return {};

        return item->ToInternal(membership, it->second);
    }

    bool IsChannelOp(const std::string& modes)
    {
        return modes.find_first_of("qao") != std::string::npos;
    }

    bool IsJoinTime(const std::string& value)
    {
        return !value.empty() && value.size() <= 20 &&
            value.front() != '0' &&
            value.find_first_not_of("0123456789") == std::string::npos;
    }
}

class CommandVroomCheck final : public Command
{
private:
    Account::API accountapi;
    const VroomChannels& enabledchannels;

public:
    CommandVroomCheck(Module* parent, const VroomChannels& channels)
        : Command(parent, "VROOMCHECK", 1, 1)
        , accountapi(parent)
        , enabledchannels(channels)
    {
        syntax = { "<channel>" };
    }

    CmdResult Handle(User* user, const Params& parameters) override
    {
        if (!IS_LOCAL(user))
            return CmdResult::FAILURE;

        const auto& channelname = parameters[0];
        if (enabledchannels.find(channelname) == enabledchannels.end())
        {
            user->WriteNotice("Conferenze disabilitate su questo canale.");
            return CmdResult::FAILURE;
        }

        auto* channel = ServerInstance->Channels.Find(channelname);
        auto* membership = channel ? channel->GetUser(user) : nullptr;
        if (!membership)
        {
            user->WriteNotice("Devi essere presente nel canale.");
            return CmdResult::FAILURE;
        }

        const auto joined = GetJoinTime(membership);
        if (!IsJoinTime(joined))
        {
            user->WriteNotice("Join-time EXTJWT non disponibile per questa presenza.");
            return CmdResult::FAILURE;
        }

        if (!accountapi)
        {
            user->WriteNotice("API account non disponibile su questo server.");
            return CmdResult::FAILURE;
        }

        const auto* account = accountapi->GetAccountName(user);
        const auto modes = membership->GetAllPrefixModes();

        user->WriteNotice("VROOMCHECK {} joined={} account={} modes={} is_op={}",
            channel->name, joined,
            account && !account->empty() ? *account : "*",
            modes.empty() ? "-" : modes,
            IsChannelOp(modes) ? 1 : 0);

        return CmdResult::SUCCESS;
    }
};

class ModuleVroomCheck final
    : public Module
    , public HTTPRequestEventListener
    , public Account::EventListener
{
private:
    VroomChannels enabledchannels;
    // Canale -> UUID della connessione -> ultimo account osservato.
    // Una stringa vuota rappresenta un logout.
    using SessionAccounts = std::map<std::string, std::string>;
    std::map<std::string, SessionAccounts, irc::insensitive_swo> observedaccounts;
    enum class VroomEventKind
    {
        Role,
        Part,
        Kick,
        Quit,
        Account,
        Invite,
        Start,
        Close,
        SetMode
    };

    struct InviteRequest
    {
        std::string actorNick;
        std::string actorJoined;
        std::string targetNick;
        std::string targetAccount;
        std::string targetSessionId;
        std::string conferenceId;
        std::uint64_t revision = 0;
        bool noticeSent = false;
        std::string noticeServer{};
        time_t noticeStarted = 0;
        time_t noticeLastAttempt = 0;
    };

    struct VroomEvent
    {
        std::uint64_t sequence;
        std::string channel;
        std::string sessionid;
        bool isop;
        VroomEventKind kind = VroomEventKind::Role;
        std::string account = {};
        InviteRequest invite = {};
        std::string starterNick = {};
        std::string starterJoined = {};
        std::string conferenceId = {};
        std::uint64_t revision = 0;
        std::string requestedMode = {};
        bool expiredNoticeSent = false;
    };

    static constexpr std::size_t MaxRoleEvents = 1024;
    std::deque<VroomEvent> roleevents;
    std::uint64_t lastsequence = 0;
    const std::string eventepoch = ServerInstance->GenRandomStr(32);
    CommandVroomCheck command;

    class CommandVroom final : public Command
    {
    private:
        ModuleVroomCheck& module;

    public:
        explicit CommandVroom(ModuleVroomCheck* parent)
            : Command(parent, "VROOM", 2, 5)
            , module(*parent)
        {
            syntax = {
                "START <channel>",
                "MODE <channel> <OPEN|INVITE_ONLY> <conference-id> <revision>",
                "CLOSE <channel> <conference-id> <revision>",
                "INVITE <channel> <nick> <conference-id> <revision>"
            };
        }

        CmdResult Handle(User* user, const Params& parameters) override
        {
            if (irc::equals(parameters[0], "START") && parameters.size() == 2)
                return module.QueueChannelCommand(user, parameters);

            if (irc::equals(parameters[0], "CLOSE") && parameters.size() == 4)
                return module.QueueChannelCommand(user, parameters);

            if (irc::equals(parameters[0], "MODE") && parameters.size() == 5)
                return module.QueueChannelCommand(user, parameters);

            if (irc::equals(parameters[0], "INVITE") && parameters.size() == 5)
                return module.QueueChannelCommand(user, parameters);

            user->WriteNotice("Uso: VROOM START <canale>, "
                "VROOM CLOSE <canale> <id-conferenza> <revisione> oppure "
                "VROOM INVITE <canale> <nick> <id-conferenza> <revisione>");
            return CmdResult::FAILURE;
        }
    };

    CommandVroom vroomcommand{this};

    class CommandVroomNotice final : public Command
    {
    private:
        ModuleVroomCheck& module;

    public:
        explicit CommandVroomNotice(ModuleVroomCheck* parent)
            : Command(parent, "VROOMNOTICE", 6, 6)
            , module(*parent)
        {
        }

        CmdResult Handle(User* source, const Params& parameters) override
        {
            if (!IS_SERVER(source))
                return CmdResult::FAILURE;

            return module.ReceiveInviteNotice(source, parameters);
        }
    };

    CommandVroomNotice vroomnoticecommand{this};

    class CommandVroomNoticeAck final : public Command
    {
    private:
        ModuleVroomCheck& module;

    public:
        explicit CommandVroomNoticeAck(ModuleVroomCheck* parent)
            : Command(parent, "VROOMNOTICEACK", 3, 3)
            , module(*parent)
        {
        }

        CmdResult Handle(User* source, const Params& parameters) override
        {
            // Parametri: epoch del mittente, sequenza invito, UUID destinatario.
            if (!IS_SERVER(source) || parameters[0] != module.eventepoch)
                return CmdResult::FAILURE;

            std::uint64_t seq = 0;
            if (!module.ParseCursor(parameters[1], seq) || !seq)
                return CmdResult::FAILURE;

            for (auto& event : module.roleevents)
            {
                if (event.sequence != seq)
                    continue;

                auto& invite = event.invite;
                if (event.kind != VroomEventKind::Invite
                    || invite.noticeServer.empty()
                    || !irc::equals(invite.noticeServer, source->server->GetName())
                    || invite.targetSessionId != parameters[2])
                    return CmdResult::FAILURE;

                invite.noticeSent = true;
                return CmdResult::SUCCESS;
            }

            return CmdResult::FAILURE;
        }
    };

    CommandVroomNoticeAck vroomnoticeackcommand{this};

    HTTPdAPI httpapi;
    Account::API accountapi;

    ModResult SendJson(HTTPRequest& request, unsigned int status,
        const std::string& json)
    {
        std::stringstream body;
        body << json << '\n';

        HTTPDocumentResponse response(this, request, &body, status);
        response.headers.SetHeader("Content-Type", "application/json");
        response.headers.SetHeader("Cache-Control", "no-store");
        if (status == 405)
            response.headers.SetHeader("Allow", "POST");

        httpapi->SendResponse(response);
        return MOD_RES_DENY;
    }

    ModResult Reject(HTTPRequest& request, unsigned int status,
        const char* reason)
    {
        // reason is always a fixed string supplied by this module.
        return SendJson(request, status,
            std::string("{\"result\":\"") + reason + "\"}");
    }

public:
    ModuleVroomCheck()
        : Module(VF_NONE, "Verifica l'identita IRC per le conferenze VRoom")
        , HTTPRequestEventListener(this)
        , Account::EventListener(this)
        , command(this, enabledchannels)
        , httpapi(this)
        , accountapi(this)
    {
    }

    void ReadConfig(ConfigStatus&) override
    {
        VroomChannels nextchannels;

        for (const auto& [key, tag] : ServerInstance->Config->ConfTags("vroomchannel"))
        {
            const auto channelname = tag->getString("name");
            if (channelname.empty() || !ServerInstance->Channels.IsChannel(channelname))
            {
                throw ModuleException(this,
                    "Nome canale mancante o non valido in <vroomchannel> in "
                    + tag->source.str());
            }

            nextchannels.insert(channelname);
        }

        enabledchannels.swap(nextchannels);

        for (auto it = observedaccounts.begin(); it != observedaccounts.end(); )
        {
            if (enabledchannels.find(it->first) == enabledchannels.end())
                it = observedaccounts.erase(it);
            else
                ++it;
        }
    }

    CmdResult QueueChannelCommand(User* user, const CommandBase::Params& parameters)
    {
        const auto& channelname = parameters[1];
        if (!IS_LOCAL(user))
            return CmdResult::FAILURE;

        if (enabledchannels.find(channelname) == enabledchannels.end())
        {
            user->WriteNotice("Conferenze disabilitate su questo canale.");
            return CmdResult::FAILURE;
        }

        auto* channel = ServerInstance->Channels.Find(channelname);
        auto* membership = channel ? channel->GetUser(user) : nullptr;
        if (!membership || !IsChannelOp(membership->GetAllPrefixModes()))
        {
            user->WriteNotice("Devi essere op del canale per usare questo comando.");
            return CmdResult::FAILURE;
        }

        if (!accountapi)
        {
            user->WriteNotice("API account non disponibile su questo server.");
            return CmdResult::FAILURE;
        }

        const auto* actoraccount = accountapi->GetAccountName(user);
        if (!actoraccount || actoraccount->empty() || *actoraccount == "*")
        {
            user->WriteNotice("Devi essere autenticato per usare questo comando.");
            return CmdResult::FAILURE;
        }

        const auto joined = GetJoinTime(membership);
        if (!IsJoinTime(joined))
        {
            user->WriteNotice("Join-time EXTJWT non disponibile per questa presenza.");
            return CmdResult::FAILURE;
        }

        if (irc::equals(parameters[0], "START"))
        {
            roleevents.push_back({
                ++lastsequence,
                channel->name,
                user->uuid,
                true,
                VroomEventKind::Start,
                *actoraccount,
                {},
                user->nick,
                joined
            });

            if (roleevents.size() > MaxRoleEvents)
                roleevents.pop_front();

            user->WriteNotice("Richiesta di avvio conferenza per {} presa in carico.",
                channel->name);
            return CmdResult::SUCCESS;
        }

        const bool closing = irc::equals(parameters[0], "CLOSE");
        const auto& conferenceid = parameters[closing ? 2 : 3];
        const auto& revisiontext = parameters[closing ? 3 : 4];

        std::uint64_t revision = 0;
        if (conferenceid.empty() || conferenceid.size() > 128 ||
            !ParseCursor(revisiontext, revision) || revision == 0)
        {
            user->WriteNotice("Identificativo o revisione della conferenza non validi.");
            return CmdResult::FAILURE;
        }

        const bool settingMode = irc::equals(parameters[0], "MODE");
        if (closing || settingMode)
        {
            std::string requestedMode;
            if (settingMode)
            {
                if (irc::equals(parameters[2], "OPEN"))
                    requestedMode = "OPEN";
                else if (irc::equals(parameters[2], "INVITE_ONLY"))
                    requestedMode = "INVITE_ONLY";
                else
                {
                    user->WriteNotice("Modalità non valida. Usa OPEN oppure INVITE_ONLY.");
                    return CmdResult::FAILURE;
                }
            }

            roleevents.push_back({
                ++lastsequence,
                channel->name,
                user->uuid,
                true,
                closing ? VroomEventKind::Close : VroomEventKind::SetMode,
                *actoraccount,
                {},
                user->nick,
                joined,
                conferenceid,
                revision,
                requestedMode
            });

            if (roleevents.size() > MaxRoleEvents)
                roleevents.pop_front();

            if (closing)
                user->WriteNotice("Richiesta di chiusura conferenza per {} presa in carico.",
                    channel->name);
            else
                user->WriteNotice("Richiesta modalità {} per {} presa in carico.",
                    requestedMode, channel->name);

            return CmdResult::SUCCESS;
        }

        const auto& targetnick = parameters[2];

        auto* target = ServerInstance->Users.FindNick(targetnick, true);
        if (!target)
        {
            user->WriteNotice("Il destinatario non è connesso.");
            return CmdResult::FAILURE;
        }

        const auto* targetaccount = accountapi->GetAccountName(target);
        if (!targetaccount || targetaccount->empty() || *targetaccount == "*")
        {
            user->WriteNotice("Il destinatario deve essere autenticato per ricevere l'invito.");
            return CmdResult::FAILURE;
        }

        roleevents.push_back({
            ++lastsequence,
            channel->name,
            user->uuid,
            true,
            VroomEventKind::Invite,
            *actoraccount,
            {user->nick, joined, target->nick, *targetaccount,
                target->uuid, conferenceid, revision}
        });

        if (roleevents.size() > MaxRoleEvents)
            roleevents.pop_front();

        user->WriteNotice("Richiesta di invito per {} presa in carico.", target->nick);
        return CmdResult::SUCCESS;
    }

    void LogDeparture(Membership* membership, VroomEventKind kind)
    {
        if (!IS_LOCAL(membership->user))
            return;

        const auto& channelname = membership->chan->name;
        const auto& sessionid = membership->user->uuid;

        const auto tracked = observedaccounts.find(channelname);
        if (tracked != observedaccounts.end())
        {
            tracked->second.erase(sessionid);
            if (tracked->second.empty())
                observedaccounts.erase(tracked);
        }

        if (enabledchannels.find(channelname) == enabledchannels.end())
            return;

        const char* cause;
        switch (kind)
        {
            case VroomEventKind::Part: cause = "part"; break;
            case VroomEventKind::Kick: cause = "kick"; break;
            case VroomEventKind::Quit: cause = "quit"; break;
            default: return;
        }

        roleevents.push_back({
            ++lastsequence,
            channelname,
            sessionid,
            false,
            kind
        });

        if (roleevents.size() > MaxRoleEvents)
            roleevents.pop_front();

        ServerInstance->Logs.Normal(MODNAME,
            "VROOM leave epoch={} seq={} channel={} session_id={} cause={}",
            eventepoch, lastsequence, channelname, sessionid, cause);
    }

    void OnUserPart(Membership* membership, std::string&, CUList&) override
    {
        LogDeparture(membership, VroomEventKind::Part);
    }

    void OnUserKick(User*, Membership* membership,
        const std::string&, CUList&) override
    {
        LogDeparture(membership, VroomEventKind::Kick);
    }

    void OnUserQuit(User* user, const std::string&, const std::string&) override
    {
        if (!IS_LOCAL(user))
            return;

        for (auto* membership : user->chans)
            LogDeparture(membership, VroomEventKind::Quit);
    }

    void OnAccountChange(User* user, const std::string& account) override
    {
        if (!IS_LOCAL(user))
            return;

        for (auto* membership : user->chans)
        {
            const auto& channelname = membership->chan->name;
            if (enabledchannels.find(channelname) == enabledchannels.end())
                continue;

            auto& sessions = observedaccounts[channelname];
            const auto previous = sessions.find(user->uuid);

            if (previous != sessions.end() && previous->second == account)
                continue;

            sessions[user->uuid] = account;

            roleevents.push_back({
                ++lastsequence,
                channelname,
                user->uuid,
                false,
                VroomEventKind::Account,
                account
            });

            if (roleevents.size() > MaxRoleEvents)
                roleevents.pop_front();

            ServerInstance->Logs.Normal(MODNAME,
                "VROOM account channel={} session_id={} account={} authenticated={}",
                channelname, user->uuid,
                account.empty() ? "*" : account,
                account.empty() ? 0 : 1);
        }
    }

    void OnMode(User*, User*, Channel* channel,
        const Modes::ChangeList& changes, ModeParser::ModeProcessFlag) override
    {
        if (!channel || enabledchannels.find(channel->name) == enabledchannels.end())
            return;

        // Un singolo MODE può modificare più privilegi dello stesso utente.
        std::set<LocalUser*> affected;

        for (const auto& change : changes.getlist())
        {
            const char mode = change.mh->GetModeChar();
            if (mode != 'q' && mode != 'a' && mode != 'o')
                continue;

            if (ServerInstance->Modes.FindPrefixMode(mode) != change.mh)
                continue;

            // change.param identifica chi riceve o perde il privilegio.
            auto* target = ServerInstance->Users.FindNick<LocalUser>(change.param, true);
            if (target)
                affected.insert(target);
        }

        for (auto* target : affected)
        {
            auto* membership = channel->GetUser(target);
            if (!membership)
                continue;

            const auto modes = membership->GetAllPrefixModes();
            const bool isop = IsChannelOp(modes);

            roleevents.push_back({
                ++lastsequence,
                channel->name,
                target->uuid,
                isop
            });

            if (roleevents.size() > MaxRoleEvents)
                roleevents.pop_front();

            ServerInstance->Logs.Normal(MODNAME,
                "VROOM role epoch={} seq={} channel={} session_id={} modes={} is_op={}",
                eventepoch, lastsequence, channel->name, target->uuid,
                modes.empty() ? "-" : modes, isop ? 1 : 0);
        }
    }

    static bool ParseCursor(const std::string& text, std::uint64_t& value)
    {
        if (text.empty() || text.size() > 20)
            return false;

        value = 0;
        for (const char ch : text)
        {
            if (ch < '0' || ch > '9')
                return false;

            const auto digit = static_cast<unsigned int>(ch - '0');
            if (value > (std::numeric_limits<std::uint64_t>::max() - digit) / 10)
                return false;

            value = value * 10 + digit;
        }
        return true;
    }

    // I nomi IRC possono contenere virgolette, backslash o byte non UTF-8.
    // Trasmettiamo i byte del canale in esadecimale per conservarli esattamente.
    static std::string ChannelHex(const std::string& channel)
    {
        static constexpr char digits[] = "0123456789abcdef";
        std::string encoded;
        encoded.reserve(channel.size() * 2);

        for (const unsigned char ch : channel)
        {
            encoded.push_back(digits[ch >> 4]);
            encoded.push_back(digits[ch & 15]);
        }
        return encoded;
    }

    ModResult ReadEvents(HTTPRequest& request)
    {
        if (request.GetIP() != "127.0.0.1")
            return Reject(request, 403, "local-only");

        if (request.GetType() != "GET")
        {
            std::stringstream body;
            body << "{\"result\":\"get-required\"}\n";
            HTTPDocumentResponse response(this, request, &body, 405);
            response.headers.SetHeader("Allow", "GET");
            response.headers.SetHeader("Content-Type", "application/json");
            response.headers.SetHeader("Cache-Control", "no-store");
            httpapi->SendResponse(response);
            return MOD_RES_DENY;
        }

        const auto epoch = request.headers->GetHeader("X-Vroom-Epoch");
        const auto cursor = request.headers->GetHeader("X-Vroom-After");

        std::uint64_t after = 0;
        if (!ParseCursor(cursor, after))
            return Reject(request, 400, "invalid-cursor");

        // Se il primo evento conservato è 10, after=9 è ancora recuperabile.
        const bool missed = !roleevents.empty() &&
            after < roleevents.front().sequence - 1;

        if (epoch != eventepoch || after > lastsequence || missed)
        {
            std::ostringstream json;
            json << "{\"result\":\"resync-required\",\"epoch\":\""
                 << eventepoch << "\",\"latest\":" << lastsequence << "}";
            return SendJson(request, 409, json.str());
        }

        std::ostringstream json;
        json << "{\"result\":\"ok\",\"epoch\":\"" << eventepoch
             << "\",\"latest\":" << lastsequence << ",\"events\":[";

        // Un massimo di 64 eventi per risposta. Il client riprende da "next".
        unsigned int count = 0;
        auto next = after;
        for (const auto& event : roleevents)
        {
            if (event.sequence <= after)
                continue;

            if (count != 0)
                json << ',';

            const char* kind;
            switch (event.kind)
            {
                case VroomEventKind::Role:    kind = "role";    break;
                case VroomEventKind::Part:    kind = "part";    break;
                case VroomEventKind::Kick:    kind = "kick";    break;
                case VroomEventKind::Quit:    kind = "quit";    break;
                case VroomEventKind::Account: kind = "account"; break;
                case VroomEventKind::Invite:  kind = "invite";  break;
                case VroomEventKind::Start:   kind = "start";   break;
                case VroomEventKind::Close:   kind = "close";   break;
                case VroomEventKind::SetMode: kind = "set_mode"; break;
                default:
                    return Reject(request, 500, "unknown-event-kind");
            }

            json << "{\"seq\":" << event.sequence
                 << ",\"kind\":\"" << kind << '"'
                 << ",\"channel_hex\":\"" << ChannelHex(event.channel) << '"'
                 << ",\"session_id\":\"" << event.sessionid << '"';

            if (event.kind == VroomEventKind::Role)
            {
                json << ",\"is_op\":" << (event.isop ? "true" : "false");
            }
            else if (event.kind == VroomEventKind::Account)
            {
                json << ",\"authenticated\":"
                     << (event.account.empty() ? "false" : "true")
                     << ",\"account_hex\":\"" << ChannelHex(event.account) << '"';
            }
            else if (event.kind == VroomEventKind::Start
                || event.kind == VroomEventKind::Close
                || event.kind == VroomEventKind::SetMode)
            {
                json << ",\"actor_nick_hex\":\"" << ChannelHex(event.starterNick) << '"'
                     << ",\"actor_account_hex\":\"" << ChannelHex(event.account) << '"'
                     << ",\"actor_joined\":\"" << event.starterJoined << '"';

                if (event.kind != VroomEventKind::Start)
                {
                    json << ",\"conference_id_hex\":\"" << ChannelHex(event.conferenceId) << '"'
                         << ",\"revision\":" << event.revision;
                }

                if (event.kind == VroomEventKind::SetMode)
                    json << ",\"mode\":\"" << event.requestedMode << '"';
            }
            else if (event.kind == VroomEventKind::Invite)
            {
                const auto& invite = event.invite;
                json << ",\"actor_nick_hex\":\"" << ChannelHex(invite.actorNick) << '"'
                     << ",\"actor_account_hex\":\"" << ChannelHex(event.account) << '"'
                     << ",\"actor_joined\":\"" << invite.actorJoined << '"'
                     << ",\"target_nick_hex\":\"" << ChannelHex(invite.targetNick) << '"'
                     << ",\"target_account_hex\":\"" << ChannelHex(invite.targetAccount) << '"'
                     << ",\"target_session_id_hex\":\"" << ChannelHex(invite.targetSessionId) << '"'
                     << ",\"conference_id_hex\":\"" << ChannelHex(invite.conferenceId) << '"'
                     << ",\"revision\":" << invite.revision;
            }

            json << '}';

            next = event.sequence;
            if (++count == 64)
                break;
        }

        json << "],\"next\":" << next << "}";
        return SendJson(request, 200, json.str());
    }

    static bool DecodeNoticeField(const std::string& hex, std::string& value)
    {
        if (hex.empty() || hex.size() % 2 != 0)
            return false;

        auto digit = [](char ch) -> int
        {
            if (ch >= '0' && ch <= '9')
                return ch - '0';
            if (ch >= 'a' && ch <= 'f')
                return ch - 'a' + 10;
            return -1;
        };

        value.clear();
        value.reserve(hex.size() / 2);
        for (std::size_t pos = 0; pos < hex.size(); pos += 2)
        {
            const int high = digit(hex[pos]);
            const int low = digit(hex[pos + 1]);
            if (high < 0 || low < 0)
                return false;

            const int byte = high * 16 + low;
            if (byte <= 0x20 || byte == 0x7f)
                return false;

            value.push_back(static_cast<char>(byte));
        }
        return true;
    }

    struct DeliveredNotice
    {
        std::string targetSessionId;
        time_t expires;
    };

    std::map<std::string, DeliveredNotice> deliveredNotices;

    CmdResult ReceiveInviteNotice(User* source, const CommandBase::Params& parameters)
    {
        // epoch, seq, UUID destinatario, account hex, canale hex, nick autore hex
        std::uint64_t seq = 0;
        if (!IS_SERVER(source) || parameters.size() != 6
            || parameters[0].size() != 32
            || !ParseCursor(parameters[1], seq) || !seq)
            return CmdResult::FAILURE;

        const auto& origin = source->server->GetName();
        const auto now = ServerInstance->Time();
        const std::string key = origin + "/" + parameters[0] + "/" + std::to_string(seq);

        for (auto it = deliveredNotices.begin(); it != deliveredNotices.end(); )
        {
            if (it->second.expires <= now)
                it = deliveredNotices.erase(it);
            else
                ++it;
        }

        const auto acknowledge = [&]()
        {
            CommandBase::Params ack;
            ack.push_back(parameters[0]);
            ack.push_back(parameters[1]);
            ack.push_back(parameters[2]);
            return ServerInstance->PI->SendEncapsulatedData(origin, "VROOMNOTICEACK", ack);
        };

        const auto previous = deliveredNotices.find(key);
        if (previous != deliveredNotices.end())
        {
            if (previous->second.targetSessionId != parameters[2])
                return CmdResult::FAILURE;

            return acknowledge() ? CmdResult::SUCCESS : CmdResult::FAILURE;
        }

        // Manteniamo le conferme ancora valide anche quando la cache è piena.
        if (deliveredNotices.size() >= MaxRoleEvents)
            return CmdResult::FAILURE;

        std::string channelname;
        std::string actornick;
        if (!DecodeNoticeField(parameters[4], channelname)
            || !DecodeNoticeField(parameters[5], actornick)
            || enabledchannels.find(channelname) == enabledchannels.end())
            return CmdResult::FAILURE;

        auto* channel = ServerInstance->Channels.Find(channelname);
        auto* actor = ServerInstance->Users.FindNick(actornick, true);
        if (!channel || !actor || actor->server != source->server)
            return CmdResult::FAILURE;

        auto* membership = channel->GetUser(actor);
        if (!membership || !IsChannelOp(membership->GetAllPrefixModes()))
            return CmdResult::FAILURE;

        auto* target = ServerInstance->Users.FindUUID<LocalUser>(parameters[2], true);
        if (!target || !accountapi)
            return CmdResult::FAILURE;

        const auto* account = accountapi->GetAccountName(target);
        if (!account || account->empty() || *account == "*"
            || ChannelHex(*account) != parameters[3])
            return CmdResult::FAILURE;

        target->WriteNotice("{} ti invita alla conferenza di {}. Apri VRoom nel canale.",
            actor->nick, channel->name);

        deliveredNotices.emplace(key, DeliveredNotice{target->uuid, now + 120});
        return acknowledge() ? CmdResult::SUCCESS : CmdResult::FAILURE;
    }

    bool ForwardInviteNotice(const std::string& targetserver, const VroomEvent& event)
    {
        const auto& invite = event.invite;

        CommandBase::Params params;
        params.push_back(eventepoch);
        params.push_back(std::to_string(event.sequence));
        params.push_back(invite.targetSessionId);
        params.push_back(ChannelHex(invite.targetAccount));
        params.push_back(ChannelHex(event.channel));
        params.push_back(ChannelHex(invite.actorNick));

        return ServerInstance->PI->SendEncapsulatedData(
            targetserver, "VROOMNOTICE", params);
    }

    ModResult OnHTTPRequest(HTTPRequest& request) override
    {
        if (request.GetPath() == "/vroom/events")
            return ReadEvents(request);

        if (request.GetPath() == "/vroom/start-expired")
        {
            if (request.GetIP() != "127.0.0.1")
                return Reject(request, 403, "local-only");

            if (request.GetType() != "POST")
                return Reject(request, 405, "post-required");

            if (request.headers->GetHeader("X-Vroom-Epoch") != eventepoch)
                return Reject(request, 409, "epoch-mismatch");

            std::uint64_t seq = 0;
            if (!ParseCursor(request.headers->GetHeader("X-Vroom-Seq"), seq) || !seq)
                return Reject(request, 400, "invalid-sequence");

            for (auto& event : roleevents)
            {
                if (event.sequence != seq)
                    continue;

                if (event.kind != VroomEventKind::Start)
                    return Reject(request, 409, "not-a-start");

                if (event.expiredNoticeSent)
                    return SendJson(request, 200, "{\"result\":\"already-sent\"}");

                auto* target = ServerInstance->Users.FindUUID<LocalUser>(event.sessionid, true);
                if (!target)
                    return Reject(request, 409, "target-session-changed");

                if (!accountapi)
                    return Reject(request, 503, "account-api-unavailable");

                const auto* account = accountapi->GetAccountName(target);
                if (!account || account->empty() || *account == "*" || *account != event.account)
                    return Reject(request, 403, "target-account-mismatch");

                target->WriteNotice("La richiesta di avvio per {} è scaduta mentre VRoom "
                    "era offline. Per aprire la conferenza, ripeti VROOM START {}.",
                    event.channel, event.channel);

                event.expiredNoticeSent = true;
                return SendJson(request, 200, "{\"result\":\"sent\"}");
            }

            return Reject(request, 404, "start-event-unavailable");
        }

        if (request.GetPath() == "/vroom/invite-notice")
        {
            if (request.GetIP() != "127.0.0.1")
                return Reject(request, 403, "local-only");

            if (request.GetType() != "POST")
                return Reject(request, 405, "post-required");

            if (request.headers->GetHeader("X-Vroom-Epoch") != eventepoch)
                return Reject(request, 409, "epoch-mismatch");

            std::uint64_t seq = 0;
            if (!ParseCursor(request.headers->GetHeader("X-Vroom-Seq"), seq) || !seq)
                return Reject(request, 400, "invalid-sequence");

            for (auto& event : roleevents)
            {
                if (event.sequence != seq)
                    continue;

                if (event.kind != VroomEventKind::Invite)
                    return Reject(request, 409, "not-an-invite");

                auto& invite = event.invite;
                if (invite.noticeSent)
                    return SendJson(request, 200, "{\"result\":\"already-sent\"}");

                if (enabledchannels.find(event.channel) == enabledchannels.end())
                    return Reject(request, 403, "channel-disabled");

                auto* target = ServerInstance->Users.FindNick<LocalUser>(invite.targetNick, true);
                if (!target || target->uuid != invite.targetSessionId)
                    return Reject(request, 409, "target-session-changed");

                if (!accountapi)
                    return Reject(request, 503, "account-api-unavailable");

                const auto* account = accountapi->GetAccountName(target);
                if (!account || account->empty() || *account == "*" ||
                    *account != invite.targetAccount)
                    return Reject(request, 403, "target-account-mismatch");

                target->WriteNotice("{} ti invita alla conferenza di {}. Apri VRoom nel canale.",
                    invite.actorNick, event.channel);
                invite.noticeSent = true;
                return SendJson(request, 200, "{\"result\":\"sent\"}");
            }

            return Reject(request, 404, "invite-event-unavailable");
        }

        if (request.GetPath() != "/vroom/check")
            return MOD_RES_PASSTHRU;

        if (request.GetIP() != "127.0.0.1")
            return Reject(request, 403, "local-only");

        if (request.GetType() != "POST")
            return Reject(request, 405, "post-required");

        const auto channelname = request.headers->GetHeader("X-Vroom-Channel");
        const auto nickname = request.headers->GetHeader("X-Vroom-Nick");
        if (channelname.empty() || nickname.empty())
            return Reject(request, 400, "missing-channel-or-nick");

        if (enabledchannels.find(channelname) == enabledchannels.end())
            return Reject(request, 403, "channel-disabled");

        auto* channel = ServerInstance->Channels.Find(channelname);
        auto* user = ServerInstance->Users.FindNick<LocalUser>(nickname, true);
        auto* membership = channel && user ? channel->GetUser(user) : nullptr;
        if (!membership)
            return Reject(request, 403, "not-local-channel-member");

        if (!accountapi)
            return Reject(request, 503, "account-api-unavailable");

        const auto* account = accountapi->GetAccountName(user);
        if (!account || account->empty())
            return Reject(request, 403, "account-required");

        const auto expectedaccount = request.headers->GetHeader("X-Vroom-Account");
        const auto expectedjoined = request.headers->GetHeader("X-Vroom-Joined");
        if (expectedaccount.empty() || expectedaccount == "*" || !IsJoinTime(expectedjoined))
            return Reject(request, 400, "invalid-identity-claims");

        if (!irc::equals(user->nick, nickname) ||
            *account != expectedaccount ||
            !irc::equals(channel->name, channelname))
        {
            return Reject(request, 403, "identity-mismatch");
        }

        const auto joined = GetJoinTime(membership);
        if (!IsJoinTime(joined))
            return Reject(request, 503, "join-time-unavailable");

        if (joined != expectedjoined)
            return Reject(request, 403, "join-time-mismatch");

        // Only the server-generated IRC UUID is inserted into the JSON string.
        const auto& sessionid = user->uuid;
        if (sessionid.empty() ||
            sessionid.find_first_not_of("ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789") != std::string::npos)
            return Reject(request, 503, "invalid-server-session-id");

        const bool isop = IsChannelOp(membership->GetAllPrefixModes());
        return SendJson(request, 200,
            std::string("{\"result\":\"verified\",\"session_id\":\"") +
            sessionid + "\",\"is_op\":" + (isop ? "true}" : "false}"));
    }
};

MODULE_INIT(ModuleVroomCheck)
