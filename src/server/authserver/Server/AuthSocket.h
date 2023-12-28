/*
* This file is part of the Pandaria 5.4.8 Project. See THANKS file for Copyright information
*
* This program is free software; you can redistribute it and/or modify it
* under the terms of the GNU General Public License as published by the
* Free Software Foundation; either version 2 of the License, or (at your
* option) any later version.
*
* This program is distributed in the hope that it will be useful, but WITHOUT
* ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
* FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
* more details.
*
* You should have received a copy of the GNU General Public License along
* with this program. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef SF_AUTHSOCKET_H
#define SF_AUTHSOCKET_H

#include "Common.h"
#include "BigNumber.h"
#include "Optional.h"
#include "RealmSocket.h"
#include "SRP6.h"
#include <mutex>

class ACE_INET_Addr;
class ByteBuffer;
struct Realm;
struct AuthHandler;

enum AuthStatus
{
    STATUS_CHALLENGE = 0,
    STATUS_LOGON_PROOF,
    STATUS_RECONNECT_PROOF,
    STATUS_AUTHED,
    STATUS_WAITING_FOR_REALM_LIST,
    STATUS_CLOSED
};

struct AccountInfo
{
    void LoadResult(Field* fields);

    uint32 Id = 0;
    std::string Login;
    bool IsLockedToIP = false;
    std::string LockCountry;
    std::string LastIP;
    uint32 FailedLogins = 0;
    bool IsBanned = false;
    bool IsPermanenetlyBanned = false;
    std::string v;
    std::string s;
    std::string rI;
    AccountTypes SecurityLevel = SEC_PLAYER;
};

// Handle login commands
class AuthSocket: public RealmSocket::Session
{
public:
    const static int s_BYTE_SIZE = 32;
    static std::unordered_map<uint8, AuthHandler> InitHandlers();

    AuthSocket(RealmSocket& socket);
    virtual ~AuthSocket(void);

    virtual void OnRead(void);
    virtual void OnAccept(void);
    virtual void OnClose(void);

    static ACE_INET_Addr const& GetAddressForClient(Realm const& realm, ACE_INET_Addr const& clientAddr);

    bool HandleLogonChallenge();
    bool HandleLogonProof();
    bool HandleReconnectChallenge();
    bool HandleReconnectProof();
    bool HandleRealmList();

    //data transfer handle for patch
    bool HandleXferResume();
    bool HandleXferCancel();
    bool HandleXferAccept();

    void SetVSFields(const std::string& rI);

    void SendPacket(ByteBuffer& packet);

    FILE* pPatch;
    std::mutex patcherLock;

private:
    RealmSocket& socket_;
    RealmSocket& socket(void) { return socket_; }

    BigNumber N, s, g, v;
    BigNumber b, B;
    BigNumber K;
    BigNumber _reconnectProof;

    std::string _login;
    std::string _tokenKey;

    // Since GetLocaleByName() is _NOT_ bijective, we have to store the locale as a string. Otherwise we can't differ
    // between enUS and enGB, which is important for the patch system
    std::string _localizationName;
    std::string _os;
    std::string _ipCountry;
    uint16 _build;
    uint8 _expversion;

    Optional<Trinity::Crypto::SRP6> _srp6;
    SessionKey _sessionKey = {};
    AuthStatus _status;
    AccountInfo _accountInfo;
};

#pragma pack(push, 1)

struct AuthHandler
{
    AuthStatus status;
    size_t packetSize;
    //bool (AuthSession::*handler)();
    bool (AuthSocket::*handler)(void);
};

#pragma pack(pop)

#endif
