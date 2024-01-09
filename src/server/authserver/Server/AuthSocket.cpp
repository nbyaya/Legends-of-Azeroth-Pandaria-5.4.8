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

#include <algorithm>
#include <openssl/md5.h>

#include "BigNumber.h"
#include "Common.h"
#include "CryptoRandom.h"
#include "Database/DatabaseEnv.h"
#include "ByteBuffer.h"
#include "Configuration/Config.h"
#include "Log.h"
#include "RealmList.h"
#include "AuthSocket.h"
#include "AuthCodes.h"
#include "TOTP.h"
#include "SHA1.h"
#include "openssl/crypto.h"
#include "UtilACE.h"
#include "Threading/Threading.h"
#include "IPLocation.h"

#define ChunkSize 2048

enum eAuthCmd
{
    AUTH_LOGON_CHALLENGE                         = 0x00,
    AUTH_LOGON_PROOF                             = 0x01,
    AUTH_RECONNECT_CHALLENGE                     = 0x02,
    AUTH_RECONNECT_PROOF                         = 0x03,
    REALM_LIST                                   = 0x10,
    XFER_INITIATE                                = 0x30,
    XFER_DATA                                    = 0x31,
    XFER_ACCEPT                                  = 0x32,
    XFER_RESUME                                  = 0x33,
    XFER_CANCEL                                  = 0x34
};

// GCC have alternative #pragma pack(N) syntax and old gcc version not support pack(push, N), also any gcc version not support it at some paltform
#if defined(__GNUC__)
#pragma pack(1)
#else
#pragma pack(push, 1)
#endif

typedef struct AUTH_LOGON_CHALLENGE_C
{
    uint8   cmd;
    uint8   error;
    uint16  size;
    uint8   gamename[4];
    uint8   version1;
    uint8   version2;
    uint8   version3;
    uint16  build;
    uint8   platform[4];
    uint8   os[4];
    uint8   country[4];
    uint32  timezone_bias;
    uint32  ip;
    uint8   I_len;
    uint8   I[1];
} sAuthLogonChallenge_C;

typedef struct AUTH_LOGON_PROOF_C
{
    uint8   cmd;
    uint8   A[32];
    uint8   M1[20];
    uint8   crc_hash[20];
    uint8   number_of_keys;
    uint8   securityFlags;                                  // 0x00-0x04
} sAuthLogonProof_C;

typedef struct AUTH_LOGON_PROOF_S
{
    uint8   cmd;
    uint8   error;
    uint8   M2[20];
    uint32  AccountFlags;
    uint32  SurveyId;
    uint16  LoginFlags;
} sAuthLogonProof_S;

typedef struct AUTH_LOGON_PROOF_S_OLD
{
    uint8   cmd;
    uint8   error;
    uint8   M2[20];
    uint32  unk2;
} sAuthLogonProof_S_Old;

typedef struct AUTH_RECONNECT_PROOF_C
{
    uint8   cmd;
    uint8   R1[16];
    uint8   R2[20];
    uint8   R3[20];
    uint8   number_of_keys;
} sAuthReconnectProof_C;

typedef struct XFER_INIT
{
    uint8 cmd;                                              // XFER_INITIATE
    uint8 fileNameLen;                                      // strlen(fileName);
    uint8 fileName[5];                                      // fileName[fileNameLen]
    uint64 file_size;                                       // file size (bytes)
    uint8 md5[MD5_DIGEST_LENGTH];                           // MD5
} XFER_INIT;

typedef struct XFER_DATA
{
    uint8 opcode;
    uint16 data_size;
    uint8 data[ChunkSize];
} XFER_DATA_STRUCT;

// GCC have alternative #pragma pack() syntax and old gcc version not support pack(pop), also any gcc version not support it at some paltform
#if defined(__GNUC__)
#pragma pack()
#else
#pragma pack(pop)
#endif

// Launch a thread to transfer a patch to the client
class PatcherRunnable: public MopCore::Runnable
{
public:
    PatcherRunnable(class AuthSocket*);
    void run();

private:
    AuthSocket* mySocket;
};

typedef struct PATCH_INFO
{
    uint8 md5[MD5_DIGEST_LENGTH];
} PATCH_INFO;

// Caches MD5 hash of client patches present on the server
class Patcher
{
public:
    typedef std::map<std::string, PATCH_INFO*> Patches;
    ~Patcher();
    Patcher();
    Patches::const_iterator begin() const { return _patches.begin(); }
    Patches::const_iterator end() const { return _patches.end(); }
    void LoadPatchMD5(char*);
    bool GetHash(char * pat, uint8 mymd5[16]);

private:
    void LoadPatchesInfo();
    Patches _patches;
};

#define AUTH_LOGON_CHALLENGE_INITIAL_SIZE 4
#define REALM_LIST_PACKET_SIZE 5

std::unordered_map<uint8, AuthHandler> AuthSocket::InitHandlers()
{
    std::unordered_map<uint8, AuthHandler> handlers;

    handlers[AUTH_LOGON_CHALLENGE]      = { STATUS_CHALLENGE, AUTH_LOGON_CHALLENGE_INITIAL_SIZE, &AuthSocket::HandleLogonChallenge };
    handlers[AUTH_LOGON_PROOF]          = { STATUS_LOGON_PROOF, sizeof(AUTH_LOGON_PROOF_C),      &AuthSocket::HandleLogonProof };
    handlers[AUTH_RECONNECT_CHALLENGE]  = { STATUS_CHALLENGE, AUTH_LOGON_CHALLENGE_INITIAL_SIZE, &AuthSocket::HandleReconnectChallenge };
    handlers[AUTH_RECONNECT_PROOF]      = { STATUS_RECONNECT_PROOF, sizeof(AUTH_RECONNECT_PROOF_C),    &AuthSocket::HandleReconnectProof };
    handlers[REALM_LIST]                = { STATUS_AUTHED,    REALM_LIST_PACKET_SIZE,            &AuthSocket::HandleRealmList };
    handlers[XFER_ACCEPT]               = { STATUS_CHALLENGE,    1,             &AuthSocket::HandleXferAccept };
    handlers[XFER_RESUME]               = { STATUS_CHALLENGE,    9,             &AuthSocket::HandleXferResume };
    handlers[XFER_CANCEL]               = { STATUS_CHALLENGE,    1,             &AuthSocket::HandleXferCancel };   

    return handlers;
}

std::unordered_map<uint8, AuthHandler> const Handlers = AuthSocket::InitHandlers();

#define AUTH_TOTAL_COMMANDS 8

// Holds the MD5 hash of client patches present on the server
Patcher PatchesCache;

void AccountInfo::LoadResult(Field* fields)
{

    //          0                1        2       3          4        5     6         7            8             9                                                                10                           
    // SELECT a.sha_pass_hash, a.id, a.locked, a.last_ip, aa.gmlevel, a.v, a.s, a.lock_country, a.failed_logins, ab.unbandate > UNIX_TIMESTAMP() OR ab.unbandate = ab.bandate, ab.unbandate = ab.bandate 
    // FROM account a LEFT JOIN account_access aa ON (a.id = aa.id) LEFT JOIN account_banned ab ON ab.id = a.id AND ab.active = 1 WHERE a.username = ?
    
    rI = fields[0].GetString();
    Id = fields[1].GetUInt32();
    //Login = fields[1].GetString();
    IsLockedToIP = fields[2].GetBool();
    LastIP = fields[3].GetString();
    uint8 secLevel = fields[4].GetUInt8();
    SecurityLevel = (secLevel <= SEC_ADMINISTRATOR ? AccountTypes(secLevel) : SEC_ADMINISTRATOR);
    //SecurityLevel = AccountTypes(fields[4].GetUInt8());
    v = fields[5].GetString();
    s = fields[6].GetString();
    LockCountry = fields[7].GetString();
    FailedLogins = fields[8].GetUInt32();

    IsBanned = fields[9].GetUInt64() != 0;
    IsPermanenetlyBanned = fields[10].GetUInt64() != 0;

    // Use our own uppercasing of the account name instead of using UPPER() in mysql query
    // This is how the account was created in the first place and changing it now would result in breaking
    // login for all accounts having accented characters in their name
    // Utf8ToUpperOnlyLatin(Login);
}

// Constructor - set the N and g values for SRP6
AuthSocket::AuthSocket(RealmSocket& socket) :
    pPatch(NULL), socket_(socket), _status(STATUS_CHALLENGE), _build(0),
    _expversion(0)
{
    N.SetHexStr("894B645E89E1535BBDAD5B8B290650530801B18EBFBF5E8FAB3C82872A3E9BB7");
    g.SetDword(7);
}

// Close patch file descriptor before leaving
AuthSocket::~AuthSocket(void) { }

// Accept the connection
void AuthSocket::OnAccept(void)
{
    TC_LOG_DEBUG("server.authserver", "'%s:%d' Accepting connection", socket().getRemoteAddress().c_str(), socket().getRemotePort());
}

void AuthSocket::OnClose(void)
{
    TC_LOG_DEBUG("server.authserver", "AuthSocket::OnClose");
}

// Read the packet from the client
void AuthSocket::OnRead()
{
#define MAX_AUTH_LOGON_CHALLENGES_IN_A_ROW 3
    uint32 challengesInARow = 0;

#define MAX_AUTH_GET_REALM_LIST 10
    uint32 challengesInARowRealmList = 0;

    uint8 _cmd;
    while (1)
    {
        if (!socket().recv_soft((char *)&_cmd, 1))
            return;

        auto itr = Handlers.find(_cmd);
        if (itr == Handlers.end())
        {
            // well we dont handle this, lets just ignore it
            // packet.Reset();
            // break;
            TC_LOG_ERROR("server.authserver", "Got unknown packet from '%s'", socket().getRemoteAddress().c_str());
            socket().shutdown();
            return;            
        }

        if (_status != itr->second.status)
        {
            socket().shutdown();
            return; 
        }

        // uint16 size = uint16(itr->second.packetSize);
        // if (packet.GetActiveSize() < size)
        //     break;


        if (_cmd == AUTH_LOGON_CHALLENGE)
        {
            ++challengesInARow;
            if (challengesInARow == MAX_AUTH_LOGON_CHALLENGES_IN_A_ROW)
            {
                TC_LOG_WARN("server.authserver", "Got %u AUTH_LOGON_CHALLENGE in a row from '%s', possible ongoing DoS", challengesInARow, socket().getRemoteAddress().c_str());
                socket().shutdown();
                return;
            }
        }
        else if (_cmd == REALM_LIST) {
            challengesInARowRealmList++;
            if (challengesInARowRealmList == MAX_AUTH_GET_REALM_LIST)
            {
                TC_LOG_WARN("server.authserver", "Got %u REALMLIST in a row from '%s', possible ongoing DoS", challengesInARowRealmList, socket().getRemoteAddress().c_str());
                socket().shutdown();
                return;
            }
        }

        if (!(*this.*itr->second.handler)())
        {
            TC_LOG_DEBUG("server.authserver", "Command handler failed for cmd %u recv length %u", (uint32)_cmd, (uint32)socket().recv_len());
            return;
        }

    }
}

void AuthSocket::SendPacket(ByteBuffer& packet)
{
    socket().send((char const*)packet.contents(), packet.size());
}

// Make the SRP6 calculation from hash in dB
void AuthSocket::SetVSFields(const std::string& rI)
{
    s.SetRand(s_BYTE_SIZE * 8);

    BigNumber I;
    I.SetHexStr(rI.c_str());

    // In case of leading zeros in the rI hash, restore them
    uint8 mDigest[SHA_DIGEST_LENGTH];
    memset(mDigest, 0, SHA_DIGEST_LENGTH);
    if (I.GetNumBytes() <= SHA_DIGEST_LENGTH)
        memcpy(mDigest, I.AsByteArray(), I.GetNumBytes());

    std::reverse(mDigest, mDigest + SHA_DIGEST_LENGTH);

    SHA1Hash sha;
    sha.UpdateData(s.AsByteArray(), s.GetNumBytes());
    sha.UpdateData(mDigest, SHA_DIGEST_LENGTH);
    sha.Finalize();
    BigNumber x;
    x.SetBinary(sha.GetDigest(), sha.GetLength());
    v = g.ModExp(x, N);

    // No SQL injection (username escaped)
    char *v_hex, *s_hex;
    v_hex = v.AsHexStr();
    s_hex = s.AsHexStr();

    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_VS);
    stmt->setString(0, v_hex);
    stmt->setString(1, s_hex);
    stmt->setString(2, _login);
    LoginDatabase.Execute(stmt);

    OPENSSL_free(v_hex);
    OPENSSL_free(s_hex);
}

// Logon Challenge command handler
bool AuthSocket::HandleLogonChallenge()
{
    _status = STATUS_CLOSED;

    TC_LOG_DEBUG("server.authserver", "Entering _HandleLogonChallenge");
    if (socket().recv_len() < sizeof(sAuthLogonChallenge_C))
        return false;

    // Read the first 4 bytes (header) to get the length of the remaining of the packet
    std::vector<uint8> buf;
    buf.resize(4);

    socket().recv((char *)&buf[0], 4);

    EndianConvertPtr<uint16>(&buf[0]);

    uint16 remaining = ((sAuthLogonChallenge_C *)&buf[0])->size;
    TC_LOG_DEBUG("server.authserver", "[AuthChallenge] got header, body is %#04x bytes", remaining);

    if ((remaining < sizeof(sAuthLogonChallenge_C) - buf.size()) || (socket().recv_len() < remaining))
        return false;

    //No big fear of memory outage (size is int16, i.e. < 65536)
    buf.resize(remaining + buf.size() + 1);
    buf[buf.size() - 1] = 0;
    sAuthLogonChallenge_C *ch = (sAuthLogonChallenge_C*)&buf[0];

    // Read the remaining of the packet
    socket().recv((char *)&buf[4], remaining);
    TC_LOG_DEBUG("server.authserver", "[AuthChallenge] got full packet, %#04x bytes", ch->size);
    TC_LOG_DEBUG("server.authserver", "[AuthChallenge] name(%d): '%s'", ch->I_len, ch->I);

    // BigEndian code, nop in little endian case
    // size already converted
    EndianConvertPtr<uint32>(&ch->gamename[0]);
    EndianConvert(ch->build);
    EndianConvertPtr<uint32>(&ch->platform[0]);
    EndianConvertPtr<uint32>(&ch->os[0]);
    EndianConvertPtr<uint32>(&ch->country[0]);
    EndianConvert(ch->timezone_bias);
    EndianConvert(ch->ip);

    ByteBuffer pkt;

    _login = (const char*)ch->I;
    _build = ch->build;
    _expversion = uint8(AuthHelper::IsPostBCAcceptedClientBuild(_build) ? POST_BC_EXP_FLAG : (AuthHelper::IsPreBCAcceptedClientBuild(_build) ? PRE_BC_EXP_FLAG : NO_VALID_EXP_FLAG));
    _os = (const char*)ch->os;

    if (_os.size() > 4)
        return false;

    // Restore string order as its byte order is reversed
    std::reverse(_os.begin(), _os.end());

    pkt << uint8(AUTH_LOGON_CHALLENGE);
    pkt << uint8(0x00);

    // Verify that this IP is not in the ip_banned table
    LoginDatabase.Execute(LoginDatabase.GetPreparedStatement(LOGIN_DEL_EXPIRED_IP_BANS));

    std::string const& ip_address = socket().getRemoteAddress();
    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_IP_BANNED);
    stmt->setString(0, ip_address);
    PreparedQueryResult result = LoginDatabase.Query(stmt);
    if (result)
    {
        pkt << uint8(WOW_FAIL_BANNED);
        SendPacket(pkt);
        TC_LOG_DEBUG("server.authserver", "'%s:%d' [AuthChallenge] Banned ip tries to login!", socket().getRemoteAddress().c_str(), socket().getRemotePort());
        return true;
    }
    else
    {
        // Get the account details from the account table
        // No SQL injection (prepared statement)
        stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_LOGONCHALLENGE);
        stmt->setString(0, _login);

        PreparedQueryResult res2 = LoginDatabase.Query(stmt);
        if (!res2)
        {
            pkt << uint8(WOW_FAIL_UNKNOWN_ACCOUNT);
            SendPacket(pkt);
            return true;
        }        

        Field* fields = res2->Fetch();
        _accountInfo.LoadResult(fields);

        // If the IP is 'locked', check that the player comes indeed from the correct IP address
        if (_accountInfo.IsLockedToIP)                  // if ip is locked
        {
            TC_LOG_DEBUG("server.authserver", "[AuthChallenge] Account '%s' is locked to IP - '%s' is logging in from '%s'", _login.c_str(), _accountInfo.LastIP.c_str(), ip_address.c_str());
            if (_accountInfo.LastIP != ip_address)
            {
                TC_LOG_DEBUG("server.authserver", "[AuthChallenge] Account IP differs");
                pkt << uint8(WOW_FAIL_LOCKED_ENFORCED);
                SendPacket(pkt);
                return true;
            }
                
        }
        else
        {
            if (IpLocationRecord const* location = sIPLocation->GetLocationRecord(ip_address))
                _ipCountry = location->CountryCode;
            TC_LOG_DEBUG("server.authserver", "[AuthChallenge] Account '%s' is not locked to ip", _login.c_str());
            if (_accountInfo.LockCountry.empty() || _accountInfo.LockCountry == "00")
                TC_LOG_DEBUG("server.authserver", "[AuthChallenge] Account '%s' is not locked to country", _login.c_str());
            else if (!_ipCountry.empty())
            {
                TC_LOG_DEBUG("server.authserver", "[AuthChallenge] Account '%s' is locked to country: '%s' Player country is '%s'", _login.c_str(), _accountInfo.LockCountry.c_str(), _ipCountry.c_str());
                if (_ipCountry != _accountInfo.LockCountry)
                {
                    pkt << uint8(WOW_FAIL_UNLOCKABLE_LOCK);
                    SendPacket(pkt);
                    return true;
                }
            }
        }
        TC_LOG_DEBUG("server.authserver", "[AuthChallenge] Account '%s' is not locked to ip", _login.c_str());
        //set expired bans to inactive
        LoginDatabase.DirectExecute(LoginDatabase.GetPreparedStatement(LOGIN_UPD_EXPIRED_ACCOUNT_BANS));

        if (_accountInfo.IsBanned)
        {
            if (_accountInfo.IsPermanenetlyBanned)
            {
                pkt << uint8(WOW_FAIL_BANNED);
                TC_LOG_DEBUG("server.authserver", "'%s:%d' [AuthChallenge] Banned account %s tried to login!", socket().getRemoteAddress().c_str(), socket().getRemotePort(), _login.c_str ());
                SendPacket(pkt);
                return true;
            }
            else
            {
                pkt << uint8(WOW_FAIL_SUSPENDED);
                TC_LOG_DEBUG("server.authserver", "'%s:%d' [AuthChallenge] Temporarily banned account %s tried to login!", socket().getRemoteAddress().c_str(), socket().getRemotePort(), _login.c_str ());
                SendPacket(pkt);
                return true;                
            }
        }
        // Get the password from the account table, upper it, and make the SRP6 calculation
        // Don't calculate (v, s) if there are already some in the database
        TC_LOG_DEBUG("network", "database authentication values: v='%s' s='%s'", _accountInfo.s.c_str(), _accountInfo.v.c_str());

        // multiply with 2 since bytes are stored as hexstring
        if (_accountInfo.v.size() != s_BYTE_SIZE * 2 || _accountInfo.s.size() != s_BYTE_SIZE * 2)
            SetVSFields(_accountInfo.rI);
        else
        {
            s.SetHexStr(_accountInfo.s.c_str());
            v.SetHexStr(_accountInfo.v.c_str());
        }

        b.SetRand(19 * 8);
        BigNumber gmod = g.ModExp(b, N);
        B = ((v * 3) + gmod) % N;

        ASSERT(gmod.GetNumBytes() <= 32);

        BigNumber unk3;
        unk3.SetRand(16 * 8);

        // Fill the response packet with the result
        if (AuthHelper::IsAcceptedClientBuild(_build))
            pkt << uint8(WOW_SUCCESS);
        else
            pkt << uint8(WOW_FAIL_VERSION_INVALID);

        // B may be calculated < 32B so we force minimal length to 32B
        pkt.append(B.AsByteArray(32), 32);      // 32 bytes
        pkt << uint8(1);
        pkt.append(g.AsByteArray(), 1);
        pkt << uint8(32);
        pkt.append(N.AsByteArray(32), 32);
        pkt.append(s.AsByteArray(), s.GetNumBytes());   // 32 bytes
        pkt.append(unk3.AsByteArray(16), 16);
        uint8 securityFlags = 0;

        // Check if token is used
        /*_tokenKey = fields[7].GetString();
        if (!_tokenKey.empty())
            securityFlags = 4;*/

        pkt << uint8(securityFlags);            // security flags (0x0...0x04)

        if (securityFlags & 0x01)               // PIN input
        {
            pkt << uint32(0);
            pkt << uint64(0) << uint64(0);      // 16 bytes hash?
        }

        if (securityFlags & 0x02)               // Matrix input
        {
            pkt << uint8(0);
            pkt << uint8(0);
            pkt << uint8(0);
            pkt << uint8(0);
            pkt << uint64(0);
        }

        if (securityFlags & 0x04)               // Security token input
            pkt << uint8(1);

        _localizationName.resize(4);
        for (int i = 0; i < 4; ++i)
            _localizationName[i] = ch->country[4-i-1];

        TC_LOG_DEBUG("server.authserver", "'%s:%d' [AuthChallenge] account %s is using '%c%c%c%c' locale (%u)", socket().getRemoteAddress().c_str(), socket().getRemotePort(),
                _login.c_str (), ch->country[3], ch->country[2], ch->country[1], ch->country[0], GetLocaleByName(_localizationName));

        _status = STATUS_LOGON_PROOF;
            
    }

    SendPacket(pkt);
    return true;
}

// Logon Proof command handler
bool AuthSocket::HandleLogonProof()
{
    TC_LOG_DEBUG("server.authserver", "Entering _HandleLogonProof");
    _status = STATUS_CLOSED;
    // Read the packet
    sAuthLogonProof_C lp;

    if (!socket().recv((char *)&lp, sizeof(sAuthLogonProof_C)))
        return false;

    // If the client has no valid version
    if (_expversion == NO_VALID_EXP_FLAG)
    {
        // Check if we have the appropriate patch on the disk
        TC_LOG_DEBUG("network", "Client with invalid version, patching is not implemented");
        socket().shutdown();
        return true;
    }

    // Continue the SRP6 calculation based on data received from the client
    BigNumber A;

    A.SetBinary(lp.A, 32);

    // SRP safeguard: abort if A == 0
    if (A.IsZero())
    {
        socket().shutdown();
        return true;
    }

    SHA1Hash sha;
    sha.UpdateBigNumbers(&A, &B, NULL);
    sha.Finalize();
    BigNumber u;
    u.SetBinary(sha.GetDigest(), 20);
    BigNumber S = (A * (v.ModExp(u, N))).ModExp(b, N);

    uint8 t[32];
    uint8 t1[16];
    uint8 vK[40];
    memcpy(t, S.AsByteArray(32), 32);

    for (int i = 0; i < 16; ++i)
        t1[i] = t[i * 2];

    sha.Initialize();
    sha.UpdateData(t1, 16);
    sha.Finalize();

    for (int i = 0; i < 20; ++i)
        vK[i * 2] = sha.GetDigest()[i];

    for (int i = 0; i < 16; ++i)
        t1[i] = t[i * 2 + 1];

    sha.Initialize();
    sha.UpdateData(t1, 16);
    sha.Finalize();

    for (int i = 0; i < 20; ++i)
        vK[i * 2 + 1] = sha.GetDigest()[i];

    K.SetBinary(vK, 40);

    uint8 hash[20];

    sha.Initialize();
    sha.UpdateBigNumbers(&N, NULL);
    sha.Finalize();
    memcpy(hash, sha.GetDigest(), 20);
    sha.Initialize();
    sha.UpdateBigNumbers(&g, NULL);
    sha.Finalize();

    for (int i = 0; i < 20; ++i)
        hash[i] ^= sha.GetDigest()[i];

    BigNumber t3;
    t3.SetBinary(hash, 20);

    sha.Initialize();
    sha.UpdateData(_login);
    sha.Finalize();
    uint8 t4[SHA_DIGEST_LENGTH];
    memcpy(t4, sha.GetDigest(), SHA_DIGEST_LENGTH);

    sha.Initialize();
    sha.UpdateBigNumbers(&t3, NULL);
    sha.UpdateData(t4, SHA_DIGEST_LENGTH);
    sha.UpdateBigNumbers(&s, &A, &B, &K, NULL);
    sha.Finalize();
    BigNumber M;
    M.SetBinary(sha.GetDigest(), 20);

    // Check if SRP6 results match (password is correct), else send an error
    if (!memcmp(M.AsByteArray(), lp.M1, 20))
    {
        TC_LOG_DEBUG("server.authserver", "'%s:%d' User '%s' successfully authenticated", socket().getRemoteAddress().c_str(), socket().getRemotePort(), _login.c_str());

        // Update the sessionkey, last_ip, last login time and reset number of failed logins in the account table for this account
        // No SQL injection (escaped user name) and IP address as received by socket
        const char *K_hex = K.AsHexStr();

        LoginDatabasePreparedStatement *stmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_LOGONPROOF);
        stmt->setString(0, K_hex);
        stmt->setString(1, socket().getRemoteAddress().c_str());
        stmt->setUInt32(2, GetLocaleByName(_localizationName));
        stmt->setString(3, _os);
        stmt->setString(4, _login);
        LoginDatabase.DirectExecute(stmt);

        OPENSSL_free((void*)K_hex);

        // Finish SRP6 and send the final result to the client
        sha.Initialize();
        sha.UpdateBigNumbers(&A, &M, &K, NULL);
        sha.Finalize();

        // Check auth token
        if ((lp.securityFlags & 0x04) || !_tokenKey.empty())
        {
            uint8 size;
            socket().recv((char*)&size, 1);
            char* token = new char[size + 1];
            token[size] = '\0';
            socket().recv(token, size);
            unsigned int validToken = TOTP::GenerateToken(_tokenKey.c_str());
            unsigned int incomingToken = atoi(token);
            delete [] token;
            if (validToken != incomingToken)
            {
                ByteBuffer packet;
                packet << uint8(AUTH_LOGON_PROOF);
                packet << uint8(WOW_FAIL_UNKNOWN_ACCOUNT);
                packet << uint8(3);    // LoginFlags, 1 has account message
                packet << uint8(0);
                SendPacket(packet);
                return false;
            }
        }

        ByteBuffer packet;
        if (_expversion & POST_BC_EXP_FLAG)                 // 2.x and 3.x clients
        {
            sAuthLogonProof_S proof;
            memcpy(proof.M2, sha.GetDigest(), 20);
            proof.cmd = AUTH_LOGON_PROOF;
            proof.error = 0;
            proof.AccountFlags = 0x00800000;    // Accountflags. 0x01 = GM, 0x08 = Trial, 0x00800000 = Pro pass (arena tournament)
            proof.SurveyId = 0x00;          // SurveyId
            proof.LoginFlags = 0x00;

            packet.resize(sizeof(proof));
            std::memcpy(packet.contents(), &proof, sizeof(proof));
        }
        else
        {
            sAuthLogonProof_S_Old proof;
            memcpy(proof.M2, sha.GetDigest(), 20);
            proof.cmd = AUTH_LOGON_PROOF;
            proof.error = 0;
            proof.unk2 = 0x00;

            packet.resize(sizeof(proof));
            std::memcpy(packet.contents(), &proof, sizeof(proof));
        }

        SendPacket(packet);
        _status = STATUS_AUTHED;
    }
    else
    {
        ByteBuffer packet;
        packet << uint8(AUTH_LOGON_PROOF);
        packet << uint8(WOW_FAIL_UNKNOWN_ACCOUNT);
        packet << uint8(3);    // LoginFlags, 1 has account message
        packet << uint8(0);
        SendPacket(packet);

        TC_LOG_DEBUG("server.authserver", "'%s:%d' [AuthChallenge] account %s tried to login with invalid password!", socket().getRemoteAddress().c_str(), socket().getRemotePort(), _login.c_str ());

        uint32 MaxWrongPassCount = sConfigMgr->GetIntDefault("WrongPass.MaxCount", 0);
        if (MaxWrongPassCount > 0)
        {
            //Increment number of failed logins by one and if it reaches the limit temporarily ban that account or IP
            LoginDatabasePreparedStatement *stmt = LoginDatabase.GetPreparedStatement(LOGIN_UPD_FAILEDLOGINS);
            stmt->setString(0, _login);
            LoginDatabase.Execute(stmt);

            stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_FAILEDLOGINS);
            stmt->setString(0, _login);

            if (PreparedQueryResult loginfail = LoginDatabase.Query(stmt))
            {
                uint32 failed_logins = (*loginfail)[1].GetUInt32();

                if (failed_logins >= MaxWrongPassCount)
                {
                    uint32 WrongPassBanTime = sConfigMgr->GetIntDefault("WrongPass.BanTime", 600);
                    bool WrongPassBanType = sConfigMgr->GetBoolDefault("WrongPass.BanType", false);

                    if (WrongPassBanType)
                    {
                        uint32 acc_id = (*loginfail)[0].GetUInt32();
                        stmt = LoginDatabase.GetPreparedStatement(LOGIN_INS_ACCOUNT_AUTO_BANNED);
                        stmt->setUInt32(0, acc_id);
                        stmt->setUInt32(1, WrongPassBanTime);
                        LoginDatabase.Execute(stmt);

                        TC_LOG_DEBUG("server.authserver", "'%s:%d' [AuthChallenge] account %s got banned for '%u' seconds because it failed to authenticate '%u' times",
                            socket().getRemoteAddress().c_str(), socket().getRemotePort(), _login.c_str(), WrongPassBanTime, failed_logins);
                    }
                    else
                    {
                        stmt = LoginDatabase.GetPreparedStatement(LOGIN_INS_IP_AUTO_BANNED);
                        stmt->setString(0, socket().getRemoteAddress());
                        stmt->setUInt32(1, WrongPassBanTime);
                        LoginDatabase.Execute(stmt);

                        TC_LOG_DEBUG("server.authserver", "'%s:%d' [AuthChallenge] IP %s got banned for '%u' seconds because account %s failed to authenticate '%u' times",
                            socket().getRemoteAddress().c_str(), socket().getRemotePort(), socket().getRemoteAddress().c_str(), WrongPassBanTime, _login.c_str(), failed_logins);
                    }
                }
            }
        }
    }

    return true;
}

// Reconnect Challenge command handler
bool AuthSocket::HandleReconnectChallenge()
{
    _status = STATUS_CLOSED;

    TC_LOG_DEBUG("server.authserver", "Entering _HandleReconnectChallenge");
    if (socket().recv_len() < sizeof(sAuthLogonChallenge_C))
        return false;

    // Read the first 4 bytes (header) to get the length of the remaining of the packet
    std::vector<uint8> buf;
    buf.resize(4);

    socket().recv((char *)&buf[0], 4);

    EndianConvertPtr<uint16>(&buf[0]);

    uint16 remaining = ((sAuthLogonChallenge_C *)&buf[0])->size;
    TC_LOG_DEBUG("server.authserver", "[ReconnectChallenge] got header, body is %#04x bytes", remaining);

    if ((remaining < sizeof(sAuthLogonChallenge_C) - buf.size()) || (socket().recv_len() < remaining))
        return false;

    // No big fear of memory outage (size is int16, i.e. < 65536)
    buf.resize(remaining + buf.size() + 1);
    buf[buf.size() - 1] = 0;
    sAuthLogonChallenge_C *ch = (sAuthLogonChallenge_C*)&buf[0];

    // Read the remaining of the packet
    socket().recv((char *)&buf[4], remaining);
    TC_LOG_DEBUG("server.authserver", "[ReconnectChallenge] got full packet, %#04x bytes", ch->size);
    TC_LOG_DEBUG("server.authserver", "[ReconnectChallenge] name(%d): '%s'", ch->I_len, ch->I);

    _login = (const char*)ch->I;

    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_SESSIONKEY);
    stmt->setString(0, _login);
    PreparedQueryResult result = LoginDatabase.Query(stmt);

    // Stop if the account is not found
    if (!result)
    {
        TC_LOG_ERROR("server.authserver", "'%s:%d' [ERROR] user %s tried to login and we cannot find his session key in the database.", socket().getRemoteAddress().c_str(), socket().getRemotePort(), _login.c_str());
        socket().shutdown();
        return false;
    }

    // Reinitialize build, expansion and the account securitylevel
    _build = ch->build;
    _expversion = uint8(AuthHelper::IsPostBCAcceptedClientBuild(_build) ? POST_BC_EXP_FLAG : (AuthHelper::IsPreBCAcceptedClientBuild(_build) ? PRE_BC_EXP_FLAG : NO_VALID_EXP_FLAG));
    _os = (const char*)ch->os;

    if (_os.size() > 4)
        return false;

    // Restore string order as its byte order is reversed
    std::reverse(_os.begin(), _os.end());

    Field* fields = result->Fetch();
    uint8 secLevel = fields[2].GetUInt8();
    _accountInfo.SecurityLevel = secLevel <= SEC_ADMINISTRATOR ? AccountTypes(secLevel) : SEC_ADMINISTRATOR;

    K.SetHexStr ((*result)[0].GetCString());

    // Sending response
    ByteBuffer pkt;
    pkt << uint8(AUTH_RECONNECT_CHALLENGE);

    _status = STATUS_RECONNECT_PROOF;
    pkt << uint8(0x00);
    _reconnectProof.SetRand(16 * 8);
    pkt.append(_reconnectProof.AsByteArray(16), 16);        // 16 bytes random
    pkt << uint64(0x00) << uint64(0x00);                    // 16 bytes zeros
    SendPacket(pkt);
    return true;
}

// Reconnect Proof command handler
bool AuthSocket::HandleReconnectProof()
{
    TC_LOG_DEBUG("server.authserver", "Entering _HandleReconnectProof");
    _status = STATUS_CLOSED;

    // Read the packet
    sAuthReconnectProof_C lp;
    if (!socket().recv((char *)&lp, sizeof(sAuthReconnectProof_C)))
        return false;

    if (_login.empty() || !_reconnectProof.GetNumBytes() || !K.GetNumBytes())
        return false;

    BigNumber t1;
    t1.SetBinary(lp.R1, 16);

    SHA1Hash sha;
    sha.Initialize();
    sha.UpdateData(_login);
    sha.UpdateBigNumbers(&t1, &_reconnectProof, &K, NULL);
    sha.Finalize();

    if (!memcmp(sha.GetDigest(), lp.R2, SHA_DIGEST_LENGTH))
    {
        // Sending response
        ByteBuffer pkt;
        pkt << uint8(AUTH_RECONNECT_PROOF);
        pkt << uint8(0x00);
        pkt << uint16(0x00);                               // 2 bytes zeros
        SendPacket(pkt);
        _status = STATUS_AUTHED;
        return true;
    }
    else
    {
        TC_LOG_ERROR("server.authserver", "'%s:%d' [ERROR] user %s tried to login, but session is invalid.", socket().getRemoteAddress().c_str(), socket().getRemotePort(), _login.c_str());
        socket().shutdown();
        return false;
    }
}

ACE_INET_Addr const& AuthSocket::GetAddressForClient(Realm const& realm, ACE_INET_Addr const& clientAddr)
{
    return *realm.ExternalAddress;
}

// Realm List command handler
bool AuthSocket::HandleRealmList()
{
    TC_LOG_DEBUG("server.authserver", "Entering _HandleRealmList");
    if (socket().recv_len() < 5)
        return false;

    socket().recv_skip(5);

    // Get the user id (else close the connection)
    // No SQL injection (prepared statement)
    LoginDatabasePreparedStatement* stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_ACCOUNT_ID_BY_NAME);
    stmt->setString(0, _login);
    PreparedQueryResult result = LoginDatabase.Query(stmt);
    if (!result)
    {
        TC_LOG_ERROR("server.authserver", "'%s:%d' [ERROR] user %s tried to login but we cannot find him in the database.", socket().getRemoteAddress().c_str(), socket().getRemotePort(), _login.c_str());
        socket().shutdown();
        return false;
    }

    Field* fields = result->Fetch();
    uint32 id = fields[0].GetUInt32();

    // Update realm list if need
    sRealmList->UpdateIfNeed();

    ACE_INET_Addr clientAddr;
    socket().peer().get_remote_addr(clientAddr);

    // Circle through realms in the RealmList and construct the return packet (including # of user characters in each realm)
    ByteBuffer pkt;

    size_t RealmListSize = 0;
    for (auto& [realmHandle, realm] : sRealmList->GetRealms())
    {
        // don't work with realms which not compatible with the client
        bool okBuild = ((_expversion & POST_BC_EXP_FLAG) && realm.Build == _build) || ((_expversion & PRE_BC_EXP_FLAG) && !AuthHelper::IsPreBCAcceptedClientBuild(realm.Build));

        // No SQL injection. id of realm is controlled by the database.
        uint32 flag = realm.Flags;
        RealmBuildInfo const* buildInfo = sRealmList->GetBuildInfo(realm.Build);
        if (!okBuild)
        {
            if (!buildInfo)
                continue;

            flag |= REALM_FLAG_OFFLINE | REALM_FLAG_SPECIFYBUILD;   // tell the client what build the realm is for
        }

        if (!buildInfo)
            flag &= ~REALM_FLAG_SPECIFYBUILD;

        std::string name = realm.Name;
        if (_expversion & PRE_BC_EXP_FLAG && flag & REALM_FLAG_SPECIFYBUILD)
        {
            std::ostringstream ss;
            ss << name << " (" << buildInfo->MajorVersion << '.' << buildInfo->MinorVersion << '.' << buildInfo->BugfixVersion << ')';
            name = ss.str();
        }

        // We don't need the port number from which client connects with but the realm's port
        clientAddr.set_port_number(realm.ExternalAddress->get_port_number());

        uint8 lock = (realm.AllowedSecurityLevel > _accountInfo.SecurityLevel) ? 1 : 0;

        uint8 AmountOfCharacters = 0;
        stmt = LoginDatabase.GetPreparedStatement(LOGIN_SEL_NUM_CHARS_ON_REALM);
        stmt->setUInt32(0, realm.Id.Realm);
        stmt->setUInt32(1, id);
        result = LoginDatabase.Query(stmt);

        _status = STATUS_WAITING_FOR_REALM_LIST;
        
        if (result)
            AmountOfCharacters = (*result)[0].GetUInt8();

        pkt << realm.Type;                                  // realm type
        if (_expversion & POST_BC_EXP_FLAG)                 // only 2.x and 3.x clients
            pkt << lock;                                    // if 1, then realm locked
        pkt << uint8(flag);                                 // RealmFlags
        pkt << name;
        pkt << GetAddressString(GetAddressForClient(realm, clientAddr));
        pkt << realm.PopulationLevel;
        pkt << AmountOfCharacters;
        pkt << realm.Timezone;                              // realm category
        if (_expversion & POST_BC_EXP_FLAG)                 // 2.x and 3.x clients
            pkt << uint8(realm.Id.Realm);                   
        else
            pkt << uint8(0x0);                              // 1.12.1 and 1.12.2 clients

        if (_expversion & POST_BC_EXP_FLAG && flag & REALM_FLAG_SPECIFYBUILD)
        {
            pkt << uint8(buildInfo->MajorVersion);
            pkt << uint8(buildInfo->MinorVersion);
            pkt << uint8(buildInfo->BugfixVersion);
            pkt << uint16(buildInfo->Build);
        }

        ++RealmListSize;
    }

    if (_expversion & POST_BC_EXP_FLAG)                     // 2.x and 3.x clients
    {
        pkt << uint8(0x10);
        pkt << uint8(0x00);
    }
    else                                                    // 1.12.1 and 1.12.2 clients
    {
        pkt << uint8(0x00);
        pkt << uint8(0x02);
    }

    // make a ByteBuffer which stores the RealmList's size
    ByteBuffer RealmListSizeBuffer;
    RealmListSizeBuffer << uint32(0);
    if (_expversion & POST_BC_EXP_FLAG)                     // only 2.x and 3.x clients
        RealmListSizeBuffer << uint16(RealmListSize);
    else
        RealmListSizeBuffer << uint32(RealmListSize);

    ByteBuffer hdr;
    hdr << uint8(REALM_LIST);
    hdr << uint16(pkt.size() + RealmListSizeBuffer.size());
    hdr.append(RealmListSizeBuffer);                        // append RealmList's size buffer
    hdr.append(pkt);                                        // append realms in the realmlist

    SendPacket(hdr);

    _status = STATUS_AUTHED;
    return true;
}

// Resume patch transfer
bool AuthSocket::HandleXferResume()
{
    TC_LOG_DEBUG("server.authserver", "Entering _HandleXferResume");
    // Check packet length and patch existence
    if (socket().recv_len() < 9 || !pPatch) // FIXME: pPatch is never used
    {
        TC_LOG_ERROR("server.authserver", "Error while resuming patch transfer (wrong packet)");
        return false;
    }

    // Launch a PatcherRunnable thread starting at given patch file offset
    uint64 start;
    socket().recv_skip(1);
    socket().recv((char*)&start, sizeof(start));
    fseek(pPatch, long(start), 0);

    MopCore::Thread u(new PatcherRunnable(this));
    return true;
}

// Cancel patch transfer
bool AuthSocket::HandleXferCancel()
{
    TC_LOG_DEBUG("server.authserver", "Entering _HandleXferCancel");

    // Close and delete the socket
    socket().recv_skip(1);                                         //clear input buffer
    socket().shutdown();

    return true;
}

// Accept patch transfer
bool AuthSocket::HandleXferAccept()
{
    TC_LOG_DEBUG("server.authserver", "Entering _HandleXferAccept");

    // Check packet length and patch existence
    if (!pPatch)
    {
        TC_LOG_ERROR("server.authserver", "Error while accepting patch transfer (wrong packet)");
        return false;
    }

    // Launch a PatcherRunnable thread, starting at the beginning of the patch file
    socket().recv_skip(1);                                         // clear input buffer
    fseek(pPatch, 0, 0);

    MopCore::Thread u(new PatcherRunnable(this));
    return true;
}

PatcherRunnable::PatcherRunnable(class AuthSocket* as)
{
    mySocket = as;
}

// Send content of patch file to the client
void PatcherRunnable::run() { }

// Preload MD5 hashes of existing patch files on server
#ifndef _WIN32
#include <dirent.h>
#include <errno.h>
void Patcher::LoadPatchesInfo()
{
    DIR *dirp;
    struct dirent *dp;
    dirp = opendir("./patches/");

    if (!dirp)
        return;

    while (dirp)
    {
        errno = 0;
        if ((dp = readdir(dirp)) != NULL)
        {
            int l = strlen(dp->d_name);

            if (l < 8)
                continue;

            if (!memcmp(&dp->d_name[l - 4], ".mpq", 4))
                LoadPatchMD5(dp->d_name);
        }
        else
        {
            if (errno != 0)
            {
                closedir(dirp);
                return;
            }
            break;
        }
    }

    if (dirp)
        closedir(dirp);
}
#else
void Patcher::LoadPatchesInfo()
{
    WIN32_FIND_DATA fil;
    HANDLE hFil = FindFirstFile("./patches/*.mpq", &fil);
    if (hFil == INVALID_HANDLE_VALUE)
        return;                                             // no patches were found

    do
        LoadPatchMD5(fil.cFileName);
    while (FindNextFile(hFil, &fil));
}
#endif

// Calculate and store MD5 hash for a given patch file
void Patcher::LoadPatchMD5(char *szFileName)
{
    // Try to open the patch file
    std::string path = "./patches/";
    path += szFileName;
    FILE* pPatch = fopen(path.c_str(), "rb");
    TC_LOG_DEBUG("network", "Loading patch info from %s\n", path.c_str());

    if (!pPatch)
    {
        TC_LOG_ERROR("server.authserver", "Error loading patch %s\n", path.c_str());
        return;
    }

    // Calculate the MD5 hash
    MD5_CTX ctx;
    MD5_Init(&ctx);
    uint8* buf = new uint8[512 * 1024];

    while (!feof(pPatch))
    {
        size_t read = fread(buf, 1, 512 * 1024, pPatch);
        MD5_Update(&ctx, buf, read);
    }

    delete [] buf;
    fclose(pPatch);

    // Store the result in the internal patch hash map
    _patches[path] = new PATCH_INFO;
    MD5_Final((uint8 *)&_patches[path]->md5, &ctx);
}

// Get cached MD5 hash for a given patch file
bool Patcher::GetHash(char * pat, uint8 mymd5[16])
{
    for (Patches::iterator i = _patches.begin(); i != _patches.end(); ++i)
        if (!stricmp(pat, i->first.c_str()))
        {
            memcpy(mymd5, i->second->md5, 16);
            return true;
        }

    return false;
}

// Launch the patch hashing mechanism on object creation
Patcher::Patcher()
{
    LoadPatchesInfo();
}

// Empty and delete the patch map on termination
Patcher::~Patcher()
{
    for (Patches::iterator i = _patches.begin(); i != _patches.end(); ++i)
        delete i->second;
}
