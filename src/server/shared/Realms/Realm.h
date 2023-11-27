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

#ifndef Realm_h__
#define Realm_h__

#include <ace/Null_Mutex.h>
#include <ace/INET_Addr.h>
#include "Common.h"

enum RealmFlags
{
    REALM_FLAG_NONE                              = 0x00,
    REALM_FLAG_INVALID                           = 0x01,
    REALM_FLAG_OFFLINE                           = 0x02,
    REALM_FLAG_SPECIFYBUILD                      = 0x04,
    REALM_FLAG_UNK1                              = 0x08,
    REALM_FLAG_UNK2                              = 0x10,
    REALM_FLAG_RECOMMENDED                       = 0x20,
    REALM_FLAG_NEW                               = 0x40,
    REALM_FLAG_FULL                              = 0x80
};

struct TC_SHARED_API RealmHandle
{
    RealmHandle() : Realm(0) { }
    RealmHandle(uint32 index) : Realm(index) { }

    uint32 Realm;   // primary key in `realmlist` table

    bool operator<(RealmHandle const& r) const
    {
        return Realm < r.Realm;
    }
};

/// Type of server, this is values from second column of Cfg_Configs.dbc
enum RealmType
{
    REALM_TYPE_NORMAL       = 0,
    REALM_TYPE_PVP          = 1,
    REALM_TYPE_NORMAL2      = 4,
    REALM_TYPE_RP           = 6,
    REALM_TYPE_RPPVP        = 8,

    MAX_CLIENT_REALM_TYPE   = 14,

    REALM_TYPE_FFA_PVP      = 16                            // custom, free for all pvp mode like arena PvP in all zones except rest activated places and sanctuaries
                                                            // replaced by REALM_PVP in realm list
};

// Storage object for a realm
struct TC_SHARED_API Realm
{
    RealmHandle Id;
    uint32 Build;
    // ACE_INET_Addr ExternalAddress;
    // std::string name;
    // uint8 icon;
    // RealmFlags flag;
    // uint8 timezone;
    // uint32 m_ID;
    // AccountTypes allowedSecurityLevel;
    // float populationLevel;
    // uint32 gamebuild;
    std::unique_ptr<ACE_INET_Addr> ExternalAddress;
    std::unique_ptr<ACE_INET_Addr> LocalAddress;
    std::unique_ptr<ACE_INET_Addr> LocalSubnetMask;
    uint16 Port;
    std::string Name;
    uint8 Type;
    RealmFlags Flags;
    uint8 Timezone;
    AccountTypes AllowedSecurityLevel;
    float PopulationLevel;
};

#endif