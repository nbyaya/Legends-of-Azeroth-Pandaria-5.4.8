# This file is part of the Pandaria 5.4.8 Project. See THANKS file for Copyright information
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

# Enable precompiled headers when using the GCC compiler.

if (USE_SCRIPTPCH)
  set(scripts_STAT_PCH_HDR PrecompiledHeaders/ScriptPCH.h)
endif ()

file(GLOB_RECURSE sources_PrecompiledHeaders PrecompiledHeaders/*.cpp PrecompiledHeaders/*.h)
file(GLOB_RECURSE sources_Battlegrounds Battlegrounds/*.cpp  Battlegrounds/*.h)
file(GLOB_RECURSE sources_EasternKingdoms EasternKingdoms/*.cpp EasternKingdoms/*.h)
file(GLOB_RECURSE sources_Kalimdor Kalimdor/*.cpp Kalimdor/*.h)
file(GLOB_RECURSE sources_Outland Outland/*.cpp Outland/*.h)
file(GLOB_RECURSE sources_Northrend Northrend/*.cpp Northrend/*.h)
file(GLOB_RECURSE sources_Maelstrom Maelstrom/*.cpp Maelstrom/*.h)
file(GLOB_RECURSE sources_Custom Custom/*.cpp Custom/*.h)
file(GLOB_RECURSE sources_Commands Commands/*.cpp Commands/*.h)
#file(GLOB_RECURSE sources_Examples Examples/*.cpp Examples/*.h)
file(GLOB_RECURSE sources_Events Events/*.cpp Events/*.h)
file(GLOB_RECURSE sources_Pandaria Pandaria/*.cpp Pandaria/*.h)
file(GLOB_RECURSE sources_Pet Pet/*.cpp Pet/*.h)
file(GLOB_RECURSE sources_OutdoorPvP OutdoorPvP/*.cpp OutdoorPvP/*.h)
file(GLOB_RECURSE sources_Spells Spells/*.cpp Spells/*.h)
file(GLOB_RECURSE sources_ScriptLoader ScriptLoader/*.cpp ScriptLoader/*.h)
file(GLOB_RECURSE sources_World World/*.cpp World/*.h)

source_group(CMake FILES CMakeLists.txt)
source_group(Battlegrounds FILES ${sources_Battlegrounds})
source_group(PrecompiledHeaders FILES ${sources_PrecompiledHeaders})
source_group(EasternKingdoms FILES ${sources_EasternKingdoms})
source_group(Kalimdor FILES ${sources_Kalimdor})
source_group(Outland FILES ${sources_Outland})
source_group(Northrend FILES ${sources_Northrend})
source_group(Maelstrom FILES ${sources_Maelstrom})
source_group(OutdoorPvP FILES ${sources_OutdoorPvP})
source_group(Commands FILES ${sources_Commands})
#source_group(Examples FILES ${sources_Examples})
source_group(Events FILES ${sources_Events})
source_group(Pandaria FILES ${sources_Pandaria})
source_group(Pet FILES ${sources_Pet})
source_group(Spells FILES ${sources_Spells})
source_group(ScriptLoader FILES ${sources_ScriptLoader})
source_group(World FILES ${sources_World})

message(STATUS "SCRIPT PREPARATIONS")
include(Spells/CMakeLists.txt)

include(Commands/CMakeLists.txt)
include(Battlegrounds/CMakeLists.txt)

#include(Examples/CMakeLists.txt)
set(scripts_STAT_SRCS
  ${scripts_STAT_SRCS}
  ${sources_ScriptLoader}
)

if(SCRIPTS)
  include(Custom/CMakeLists.txt)
  include(World/CMakeLists.txt)
  include(OutdoorPvP/CMakeLists.txt)
  include(EasternKingdoms/CMakeLists.txt)
  include(Kalimdor/CMakeLists.txt)
  include(Outland/CMakeLists.txt)
  include(Northrend/CMakeLists.txt)
  include(Maelstrom/CMakeLists.txt)
  include(Events/CMakeLists.txt)
  include(Pandaria/CMakeLists.txt)
  include(Pet/CMakeLists.txt)
endif()

message(STATUS "SCRIPT PREPARATION COMPLETE")
message("")

include_directories(
  PUBLIC
    ${CMAKE_BINARY_DIR}
  PRIVATE    
    ${CMAKE_SOURCE_DIR}/dep/recastnavigation/Detour/Include
    ${CMAKE_SOURCE_DIR}/dep/recastnavigation/Recast/Include
    ${CMAKE_SOURCE_DIR}/dep/g3dlite/include
    ${CMAKE_SOURCE_DIR}/src/common
    ${CMAKE_SOURCE_DIR}/src/common/Asio
    ${CMAKE_SOURCE_DIR}/src/common/Configuration
    ${CMAKE_SOURCE_DIR}/src/common/Cryptography
    ${CMAKE_SOURCE_DIR}/src/common/Debugging 
    ${CMAKE_SOURCE_DIR}/src/common/IPLocation 
    ${CMAKE_SOURCE_DIR}/src/common/Logging  
    ${CMAKE_SOURCE_DIR}/src/common/Threading
    ${CMAKE_SOURCE_DIR}/src/common/Utilities
    ${CMAKE_SOURCE_DIR}/src/server/database/Database
    ${CMAKE_SOURCE_DIR}/src/server/database/Logging    
    ${CMAKE_SOURCE_DIR}/src/server/shared
    ${CMAKE_SOURCE_DIR}/src/server/shared/Configuration
    ${CMAKE_SOURCE_DIR}/src/server/shared/DataStores
    ${CMAKE_SOURCE_DIR}/src/server/shared/Debugging
    ${CMAKE_SOURCE_DIR}/src/server/shared/Dynamic/LinkedReference
    ${CMAKE_SOURCE_DIR}/src/server/shared/Dynamic
    ${CMAKE_SOURCE_DIR}/src/server/shared/Realms
    ${CMAKE_SOURCE_DIR}/src/server/shared/Packets
    ${CMAKE_SOURCE_DIR}/src/server/shared/Utilities
    ${CMAKE_SOURCE_DIR}/src/server/collision
    ${CMAKE_SOURCE_DIR}/src/server/collision/Management
    ${CMAKE_SOURCE_DIR}/src/server/collision/Models
    ${CMAKE_SOURCE_DIR}/src/server/game/Accounts
    ${CMAKE_SOURCE_DIR}/src/server/game/Achievements
    ${CMAKE_SOURCE_DIR}/src/server/game/Addons
    ${CMAKE_SOURCE_DIR}/src/server/game/AI
    ${CMAKE_SOURCE_DIR}/src/server/game/AI/CoreAI
    ${CMAKE_SOURCE_DIR}/src/server/game/AI/PlayerAI
    ${CMAKE_SOURCE_DIR}/src/server/game/AI/ScriptedAI
    ${CMAKE_SOURCE_DIR}/src/server/game/AI/SmartScripts
    ${CMAKE_SOURCE_DIR}/src/server/game/Anticheat
    ${CMAKE_SOURCE_DIR}/src/server/game/AuctionHouseBot
    ${CMAKE_SOURCE_DIR}/src/server/game/AuctionHouse
    ${CMAKE_SOURCE_DIR}/src/server/game/Battlefield
    ${CMAKE_SOURCE_DIR}/src/server/game/Battlefield/Zones
    ${CMAKE_SOURCE_DIR}/src/server/game/Battlegrounds
    ${CMAKE_SOURCE_DIR}/src/server/game/Battlegrounds/Zones
    ${CMAKE_SOURCE_DIR}/src/server/game/BattlePay
    ${CMAKE_SOURCE_DIR}/src/server/game/BattlePet
    ${CMAKE_SOURCE_DIR}/src/server/game/BlackMarket
    ${CMAKE_SOURCE_DIR}/src/server/game/Calendar
    ${CMAKE_SOURCE_DIR}/src/server/game/Chat
    ${CMAKE_SOURCE_DIR}/src/server/game/Chat/Channels
    ${CMAKE_SOURCE_DIR}/src/server/game/Conditions
    ${CMAKE_SOURCE_DIR}/src/server/game/CustomTransmogrification
    ${CMAKE_SOURCE_DIR}/src/server/game/Combat
    ${CMAKE_SOURCE_DIR}/src/server/game/DataStores
    ${CMAKE_SOURCE_DIR}/src/server/game/DungeonFinding
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/AreaTrigger
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/Corpse
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/Creature
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/DynamicObject
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/Item
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/Item/Container
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/GameObject
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/Object
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/Object/Updates
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/Pet
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/Player
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/Totem
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/Transport
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/Unit
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/Vehicle
    ${CMAKE_SOURCE_DIR}/src/server/game/Events
    ${CMAKE_SOURCE_DIR}/src/server/game/Globals
    ${CMAKE_SOURCE_DIR}/src/server/game/Grids
    ${CMAKE_SOURCE_DIR}/src/server/game/Grids/Cells
    ${CMAKE_SOURCE_DIR}/src/server/game/Grids/Notifiers
    ${CMAKE_SOURCE_DIR}/src/server/game/Groups
    ${CMAKE_SOURCE_DIR}/src/server/game/Guilds
    ${CMAKE_SOURCE_DIR}/src/server/game/Handlers
    ${CMAKE_SOURCE_DIR}/src/server/game/Instances
    ${CMAKE_SOURCE_DIR}/src/server/game/LookingForGroup
    ${CMAKE_SOURCE_DIR}/src/server/game/Loot
    ${CMAKE_SOURCE_DIR}/src/server/game/Mails
    ${CMAKE_SOURCE_DIR}/src/server/game/Miscellaneous
    ${CMAKE_SOURCE_DIR}/src/server/game/Maps
    ${CMAKE_SOURCE_DIR}/src/server/game/Movement
    ${CMAKE_SOURCE_DIR}/src/server/game/Movement/MovementGenerators
    ${CMAKE_SOURCE_DIR}/src/server/game/Movement/Spline
    ${CMAKE_SOURCE_DIR}/src/server/game/Movement/Waypoints
    ${CMAKE_SOURCE_DIR}/src/server/game/Opcodes
    ${CMAKE_SOURCE_DIR}/src/server/game/OutdoorPvP
    ${CMAKE_SOURCE_DIR}/src/server/game/Pools
    ${CMAKE_SOURCE_DIR}/src/server/game/PrecompiledHeaders
    ${CMAKE_SOURCE_DIR}/src/server/game/Quests
    ${CMAKE_SOURCE_DIR}/src/server/game/Reputation
    ${CMAKE_SOURCE_DIR}/src/server/game/Scenarios
    ${CMAKE_SOURCE_DIR}/src/server/game/Scripting
    ${CMAKE_SOURCE_DIR}/src/server/game/Server
    ${CMAKE_SOURCE_DIR}/src/server/game/Services
    ${CMAKE_SOURCE_DIR}/src/server/game/Server/Protocol
    ${CMAKE_SOURCE_DIR}/src/server/game/Skills
    ${CMAKE_SOURCE_DIR}/src/server/game/Spells
    ${CMAKE_SOURCE_DIR}/src/server/game/Spells/Auras
    ${CMAKE_SOURCE_DIR}/src/server/game/Texts
    ${CMAKE_SOURCE_DIR}/src/server/game/Tickets
    ${CMAKE_SOURCE_DIR}/src/server/game/Tools
    ${CMAKE_SOURCE_DIR}/src/server/game/Vignette
    ${CMAKE_SOURCE_DIR}/src/server/game/Warden
    ${CMAKE_SOURCE_DIR}/src/server/game/Warden/Modules
    ${CMAKE_SOURCE_DIR}/src/server/game/Weather
    ${CMAKE_SOURCE_DIR}/src/server/game/World
    ${CMAKE_CURRENT_SOURCE_DIR}/PrecompiledHeaders
    ${ACE_INCLUDE_DIR}
    ${MYSQL_INCLUDE_DIR}
    ${OPENSSL_INCLUDE_DIR} 
    ${CMAKE_SOURCE_DIR}/dep/fmt/include   
)

if (ELUNA)
  set(scripts_STAT_SRCS
    ${scripts_STAT_SRCS}
  )
  include_directories(
    PRIVATE
      ${CMAKE_SOURCE_DIR}/dep/lualib
      ${CMAKE_SOURCE_DIR}/src/server/game/LuaEngine 
  )  
endif()

if (Boost_FOUND)
  include_directories(
    PUBLIC 
      ${Boost_INCLUDE_DIRS}
  )
endif()
if( USE_SCRIPTPCH AND MSVC )
  set(scripts_STAT_SRCS
    ${scripts_STAT_SRCS}
  )
endif()

add_library(scripts STATIC 
  ${scripts_STAT_SRCS} 
)

target_link_libraries(scripts
  PUBLIC
    game)

if (ELUNA)
  add_dependencies(scripts lua)
  target_link_libraries(scripts
    PRIVATE
      lua
  )
endif()



add_dependencies(scripts revision.h)

# Generate precompiled header
if (USE_SCRIPTPCH)
  target_precompile_headers(scripts PRIVATE ${scripts_STAT_PCH_HDR}) 
endif()
