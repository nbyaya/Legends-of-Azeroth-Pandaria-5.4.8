# This file is part of the Pandaria 5.4.8 Project. See THANKS file for Copyright information
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

if( USE_COREPCH )
  include_directories(${CMAKE_CURRENT_BINARY_DIR})
endif()

file(GLOB_RECURSE sources_Management Management/*.cpp Management/*.h)
file(GLOB_RECURSE sources_Maps Maps/*.cpp Maps/*.h)
file(GLOB_RECURSE sources_Models Models/*.cpp Models/*.h)
file(GLOB sources_localdir *.cpp *.h)

if (USE_COREPCH)
  set(collision_STAT_PCH_HDR PrecompiledHeaders/collisionPCH.h)
endif ()

set(collision_STAT_SRCS
  ${collision_STAT_SRCS}
  ${sources_Management}
  ${sources_Maps}
  ${sources_Models}
  ${sources_localdir}
)

include_directories(
  PUBLIC
    ${CMAKE_BINARY_DIR}
    ${ACE_INCLUDE_DIR}    
  PRIVATE
    ${CMAKE_SOURCE_DIR}/src/common
    ${CMAKE_SOURCE_DIR}/src/common/Asio
    ${CMAKE_SOURCE_DIR}/src/common/Configuration
    ${CMAKE_SOURCE_DIR}/src/common/Debugging
    ${CMAKE_SOURCE_DIR}/src/common/Logging
    ${CMAKE_SOURCE_DIR}/src/common/Threading
    ${CMAKE_SOURCE_DIR}/src/common/Utilities
    ${CMAKE_SOURCE_DIR}/dep/g3dlite/include
    ${CMAKE_SOURCE_DIR}/dep/recastnavigation/Detour/Include
    ${CMAKE_SOURCE_DIR}/src/server/database/Database    
    ${CMAKE_SOURCE_DIR}/src/server/shared
    ${CMAKE_SOURCE_DIR}/src/server/shared/Debugging
    ${CMAKE_SOURCE_DIR}/src/server/shared/Debugging
    ${CMAKE_SOURCE_DIR}/src/server/shared/Dynamic
    ${CMAKE_SOURCE_DIR}/src/server/shared/Dynamic/LinkedReference
    ${CMAKE_SOURCE_DIR}/src/server/shared/Threading
    ${CMAKE_SOURCE_DIR}/src/server/shared/Packets
    ${CMAKE_SOURCE_DIR}/src/server/shared/Utilities
    ${CMAKE_SOURCE_DIR}/src/server/shared/DataStores
    ${CMAKE_SOURCE_DIR}/src/server/shared/Realms
    ${CMAKE_SOURCE_DIR}/src/server/game/Addons
    ${CMAKE_SOURCE_DIR}/src/server/game/Conditions
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/AreaTrigger
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/Item
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/GameObject
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/Creature
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/Object
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/Object/Updates
    ${CMAKE_SOURCE_DIR}/src/server/game/Entities/Unit
    ${CMAKE_SOURCE_DIR}/src/server/game/Combat
    ${CMAKE_SOURCE_DIR}/src/server/game/Loot
    ${CMAKE_SOURCE_DIR}/src/server/game/Miscellaneous
    ${CMAKE_SOURCE_DIR}/src/server/game/Grids
    ${CMAKE_SOURCE_DIR}/src/server/game/Grids/Cells
    ${CMAKE_SOURCE_DIR}/src/server/game/Grids/Notifiers
    ${CMAKE_SOURCE_DIR}/src/server/game/Maps
    ${CMAKE_SOURCE_DIR}/src/server/game/DataStores
    ${CMAKE_SOURCE_DIR}/src/server/game/Movement/Waypoints
    ${CMAKE_SOURCE_DIR}/src/server/game/Movement/Spline
    ${CMAKE_SOURCE_DIR}/src/server/game/Movement
    ${CMAKE_SOURCE_DIR}/src/server/game/Server
    ${CMAKE_SOURCE_DIR}/src/server/game/Server/Protocol
    ${CMAKE_SOURCE_DIR}/src/server/game/World
    ${CMAKE_SOURCE_DIR}/src/server/game/Spells
    ${CMAKE_SOURCE_DIR}/src/server/game/Spells/Auras
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/Management
    ${CMAKE_CURRENT_SOURCE_DIR}/Maps
    ${CMAKE_CURRENT_SOURCE_DIR}/Models
    ${MYSQL_INCLUDE_DIR}
    ${Boost_INCLUDE_DIRS}
    ${CMAKE_SOURCE_DIR}/dep/fmt/include
)

add_library(collision STATIC
  ${collision_STAT_SRCS}
)

target_link_libraries(collision
  PUBLIC
    common
    shared
)

# Generate precompiled header
if (USE_COREPCH)
  target_precompile_headers(collision PRIVATE ${collision_STAT_PCH_HDR}) 
endif ()
