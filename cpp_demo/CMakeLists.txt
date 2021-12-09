cmake_minimum_required(VERSION 2.8)
project(MIXER)

add_definitions(-g -fpermissive -std=c++11 -Wliteral-suffix)
add_definitions( -DLSQUIC_DEBUG_NEXT_ADV_TICK=1 -DLSQUIC_CONN_STATS=1 -Wall -Wextra -Wno-unused-parameter -fno-omit-frame-pointer)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(LSQUICDIR "${CMAKE_CURRENT_SOURCE_DIR}/3rdpart/lsquic")
set(BORINGSSL "${CMAKE_CURRENT_SOURCE_DIR}/3rdpart/boringssl")
set(SPDLOG "${CMAKE_CURRENT_SOURCE_DIR}/3rdpart/spdlog")
set(PUBLIC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/public")

include_directories(${LSQUICDIR}/include)
include_directories(${BORINGSSL}/include)
include_directories(${PUBLIC_DIR})

include_directories(${SPDLOG}/include)
include_directories(${SPDLOG}/include/spdlog)

link_directories(${LSQUICDIR}/lib)
link_directories(${BORINGSSL}/lib)
link_directories(${SPDLOG}/lib)

aux_source_directory(./ SRC_MAIN)
aux_source_directory(${PUBLIC_DIR} PUBLIC_SRC)

link_libraries(${LSQUICDIR}/lib/liblsquic.so)
link_libraries(${BORINGSSL}/lib/libssl.so)
link_libraries(${BORINGSSL}/lib/libcrypto.so)

add_executable(quci_demo ${SRC_MAIN} ${PUBLIC_SRC})
target_link_libraries(quci_demo pthread dl z m ev spdlog)


