cmake_minimum_required(VERSION 3.0)
project(saltpack)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++11 -fPIC -Wall")
if(MSVC)
    #vc 2012 fix for vararg templates
    set(MSVC_COMPILER_DEFS "-D_VARIADIC_MAX=10")
endif() 

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake_modules" ${CMAKE_MODULE_PATH})

include_directories("include")

# Sources
set(SOURCE_FILES src/ArmoredInputStream.cpp src/ArmoredOutputStream.cpp src/Base.cpp src/MessageReader.cpp src/MessageWriter.cpp src/Utils.cpp)
set(HEADER_FILES include/saltpack.h include/saltpack/alphabets.h include/saltpack/ArmoredInputStream.h include/saltpack/ArmoredOutputStream.h include/saltpack/Base.h include/saltpack/HeaderPacket.h include/saltpack/HeaderPacketRecipient.h include/saltpack/MessageReader.h include/saltpack/MessageWriter.h include/saltpack/modes.h include/saltpack/PayloadPacket.h include/saltpack/SaltpackException.h include/saltpack/SignatureHeaderPacket.h include/saltpack/SignaturePayloadPacket.h include/saltpack/types.h include/saltpack/Utils.h)

# Library
add_library(saltpack STATIC ${SOURCE_FILES} ${HEADER_FILES})

# Install paths
install(TARGETS saltpack DESTINATION lib)
install(FILES include/saltpack.h DESTINATION include)
install(DIRECTORY include/saltpack DESTINATION include)

# Tests
add_subdirectory(ext/gtest)
add_definitions(${MSVC_COMPILER_DEFS})
enable_testing()
include_directories(${GTEST_INCLUDE_DIRS})
add_executable(saltpack-test test/armor.cpp test/encryption.cpp test/signature.cpp test/utils.cpp test/main.cpp)
add_dependencies(saltpack-test googletest)

if(NOT WIN32 OR MINGW)
    target_link_libraries(saltpack-test ${GTEST_LIBS_DIR}/libgtest.a ${GTEST_LIBS_DIR}/libgtest_main.a)
else()
    target_link_libraries(saltpack-test
        debug ${GTEST_LIBS_DIR}/DebugLibs/${CMAKE_FIND_LIBRARY_PREFIXES}gtest${CMAKE_FIND_LIBRARY_SUFFIXES}
        optimized ${GTEST_LIBS_DIR}/ReleaseLibs/${CMAKE_FIND_LIBRARY_PREFIXES}gtest${CMAKE_FIND_LIBRARY_SUFFIXES}
        )
    target_link_libraries(saltpack-test
        debug ${GTEST_LIBS_DIR}/DebugLibs/${CMAKE_FIND_LIBRARY_PREFIXES}gtest_main${CMAKE_FIND_LIBRARY_SUFFIXES}
        optimized ${GTEST_LIBS_DIR}/ReleaseLibs/${CMAKE_FIND_LIBRARY_PREFIXES}gtest_main${CMAKE_FIND_LIBRARY_SUFFIXES}
        )
endif()

target_link_libraries(saltpack-test saltpack)
add_test(saltpack-test saltpack-test)

# LibSodium
find_package(Libsodium REQUIRED)
include_directories(${LIBSODIUM_INCLUDE_DIRS})
target_link_libraries(saltpack ${LIBSODIUM_LIBRARIES})
target_link_libraries(saltpack-test ${LIBSODIUM_LIBRARIES})

# MessagePack
find_package(MsgPack REQUIRED)
include_directories(${MSGPACK_INCLUDE_DIRS})

# GMP
find_package(GMP REQUIRED)
include_directories(${GMP_INCLUDE_DIRS})
target_link_libraries(saltpack ${GMP_LIBRARIES})
target_link_libraries(saltpack-test ${GMP_LIBRARIES})

# Threads
find_package(Threads REQUIRED)
target_link_libraries(saltpack-test ${CMAKE_THREAD_LIBS_INIT})
