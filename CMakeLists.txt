cmake_minimum_required(VERSION 3.5)
project(saltpack)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -fPIC -Wall")
if(MSVC)
    #vc 2012 fix for vararg templates
    set(MSVC_COMPILER_DEFS "-D_VARIADIC_MAX=10")
endif()

set(CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake_modules" ${CMAKE_MODULE_PATH})

include(FetchContent)
FetchContent_Declare(
        googletest
        URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
        DOWNLOAD_EXTRACT_TIMESTAMP true
)
# For Windows: Prevent overriding the parent project's compiler/linker settings
set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
FetchContent_MakeAvailable(googletest)

include_directories("include")

# Sources
set(SOURCE_FILES src/ArmoredInputStream.cpp src/ArmoredOutputStream.cpp src/Base.cpp src/MessageReader.cpp src/MessageWriter.cpp src/Utils.cpp)
set(HEADER_FILES include/saltpack.h include/saltpack/alphabets.h include/saltpack/ArmoredInputStream.h include/saltpack/ArmoredOutputStream.h include/saltpack/Base.h include/saltpack/HeaderPacket.h include/saltpack/HeaderPacketRecipient.h include/saltpack/MessageReader.h include/saltpack/MessageWriter.h include/saltpack/modes.h include/saltpack/PayloadPacket.h include/saltpack/PayloadPacketV2.h include/saltpack/SaltpackException.h include/saltpack/SignatureHeaderPacket.h include/saltpack/SignaturePayloadPacket.h include/saltpack/SignaturePayloadPacketV2.h include/saltpack/SigncryptionPayloadPacket.h include/saltpack/types.h include/saltpack/Utils.h)

# Library
add_library(saltpack STATIC ${SOURCE_FILES} ${HEADER_FILES})

# Install paths
install(TARGETS saltpack DESTINATION lib)
install(FILES include/saltpack.h DESTINATION include)
install(DIRECTORY include/saltpack DESTINATION include)

# Tests
enable_testing()
add_executable(saltpack-test test/armor.cpp test/encryption.cpp test/signature.cpp test/signcryption.cpp test/utils.cpp test/main.cpp)
target_link_libraries(
        saltpack-test
        GTest::gtest_main
        saltpack
)
include(GoogleTest)
gtest_discover_tests(saltpack-test)

# Code coverage
if (ENABLE_COVERAGE)
    include(CodeCoverage)
    setup_target_for_coverage_gcovr_html(
            NAME saltpack-coverage-html
            EXECUTABLE saltpack-test
            EXCLUDE "ext/*" "build/_deps/*" "test/*"
    )
    setup_target_for_coverage_gcovr_xml(
            NAME saltpack-coverage-xml
            EXECUTABLE saltpack-test
            EXCLUDE "ext/*" "build/_deps/*" "test/*"
    )
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -O0 -fprofile-arcs -ftest-coverage")
endif()

# LibSodium
find_package(Libsodium REQUIRED)
include_directories(${LIBSODIUM_INCLUDE_DIRS})
target_link_libraries(saltpack ${LIBSODIUM_LIBRARIES})
target_link_libraries(saltpack-test ${LIBSODIUM_LIBRARIES})

# MessagePack
find_package(Msgpack REQUIRED)
include_directories(${MSGPACK_INCLUDE_DIRS})
