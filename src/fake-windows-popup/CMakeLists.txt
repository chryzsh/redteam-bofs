cmake_minimum_required(VERSION 3.18)

project(fake-windows-popup-bof-pe LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

get_filename_component(DEFAULT_BOF_PE_ROOT
    "${CMAKE_CURRENT_SOURCE_DIR}/../../external/BOF-PE" ABSOLUTE)
set(BOF_PE_ROOT "${DEFAULT_BOF_PE_ROOT}" CACHE PATH
    "Path to the NetSPI BOF-PE source checkout")

if(NOT EXISTS "${BOF_PE_ROOT}/beacon/beacon.h")
    message(FATAL_ERROR
        "BOF_PE_ROOT must point to a BOF-PE checkout containing beacon/beacon.h")
endif()

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    set(BOF_PE_LINK_SCRIPT "${BOF_PE_ROOT}/link.ld")
else()
    message(FATAL_ERROR "fake-windows-popup currently supports x64 only")
endif()

add_subdirectory("${BOF_PE_ROOT}/beacon" "${CMAKE_BINARY_DIR}/bof-pe-beacon")
target_include_directories(beacon PUBLIC "${BOF_PE_ROOT}/beacon")

add_executable(fake-windows-popup
    src/credentials.cpp
    src/dimmer.cpp
    src/main.cpp
    src/policy.cpp
    src/prompt.cpp
    src/target.cpp
)

target_include_directories(fake-windows-popup PRIVATE
    "${BOF_PE_ROOT}/beacon"
    "${CMAKE_CURRENT_SOURCE_DIR}/src"
)

target_link_libraries(fake-windows-popup PRIVATE
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

add_custom_command(TARGET fake-windows-popup POST_BUILD
    COMMAND "${CMAKE_COMMAND}" -E copy_if_different
        "$<TARGET_FILE:beacon>"
        "$<TARGET_FILE_DIR:fake-windows-popup>"
    COMMENT "Copying standalone beacon.dll beside fake-windows-popup")

if(CMAKE_CXX_COMPILER_ID MATCHES "MSVC|Clang")
    target_compile_options(fake-windows-popup PRIVATE /GS- /MT /W4)
    target_link_options(fake-windows-popup PRIVATE
        /MERGE:.gfids=.
        /MERGE:_RDATA=.
        /MERGE:.data=.
        /MERGE:.rdata=.
        /MERGE:.pdata=.
        /SECTION:.,RW
        /MERGE:.discard_data=.discard
    )
else()
    target_compile_options(fake-windows-popup PRIVATE
        -Wall -Wextra -Wpedantic -fno-exceptions -fno-rtti)
    target_link_options(fake-windows-popup PRIVATE
        -static
        -fno-unwind-tables
        -fno-asynchronous-unwind-tables
        -falign-functions=1
        -fno-exceptions
        -fno-rtti
        "-T${BOF_PE_LINK_SCRIPT}"
        -Wl,--strip-all
    )
endif()

install(TARGETS fake-windows-popup DESTINATION .)
