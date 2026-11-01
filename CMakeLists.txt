# XLivelessAddon — a maintained fork of XLivelessAddon for GTA IV / EFLC, built as
# a standalone companion to OpenPreCEPatch.
#
#   1. cmake --preset win-x86            (configures build/win-x86)
#   2. cmake --build --preset release
#   3. ctest --preset release
#   4. cmake --build build/win-x86 --config Release --target package
#
# The code uses C++23 modules: one .ixx per feature plus common.hxx, following
# GTAIV.EFLC.FusionFix. Only Win32 (x86) is supported; the game is 32-bit.

cmake_minimum_required(VERSION 3.28)

project(XLivelessAddon
    VERSION 1.1.0
    DESCRIPTION "XLivelessAddon for GTA IV / EFLC (companion to OpenPreCEPatch)"
    LANGUAGES CXX RC)

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# The ASI must load on a machine that has no Visual C++ redistributable: the game
# folder is the whole installation. FusionFix (staticruntime "On") and the other
# OpenZDecomp modules link the static CRT the same way.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

if(NOT MSVC)
    message(FATAL_ERROR "XLivelessAddon targets Windows/MSVC only (the ASI is a Win32 DLL).")
endif()

if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
    message(FATAL_ERROR
        "Configure for Win32: the game is 32-bit and the hook bodies assume x86.\n"
        "  Use the win-x86 preset, or pass -A Win32 to the Visual Studio generator.")
endif()

# ---------------------------------------------------------------------------
# Dependencies (pinned git submodules)
# ---------------------------------------------------------------------------
foreach(required
        external/injector/include/injector/injector.hpp
        external/hooking/Hooking.Patterns.h
        external/IniReader/IniReader.h)
    if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${required}")
        message(FATAL_ERROR
            "Missing ${required}.\n"
            "Initialise the submodules (recursive, because injector carries "
            "safetyhook/bddisasm/kananlib/minhook):\n"
            "  git submodule update --init --recursive")
    endif()
endforeach()

# ---------------------------------------------------------------------------
# Version + PE resource
# ---------------------------------------------------------------------------
set(XLA_GIT_SHA "")
find_package(Git QUIET)
if(GIT_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
    execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}"
        OUTPUT_VARIABLE XLA_GIT_SHA
        OUTPUT_STRIP_TRAILING_WHITESPACE
        ERROR_QUIET)
endif()

if(XLA_GIT_SHA STREQUAL "")
    set(XLA_VERSION_STRING "${PROJECT_VERSION}")
else()
    set(XLA_VERSION_STRING "${PROJECT_VERSION}-${XLA_GIT_SHA}")
endif()

configure_file(cmake/version.hpp.in
               "${CMAKE_CURRENT_BINARY_DIR}/generated/xla/version.hpp" @ONLY)
configure_file(res/version.rc.in
               "${CMAKE_CURRENT_BINARY_DIR}/generated/version.rc" @ONLY)

# ---------------------------------------------------------------------------
# Shared module library
# ---------------------------------------------------------------------------
option(XLA_BUILD_TESTS "Build the native test suite" ON)

# The module interface units: one per feature, named xla.<stem>. They are a
# CXX_MODULES file set so CMake scans them (and propagates their BMIs to the
# ASI and test targets) instead of compiling them as ordinary sources.
set(XLA_MODULES
    source/common.ixx
    source/build.ixx
    source/config.ixx
    source/patch.ixx
    source/savegames.ixx
    source/registry.ixx
    source/userdata.ixx
    source/dfa.ixx
    source/rom_window.ixx
    source/skip_launcher.ixx
    source/windowed.ixx
    source/patches.ixx
    source/addon.ixx)

# The plain translation units: the vendored Hooking.Patterns and our reader boundary.
# The vendored IniReader is header-only and all-inline upstream, so mINI must not be
# instantiated in module purview: source/ini_file.cpp owns it behind declarations.
# dllmain.cpp is the ASI's own entry TU.
set(XLA_PLAIN_SOURCES
    external/hooking/Hooking.Patterns.cpp
    source/ini_file.cpp)

add_library(xla_core STATIC ${XLA_PLAIN_SOURCES})
set_target_properties(xla_core PROPERTIES CXX_SCAN_FOR_MODULES ON)
target_sources(xla_core PUBLIC FILE_SET CXX_MODULES FILES ${XLA_MODULES})
target_include_directories(xla_core PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/source"
    "${CMAKE_CURRENT_BINARY_DIR}/generated")
target_include_directories(xla_core SYSTEM PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}/external/injector/include"
    "${CMAKE_CURRENT_SOURCE_DIR}/external/hooking"
    "${CMAKE_CURRENT_SOURCE_DIR}/external/IniReader")
target_compile_definitions(xla_core PUBLIC _CRT_SECURE_NO_WARNINGS)
target_compile_options(xla_core PUBLIC
    /W4 /permissive- /Zc:__cplusplus /utf-8 /EHsc $<$<CONFIG:Release>:/O2>)
target_link_libraries(xla_core PUBLIC user32)

set(XLA_OUTPUT_DIR "${CMAKE_BINARY_DIR}/bin")
set(XLA_INI "${CMAKE_CURRENT_SOURCE_DIR}/data/XLivelessAddon.ini")

# ---------------------------------------------------------------------------
# The ASI
# ---------------------------------------------------------------------------
add_library(XLivelessAddon SHARED
    source/dllmain.cpp
    "${CMAKE_CURRENT_BINARY_DIR}/generated/version.rc")
set_target_properties(XLivelessAddon PROPERTIES
    CXX_SCAN_FOR_MODULES ON
    PREFIX ""
    OUTPUT_NAME "XLivelessAddon"
    SUFFIX ".asi"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${XLA_OUTPUT_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${XLA_OUTPUT_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_RELWITHDEBINFO "${XLA_OUTPUT_DIR}"
    RUNTIME_OUTPUT_DIRECTORY_MINSIZEREL "${XLA_OUTPUT_DIR}")
target_link_libraries(XLivelessAddon PRIVATE xla_core user32)
target_link_options(XLivelessAddon PRIVATE
    /MACHINE:X86
    /SUBSYSTEM:WINDOWS
    /BASE:0x10000000
    /INCREMENTAL:NO
    "/MAP:${XLA_OUTPUT_DIR}/XLivelessAddon.map")

# The static library's module objects would be dropped by the linker otherwise.
target_link_options(XLivelessAddon PRIVATE
    "/WHOLEARCHIVE:$<TARGET_FILE:xla_core>")

# INI next to the ASI, plus an optional copy into a live game folder:
#   cmake --preset win-x86 -DXLA_GAME_DIR="D:/Games/GTA IV"
set(XLA_GAME_DIR "" CACHE PATH "Optional game directory that receives the ASI and INI")
add_custom_command(TARGET XLivelessAddon POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different "${XLA_INI}"
            "${XLA_OUTPUT_DIR}/XLivelessAddon.ini"
    COMMENT "Copying XLivelessAddon.ini"
    VERBATIM)

if(XLA_GAME_DIR)
    add_custom_command(TARGET XLivelessAddon POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
                "$<TARGET_FILE:XLivelessAddon>" "${XLA_GAME_DIR}/XLivelessAddon.asi"
        COMMAND ${CMAKE_COMMAND} -E copy_if_different "${XLA_INI}"
                "${XLA_GAME_DIR}/XLivelessAddon.ini"
        COMMENT "Deploying XLivelessAddon to ${XLA_GAME_DIR}"
        VERBATIM)
endif()

# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------
if(XLA_BUILD_TESTS)
    enable_testing()

    add_executable(xla_tests tests/test_main.cpp)
    set_target_properties(xla_tests PROPERTIES
        CXX_SCAN_FOR_MODULES ON
        RUNTIME_OUTPUT_DIRECTORY_RELEASE "${XLA_OUTPUT_DIR}"
        RUNTIME_OUTPUT_DIRECTORY_DEBUG "${XLA_OUTPUT_DIR}")
    target_link_libraries(xla_tests PRIVATE xla_core)
    target_compile_definitions(xla_tests PRIVATE _CRT_SECURE_NO_WARNINGS)
    target_link_options(xla_tests PRIVATE /MACHINE:X86 /SUBSYSTEM:CONSOLE)

    add_test(NAME xla_tests
        COMMAND xla_tests "${CMAKE_CURRENT_SOURCE_DIR}/data"
                "${CMAKE_CURRENT_BINARY_DIR}/test-work")

    # The recovered scan list and its order are data: the parity check parses
    # every module interface unit and compares it with the committed golden
    # (tests/signature_golden.tsv) captured from the pre-modular source.
    find_package(Python3 COMPONENTS Interpreter QUIET)
    if(NOT Python3_Interpreter_FOUND)
        find_program(XLA_PYTHON_EXECUTABLE NAMES python3 python)
        if(XLA_PYTHON_EXECUTABLE)
            set(Python3_EXECUTABLE "${XLA_PYTHON_EXECUTABLE}")
            set(Python3_Interpreter_FOUND TRUE)
        endif()
    endif()
    if(Python3_Interpreter_FOUND)
        add_test(NAME xla_signature_parity
            COMMAND "${Python3_EXECUTABLE}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/tools/signature_parity.py"
                    --source "${CMAKE_CURRENT_SOURCE_DIR}/source"
                    --golden "${CMAKE_CURRENT_SOURCE_DIR}/tests/signature_golden.tsv")

        # The recovered launcher tables and the [v1005] NOP plan are data: this
        # fails if any row's offsets/lengths/bytes/fill/jump/opcode/hook, the
        # collectors or the restored head+tail NOPs change.
        add_test(NAME xla_table_parity
            COMMAND "${Python3_EXECUTABLE}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/tools/table_parity.py"
                    --source "${CMAKE_CURRENT_SOURCE_DIR}/source"
                    --tables "${CMAKE_CURRENT_SOURCE_DIR}/tests/skip_launcher_tables.tsv"
                    --v1005 "${CMAKE_CURRENT_SOURCE_DIR}/tests/patches_v1005.tsv")

        # The .ixx layout (one unit per feature, one plain TU in source/, CXX_MODULES
        # file set) is a contract; this fails if a file drifts out of it.
        add_test(NAME xla_module_layout
            COMMAND "${Python3_EXECUTABLE}"
                    "${CMAKE_CURRENT_SOURCE_DIR}/tools/module_layout.py"
                    --source "${CMAKE_CURRENT_SOURCE_DIR}/source")
    else()
        message(WARNING
            "Python 3 not found: the signature, table and layout checks are not registered.")
    endif()

    # The shipped ASI must be a Win32 DLL at the add-on's preferred base with the
    # expected subsystem and imports.
    find_program(POWERSHELL_EXECUTABLE NAMES pwsh powershell)
    if(POWERSHELL_EXECUTABLE)
        add_test(NAME xla_asi_headers
            COMMAND ${POWERSHELL_EXECUTABLE} -NoProfile -ExecutionPolicy Bypass
                    -File "${CMAKE_CURRENT_SOURCE_DIR}/tools/verify_asi.ps1"
                    -Path "$<TARGET_FILE:XLivelessAddon>")
    else()
        message(WARNING "PowerShell not found: the xla_asi_headers PE test is not registered.")
    endif()
endif()

# ---------------------------------------------------------------------------
# Install / package (zip with the ASI, INI and license files at its root)
# ---------------------------------------------------------------------------
install(TARGETS XLivelessAddon RUNTIME DESTINATION .)
install(FILES
    "${XLA_INI}"
    "${CMAKE_CURRENT_SOURCE_DIR}/README.md"
    "${CMAKE_CURRENT_SOURCE_DIR}/LICENSE"
    "${CMAKE_CURRENT_SOURCE_DIR}/NOTICE"
    "${CMAKE_CURRENT_SOURCE_DIR}/CREDITS.md"
    DESTINATION .)

set(CPACK_PACKAGE_NAME "XLivelessAddon")
set(CPACK_PACKAGE_VENDOR "OpenZDecomp")
set(CPACK_PACKAGE_VERSION "${PROJECT_VERSION}")
set(CPACK_PACKAGE_FILE_NAME "XLivelessAddon-${PROJECT_VERSION}")
set(CPACK_GENERATOR ZIP)
set(CPACK_INCLUDE_TOPLEVEL_DIRECTORY OFF)
set(CPACK_PACKAGE_CHECKSUM SHA256)
include(CPack)
