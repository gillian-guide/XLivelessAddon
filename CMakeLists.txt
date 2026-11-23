cmake_minimum_required(VERSION 3.28)

project(XLivelessAddonFusion
    VERSION 1.0.0
    DESCRIPTION "XLivelessAddon reimplemented in GTAIV.EFLC.FusionFix style"
    LANGUAGES C CXX RC)

# Release, Debug and Trace. Trace compiles exactly like Release and enables the
# per-scan diagnostic lines; the shipped binary's log is unchanged either way.
if(CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_CONFIGURATION_TYPES "Debug;Release;Trace" CACHE STRING "" FORCE)
endif()
set(CMAKE_CXX_FLAGS_TRACE "${CMAKE_CXX_FLAGS_RELEASE}" CACHE STRING "" FORCE)
set(CMAKE_EXE_LINKER_FLAGS_TRACE "${CMAKE_EXE_LINKER_FLAGS_RELEASE}" CACHE STRING "" FORCE)
set(CMAKE_SHARED_LINKER_FLAGS_TRACE "${CMAKE_SHARED_LINKER_FLAGS_RELEASE}" CACHE STRING "" FORCE)

# The ASI is a Win32 PE32 DLL with a static CRT and a fixed image base, the same
# contract as FusionFix and every other OpenZDecomp ASI.
if(NOT MSVC)
  message(FATAL_ERROR "The ASI is built with MSVC; configure with a Visual Studio generator.")
endif()
if(NOT CMAKE_SIZEOF_VOID_P EQUAL 4)
  message(FATAL_ERROR "The ASI is 32-bit (PE32); configure with -A Win32.")
endif()

set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

set(XLA_NAME "XLivelessAddon")
set(XLA_VERSION_MAJOR ${PROJECT_VERSION_MAJOR})
set(XLA_VERSION_MINOR ${PROJECT_VERSION_MINOR})
set(XLA_VERSION_PATCH ${PROJECT_VERSION_PATCH})

# The dependencies are pinned upstream submodules (see .gitmodules), never
# vendored copies. A fresh clone needs `git submodule update --init --recursive`.
foreach(required
        external/injector/include/injector/injector.hpp
        external/injector/safetyhook/include/safetyhook.hpp
        external/injector/zydis/Zydis.h
        external/hooking/Hooking.Patterns.h
        external/inireader/IniReader.h
        external/inireader/mINI/src/mini/ini.h)
  if(NOT EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/${required}")
    message(FATAL_ERROR
            "Missing submodule file ${required}; run "
            "`git submodule update --init --recursive`")
  endif()
endforeach()

# The commit hash is part of the product version and of the first trace line, so
# a log always names the binary that produced it.
find_package(Git QUIET)
set(XLA_GIT_SHA "")
if(Git_FOUND AND EXISTS "${CMAKE_CURRENT_SOURCE_DIR}/.git")
  execute_process(COMMAND ${GIT_EXECUTABLE} rev-parse --short HEAD
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    OUTPUT_VARIABLE XLA_GIT_SHA
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET)
endif()
set(XLA_VERSION_STRING "${PROJECT_VERSION}")
if(XLA_GIT_SHA)
  string(APPEND XLA_VERSION_STRING "-${XLA_GIT_SHA}")
endif()

configure_file(cmake/version.hpp.in
               "${CMAKE_CURRENT_BINARY_DIR}/generated/xla/version.hpp" @ONLY)
configure_file(res/version.rc.in
               "${CMAKE_CURRENT_BINARY_DIR}/generated/version.rc" @ONLY)

# The injection stack, wired the way GTAIV.EFLC.FusionFix's premake5.lua wires it
# (`external/injector/safetyhook/include` on the include path, `safetyhook/src/*.cpp`
# and the in-tree Zydis amalgamation compiled in). safetyhook 0.7 embeds the
# assembled x86 mid-hook stub in `mid_hook.cpp` as `asm_data`, so its `src/*.asm`
# files are data for that embed and are not separate MASM sources - FusionFix's
# premake has no MASM item either. `os.linux.cpp` is empty behind
# `SAFETYHOOK_OS_LINUX`; it is listed because the premake glob compiles it.
set(XLA_INJECTOR_DIR "${CMAKE_CURRENT_SOURCE_DIR}/external/injector")
add_library(xla_safetyhook STATIC
  ${XLA_INJECTOR_DIR}/safetyhook/src/allocator.cpp
  ${XLA_INJECTOR_DIR}/safetyhook/src/easy.cpp
  ${XLA_INJECTOR_DIR}/safetyhook/src/inline_hook.cpp
  ${XLA_INJECTOR_DIR}/safetyhook/src/mid_hook.cpp
  ${XLA_INJECTOR_DIR}/safetyhook/src/os.linux.cpp
  ${XLA_INJECTOR_DIR}/safetyhook/src/os.windows.cpp
  ${XLA_INJECTOR_DIR}/safetyhook/src/utility.cpp
  ${XLA_INJECTOR_DIR}/safetyhook/src/vmt_hook.cpp
  ${XLA_INJECTOR_DIR}/zydis/Zydis.c)
set_target_properties(xla_safetyhook PROPERTIES CXX_SCAN_FOR_MODULES OFF)
target_include_directories(xla_safetyhook SYSTEM PUBLIC
  ${XLA_INJECTOR_DIR}/safetyhook/include
  ${XLA_INJECTOR_DIR}/zydis
  ${XLA_INJECTOR_DIR}/include)
target_compile_features(xla_safetyhook PUBLIC cxx_std_23)
target_compile_definitions(xla_safetyhook PUBLIC NOMINMAX)
target_compile_options(xla_safetyhook PRIVATE /EHsc)

# One module interface unit per feature. The library also owns the
# Hooking.Patterns TU from its submodule (the only external .cpp); everything
# else is a module.
set(XLA_MODULES
    source/common.ixx
    source/patch.ixx
    source/build.ixx
    source/config.ixx
    source/warnings.ixx
    source/probe.ixx
    source/savegames.ixx
    source/registry.ixx
    source/profile.ixx
    source/core.ixx
    source/launcher.ixx
    source/menu.ixx
    source/vram.ixx
    source/windowed.ixx
    source/compatibility.ixx
    source/steam.ixx
    source/episodes.ixx
    source/stability.ixx
    source/startup.ixx)

add_library(xla_modules STATIC
  external/hooking/Hooking.Patterns.cpp
  # A data include, not a compiled TU; listed so the IDE and dependency scan see
  # it. launcher.ixx includes it inside the module.
  source/launcher_recovered.inc)
set_target_properties(xla_modules PROPERTIES CXX_SCAN_FOR_MODULES ON)
target_sources(xla_modules PUBLIC
  FILE_SET CXX_MODULES FILES ${XLA_MODULES})
target_include_directories(xla_modules PUBLIC
  ${CMAKE_CURRENT_SOURCE_DIR}/source
  ${CMAKE_CURRENT_BINARY_DIR}/generated)
target_include_directories(xla_modules SYSTEM PUBLIC
  ${XLA_INJECTOR_DIR}/include
  ${XLA_INJECTOR_DIR}/safetyhook/include
  ${XLA_INJECTOR_DIR}/zydis
  ${CMAKE_CURRENT_SOURCE_DIR}/external/hooking
  ${CMAKE_CURRENT_SOURCE_DIR}/external/inireader)
target_compile_features(xla_modules PUBLIC cxx_std_23)
target_compile_definitions(xla_modules PUBLIC
  UNICODE _UNICODE NOMINMAX _CRT_SECURE_NO_WARNINGS
  WIN32_LEAN_AND_MEAN
  $<$<CONFIG:Trace>:XLA_TRACE>)
target_compile_options(xla_modules PUBLIC
  /utf-8 /Zc:__cplusplus /W4 /permissive- /EHsc
  $<$<CONFIG:Release>:/O2>
  $<$<CONFIG:Trace>:/O2>)
target_link_libraries(xla_modules PUBLIC
  xla_safetyhook
  user32 psapi shell32 version advapi32)

# The ASI. dllmain.cpp is the only plain translation unit in source/ and owns
# startup; the activation-context manifest is the comctl32 v6 dependency the
# startup warnings need.
add_library(${XLA_NAME} SHARED
  source/dllmain.cpp
  res/warnings.rc
  "${CMAKE_CURRENT_BINARY_DIR}/generated/version.rc")
set_target_properties(${XLA_NAME} PROPERTIES
  CXX_SCAN_FOR_MODULES ON
  PREFIX ""
  OUTPUT_NAME "XLivelessAddon"
  SUFFIX ".asi")
target_include_directories(${XLA_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/res)
target_link_libraries(${XLA_NAME} PRIVATE xla_modules)
target_link_options(${XLA_NAME} PRIVATE
  /MACHINE:X86 /SUBSYSTEM:WINDOWS /BASE:0x10000000 /INCREMENTAL:NO
  "/MAP:$<TARGET_FILE_DIR:${XLA_NAME}>/XLivelessAddon.map"
  "/WHOLEARCHIVE:$<TARGET_FILE:xla_modules>")

add_custom_command(TARGET ${XLA_NAME} POST_BUILD
  COMMAND ${CMAKE_COMMAND} -E copy_if_different
          "${CMAKE_CURRENT_SOURCE_DIR}/data/XLivelessAddon.ini"
          "$<TARGET_FILE_DIR:${XLA_NAME}>/XLivelessAddon.ini"
  COMMENT "Copying XLivelessAddon.ini"
  VERBATIM)

enable_testing()

add_executable(xla_tests tests/test_main.cpp)
set_target_properties(xla_tests PROPERTIES CXX_SCAN_FOR_MODULES ON)
target_link_libraries(xla_tests PRIVATE xla_modules)
target_compile_definitions(xla_tests PRIVATE XLA_DATA_DIR="${CMAKE_CURRENT_SOURCE_DIR}/data")
target_link_options(xla_tests PRIVATE /MACHINE:X86 /SUBSYSTEM:CONSOLE)
add_dependencies(xla_tests ${XLA_NAME})
add_test(NAME xla_tests COMMAND xla_tests)
set_tests_properties(xla_tests PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_executable(xla_asi_load tests/asi_load.cpp)
add_dependencies(xla_asi_load ${XLA_NAME})
target_link_libraries(xla_asi_load PRIVATE version)
add_test(NAME xla_asi_load COMMAND xla_asi_load $<TARGET_FILE:${XLA_NAME}>)
set_tests_properties(xla_asi_load PROPERTIES WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR})

add_executable(xla_pe_check tests/pe_check.cpp)
add_dependencies(xla_pe_check ${XLA_NAME})
add_test(NAME xla_pe_check COMMAND xla_pe_check $<TARGET_FILE:${XLA_NAME}>)

find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
  add_test(NAME xla_no_installs
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/check_no_installs.py
            --source ${CMAKE_CURRENT_SOURCE_DIR}/source)
  set_tests_properties(xla_no_installs PROPERTIES
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

  add_test(NAME xla_module_layout
    COMMAND ${Python3_EXECUTABLE} ${CMAKE_CURRENT_SOURCE_DIR}/tools/check_module_layout.py
            --source ${CMAKE_CURRENT_SOURCE_DIR}/source)
  set_tests_properties(xla_module_layout PROPERTIES
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})

  # The recovered SkipLauncher rows are data. This resolves the named offsets
  # and ops:: windows and compares them with the golden captured from the old
  # addon, so the readable rewrite cannot drift from the recovered table.
  add_test(NAME xla_skip_tables
    COMMAND ${Python3_EXECUTABLE}
            ${CMAKE_CURRENT_SOURCE_DIR}/tools/check_skip_launcher_tables.py
            --source ${CMAKE_CURRENT_SOURCE_DIR}/source
            --golden ${CMAKE_CURRENT_SOURCE_DIR}/tests/skip_launcher_tables.tsv)
  set_tests_properties(xla_skip_tables PROPERTIES
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR})
endif()
