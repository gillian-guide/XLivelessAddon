# XLivelessAddon successor (separate project)
#
# Forked from https://github.com/GTAmodding/XLivelessAddon, rewritten against
# the same modern submodules OpenPreCEPatch/FusionFix use (injector,
# Hooking.Patterns, IniReader). The output is XLivelessAddon.asi; it is not part
# of the OpenPreCEPatch module.
cmake_minimum_required(VERSION 3.28)
project(XLivelessAddon LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MSVC)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded")
endif()

set(XLA_ROOT ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(XLA_OUT ${CMAKE_SOURCE_DIR}/bin)

add_library(XLivelessAddon SHARED
    source/dllmain.cpp
    source/skip_launcher.cpp
    source/windowed.cpp
    ${XLA_ROOT}/external/hooking/Hooking.Patterns.cpp
)
target_include_directories(XLivelessAddon PRIVATE
    ${XLA_ROOT}/external/injector/include
    ${XLA_ROOT}/external/injector/safetyhook/include
    ${XLA_ROOT}/external/hooking
    ${XLA_ROOT}/external/inireader
)
target_compile_definitions(XLivelessAddon PRIVATE _CRT_SECURE_NO_WARNINGS)
target_link_libraries(XLivelessAddon PRIVATE user32)
set_target_properties(XLivelessAddon PROPERTIES
    PREFIX ""
    OUTPUT_NAME "XLivelessAddon"
    SUFFIX ".asi"
    RUNTIME_OUTPUT_DIRECTORY_RELEASE "${XLA_OUT}"
    RUNTIME_OUTPUT_DIRECTORY_DEBUG "${XLA_OUT}"
)
target_link_options(XLivelessAddon PRIVATE
    /MACHINE:X86 /SUBSYSTEM:WINDOWS /BASE:0x10000000 /INCREMENTAL:NO /MAP
)

add_custom_command(TARGET XLivelessAddon POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
            ${CMAKE_CURRENT_SOURCE_DIR}/data/XLivelessAddon.ini
            ${XLA_OUT}/XLivelessAddon.ini
    COMMENT "Copying XLivelessAddon.ini")
