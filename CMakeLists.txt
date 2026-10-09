cmake_minimum_required(VERSION 3.20)
project(tinyproxy VERSION 1.11.3 LANGUAGES C)

include(CheckFunctionExists)
include(CheckIncludeFile)
include(GNUInstallDirs)
include(CTest)
find_package(Threads REQUIRED)

check_function_exists(strlcpy HAVE_STRLCPY)
check_function_exists(setgroups HAVE_SETGROUPS)
check_function_exists(ftruncate HAVE_FTRUNCATE)
check_include_file(alloca.h HAVE_ALLOCA_H)
check_include_file(memory.h HAVE_MEMORY_H)
check_include_file(poll.h HAVE_POLL_H)
check_include_file(sys/ioctl.h HAVE_SYS_IOCTL_H)
check_include_file(sysexits.h HAVE_SYSEXITS_H)
check_include_file(values.h HAVE_VALUES_H)

configure_file(config.h.cmake.in "${CMAKE_CURRENT_BINARY_DIR}/config.h" @ONLY)

add_executable(tinyproxy
    src/hostspec.c src/acl.c src/anonymous.c src/buffer.c src/child.c
    src/conf-tokens.c src/conf.c src/conns.c src/daemon.c src/heap.c
    src/html-error.c src/http-message.c src/log.c src/network.c
    src/reqs.c src/nox-policy.c src/sock.c src/stats.c src/text.c
    src/main.c src/utils.c src/upstream.c src/basicauth.c src/base64.c
    src/sblist.c src/hsearch.c src/pseudomap.c src/loop.c src/mypoll.c
    src/connect-ports.c src/filter.c src/reverse-proxy.c
    src/transparent-proxy.c
)
target_compile_features(tinyproxy PRIVATE c_std_99)
target_include_directories(tinyproxy PRIVATE "${CMAKE_CURRENT_BINARY_DIR}" src)
target_compile_definitions(tinyproxy PRIVATE
    HAVE_CONFIG_H
    NDEBUG
    FILTER_ENABLE UPSTREAM_SUPPORT REVERSE_SUPPORT TRANSPARENT_PROXY XTINYPROXY_ENABLE
    SYSCONFDIR="${CMAKE_INSTALL_FULL_SYSCONFDIR}/tinyproxy"
    LOCALSTATEDIR="${CMAKE_INSTALL_FULL_LOCALSTATEDIR}"
)
target_link_libraries(tinyproxy PRIVATE Threads::Threads)
set_target_properties(tinyproxy PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/src")

if(BUILD_TESTING)
    find_package(Python3 COMPONENTS Interpreter REQUIRED)
    add_test(NAME nox_policy
        COMMAND "${Python3_EXECUTABLE}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/scripts/test_nox_policy.py" "$<TARGET_FILE:tinyproxy>")
endif()
