cmake_minimum_required(VERSION 3.22.1)
project(auditpatch)

set(CXX_FLAGS "${CXX_FLAGS} -fno-exceptions -fno-rtti -fvisibility=hidden -fvisibility-inlines-hidden")

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${CXX_FLAGS}")

add_library(${MODULE_NAME} SHARED hook.cpp)
target_link_libraries(${MODULE_NAME} log)

# The installer moves this PIE executable from lib/<abi>/libdaemon.so to bin/daemon.
add_executable(daemon daemon.cpp process_monitor.cpp)
set_target_properties(daemon PROPERTIES OUTPUT_NAME "libdaemon.so")
target_link_libraries(daemon log)

foreach(target ${MODULE_NAME} daemon)
    add_custom_command(TARGET ${target} POST_BUILD
            COMMAND "${CMAKE_OBJCOPY}" --remove-section=.comment "$<TARGET_FILE:${target}>"
            VERBATIM)
endforeach()
