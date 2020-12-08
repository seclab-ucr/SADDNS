cmake_minimum_required (VERSION 3.0)

project (dnsinjector2)

set (CMAKE_BUILD_TYPE Debug)
#set (CMAKE_BUILD_TYPE Release)

if (CMAKE_BUILD_TYPE STREQUAL Debug)
    add_definitions (-D_DEBUG)
endif ()

# Use binary search in scan.
#add_definitions (-D_USE_BINARYSEARCH)

add_executable (nsmuter nsmuter.c util.c network.c dns.c)
add_executable (delayns delayns.c util.c network.c dns.c)
add_executable (udpscan udpscan.c util.c network.c dns.c scanner.c)
add_executable (attack_recur attack_recur.c util.c network.c dns.c scanner.c)
add_executable (attack_recur_ns attack_recur_ns.c util.c network.c dns.c scanner.c)
add_executable (attack_forwr attack_forwr.c util.c network.c dns.c scanner.c)

find_package (Threads)
target_link_libraries (nsmuter ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries (delayns ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries (udpscan ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries (attack_recur ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries (attack_recur_ns ${CMAKE_THREAD_LIBS_INIT})
target_link_libraries (attack_forwr ${CMAKE_THREAD_LIBS_INIT})
