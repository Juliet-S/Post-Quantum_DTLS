CMAKE_MINIMUM_REQUIRED(VERSION 3.16.0)
set(CMAKE_C_STANDARD 11)
project(dtls C)

if (DEBUG)
    add_compile_definitions(DEBUG)
endif()

if (NOT WOLFSSL_LIBRARIES)
    message(FATAL_ERROR "WOLFSSL_LIBRARIES not specified")
endif()

if (NOT WOLFSSL_INCLUDE_DIR)
    message(FATAL_ERROR "WOLFSSL_INCLUDE_DIR not specified")
endif()

if (NOT LIBOQS_LIBRARIES)
    message(FATAL_ERROR "LIBOQS_LIBRARIES not specified")
endif()

message(STATUS "Library Status:")
message(STATUS "    libraries: ${WOLFSSL_LIBRARIES} ${LIBOQS_LIBRARIES}")
message(STATUS "    include path: ${WOLFSSL_INCLUDE_DIR}")

include_directories(${WOLFSSL_INCLUDE_DIR} include)
add_subdirectory(src)

if (WIN32)
    target_link_libraries(${PROJECT_NAME}_server ${WOLFSSL_LIBRARIES} ${LIBOQS_LIBRARIES} wsock32 ws2_32)
    target_link_libraries(${PROJECT_NAME}_client ${WOLFSSL_LIBRARIES} ${LIBOQS_LIBRARIES} wsock32 ws2_32)
else()
    target_link_libraries(${PROJECT_NAME}_server ${WOLFSSL_LIBRARIES} ${LIBOQS_LIBRARIES} pthread m)
    target_link_libraries(${PROJECT_NAME}_client ${WOLFSSL_LIBRARIES} ${LIBOQS_LIBRARIES} pthread m)
endif()