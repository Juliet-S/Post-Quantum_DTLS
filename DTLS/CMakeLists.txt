CMAKE_MINIMUM_REQUIRED(VERSION 3.16.0)
project(dtls C)

if (OPENSSL_FOUND)
else()
    find_package(OpenSSL REQUIRED)
endif()

message(STATUS "OpenSSL library status:")
message(STATUS "    OpenSSL Found: ${OPENSSL_FOUND}")
message(STATUS "    version: ${OPENSSL_VERSION}")
message(STATUS "    libraries: ${OPENSSL_LIBRARIES}")
message(STATUS "    include path: ${OPENSSL_INCLUDE_DIR}")

include_directories(${OPENSSL_INCLUDE_DIR} include)
add_subdirectory(src)

if (WIN32)
    target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES} wsock32 ws2_32)
else()
    target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES} pthread)
endif()