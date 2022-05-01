CMAKE_MINIMUM_REQUIRED(VERSION 3.16.0)
project(dtls C)

find_package(OpenSSL REQUIRED)

message(STATUS "OpenSSL library status:")
message(STATUS "    OpenSSL Found: ${OPENSSL_FOUND}")
message(STATUS "    version: ${OPENSSL_VERSION}")
message(STATUS "    libraries: ${OPENSSL_SSL_LIBRARIES}")
message(STATUS "    include path: ${OPENSSL_INCLUDE_DIR}")

include_directories(${OPENSSL_INCLUDE_DIR} include)
add_subdirectory(src)

if (WIN32)
    target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES} wsock32 ws2_32)
else()
    target_link_libraries(${PROJECT_NAME} ${OPENSSL_LIBRARIES} pthread /usr/local/ssl/lib64/libssl.so.3 /usr/local/lib64/libcrypto.so.3)
endif()