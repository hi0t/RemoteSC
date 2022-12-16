cmake_minimum_required(VERSION 3.12)

project(rpkcs11)

include(ExternalProject)

ExternalProject_Add(mbedtls
    URL https://github.com/Mbed-TLS/mbedtls/archive/refs/tags/v3.2.1.tar.gz
    CMAKE_ARGS
        -DENABLE_PROGRAMS=OFF
        -DENABLE_TESTING=OFF
        -DCMAKE_C_VISIBILITY_PRESET=hidden
        -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
        -DCMAKE_BUILD_TYPE=Release
    UPDATE_COMMAND ""
)
ExternalProject_Get_Property(mbedtls INSTALL_DIR)
set(MBEDTLS_ROOT ${INSTALL_DIR})

ExternalProject_Add(curl
    URL https://curl.se/download/curl-7.86.0.tar.gz
    CMAKE_ARGS
        -DBUILD_SHARED_LIBS=OFF
        -DHTTP_ONLY=ON
        -DCURL_USE_MBEDTLS=ON
        -DCMAKE_FIND_ROOT_PATH=${MBEDTLS_ROOT}
        -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
        -DCMAKE_BUILD_TYPE=Release
    UPDATE_COMMAND ""
    DEPENDS mbedtls
)
ExternalProject_Get_Property(curl INSTALL_DIR)
set(CURL_INCLUDE ${INSTALL_DIR}/include)
set(CURL_LIB ${INSTALL_DIR}/lib)

ExternalProject_Add(json-c
    URL  https://github.com/json-c/json-c/archive/refs/tags/json-c-0.16-20220414.tar.gz
    CMAKE_ARGS
        -DBUILD_SHARED_LIBS=OFF
        -DCMAKE_INSTALL_PREFIX:PATH=<INSTALL_DIR>
        -DCMAKE_POSITION_INDEPENDENT_CODE=ON
        -DCMAKE_BUILD_TYPE=Release
    UPDATE_COMMAND ""
)
ExternalProject_Get_Property(json-c INSTALL_DIR)
set(JSONC_INCLUDE ${INSTALL_DIR}/include)
set(JSONC_LIB ${INSTALL_DIR}/lib)

include_directories(${CURL_INCLUDE} ${JSONC_INCLUDE} ${MBEDTLS_ROOT}/include)
if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
    add_link_options(-Wl,--no-undefined)
endif()

add_library(rpkcs11 SHARED http.c lib.c utils.c)
add_dependencies(rpkcs11 curl json-c)
target_link_libraries(rpkcs11
    ${CURL_LIB}/libcurl.a
    ${JSONC_LIB}/libjson-c.a
    ${MBEDTLS_ROOT}/lib/libmbedtls.a
    ${MBEDTLS_ROOT}/lib/libmbedx509.a
    ${MBEDTLS_ROOT}/lib/libmbedcrypto.a
)
