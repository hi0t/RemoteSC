cmake_minimum_required(VERSION 3.5)

project(RemoteSC)

if(MSVC)
    add_compile_options(/W4 /WX)
else()
    add_compile_options(-Wall -Wextra -Wpedantic -Werror)
    add_link_options(-Wl,--no-undefined)
endif()

add_library(rpkcs11 SHARED lib.c utils.c)
