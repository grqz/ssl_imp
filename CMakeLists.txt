cmake_minimum_required(VERSION 3.20 FATAL_ERROR)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
project(ssl_imp)

set(OPENSSL_ROOT_DIR "" CACHE STRING "root dir to OpenSSL")
set(OPENSSL_USE_STATIC_LIBS OFF)
find_package(OpenSSL REQUIRED)

string(REGEX MATCH "^[0-9]+\\.[0-9]+\\.[0-9]+" OSSL_VSN_NUM "${OPENSSL_VERSION}")
if (NOT OSSL_VSN_NUM VERSION_GREATER_EQUAL "3.6.0")
  message(FATAL_ERROR "OpenSSL version must be >= 3.6.0, but found ${OSSL_VSN_NUM} at ${OPENSSL_INCLUDE_DIR} under ${OPENSSL_ROOT_DIR}")
endif()

if (MSVC)
    add_compile_options(/W4 /Wall /wd4100 /wd4295 /wd4152 /wd4701 /wd4189 /wd5045 /wd4710)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS)
    set(EXTRA_LIBS ${EXTRA_LIBS} ws2_32)
elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU" OR CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    add_compile_options(-Wall -Wextra -pedantic -Wno-unused-parameter -Wno-unused-const-variable)
endif()

add_executable(ssl_imp main.c)
target_link_libraries(ssl_imp PRIVATE OpenSSL::SSL OpenSSL::Crypto OpenSSL::applink ${EXTRA_LIBS})
file(GLOB_RECURSE OPENSSL_DLLS "${OPENSSL_INCLUDE_DIR}/../lib*.dll")
if (NOT "${OPENSSL_DLLS} " STREQUAL " ")
    add_custom_command(TARGET ssl_imp POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different ${OPENSSL_DLLS} $<TARGET_FILE_DIR:ssl_imp>)
endif()
