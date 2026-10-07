cmake_minimum_required(VERSION 3.16)
project(mqttsn2_c VERSION 0.1.0 LANGUAGES C)

add_library(mqttsn2 STATIC
    src/mqttsn.c
    src/packets.c
    src/client.c
    src/protection.c
)
target_include_directories(mqttsn2
    PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_compile_features(mqttsn2 PUBLIC c_std_99)

if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
    target_compile_options(mqttsn2 PRIVATE -Wall -Wextra -Wpedantic -Werror)
endif()

enable_testing()

add_executable(mqttsn2_c_test
    test/test_mqttsn.c
)
target_link_libraries(mqttsn2_c_test PRIVATE mqttsn2)
add_test(NAME mqttsn2_c_test COMMAND mqttsn2_c_test)

add_executable(mqttsn2_client_test
    test/test_client.c
)
target_link_libraries(mqttsn2_client_test PRIVATE mqttsn2)
add_test(NAME mqttsn2_client_test COMMAND mqttsn2_client_test)

find_package(OpenSSL 3.0 QUIET COMPONENTS Crypto)
if(OpenSSL_FOUND)
    add_library(mqttsn2_openssl STATIC src/protection_openssl.c)
    target_include_directories(mqttsn2_openssl PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}/include)
    target_link_libraries(mqttsn2_openssl PUBLIC mqttsn2 OpenSSL::Crypto)
    target_compile_features(mqttsn2_openssl PUBLIC c_std_99)
    if(CMAKE_C_COMPILER_ID MATCHES "GNU|Clang")
        target_compile_options(mqttsn2_openssl PRIVATE -Wall -Wextra -Wpedantic -Werror)
    endif()

    add_executable(mqttsn2_openssl_test test/test_openssl_provider.c)
    target_link_libraries(mqttsn2_openssl_test PRIVATE mqttsn2_openssl)
    add_test(NAME mqttsn2_openssl_test COMMAND mqttsn2_openssl_test)
endif()
