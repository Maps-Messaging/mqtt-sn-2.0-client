cmake_minimum_required(VERSION 3.16)
project(mqttsn2_cpp VERSION 0.1.0 LANGUAGES C CXX)

add_subdirectory(
    ${CMAKE_CURRENT_SOURCE_DIR}/../c
    ${CMAKE_CURRENT_BINARY_DIR}/c-core
)

add_library(mqttsn2_cpp INTERFACE)
target_include_directories(mqttsn2_cpp
    INTERFACE
        ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_link_libraries(mqttsn2_cpp INTERFACE mqttsn2)
target_compile_features(mqttsn2_cpp INTERFACE cxx_std_20)

enable_testing()

add_executable(mqttsn2_cpp_test
    test/test_mqttsn.cpp
)
target_link_libraries(mqttsn2_cpp_test PRIVATE mqttsn2_cpp)
add_test(NAME mqttsn2_cpp_test COMMAND mqttsn2_cpp_test)

add_executable(mqttsn2_cpp_auth_test
    test/test_auth.cpp
)
target_link_libraries(mqttsn2_cpp_auth_test PRIVATE mqttsn2_cpp)
add_test(NAME mqttsn2_cpp_auth_test COMMAND mqttsn2_cpp_auth_test)

if(TARGET mqttsn2_openssl)
    add_library(mqttsn2_cpp_openssl INTERFACE)
    target_include_directories(mqttsn2_cpp_openssl
        INTERFACE
            ${CMAKE_CURRENT_SOURCE_DIR}/include
    )
    target_link_libraries(
        mqttsn2_cpp_openssl
        INTERFACE
            mqttsn2_cpp
            mqttsn2_openssl
    )
    target_compile_features(mqttsn2_cpp_openssl INTERFACE cxx_std_20)

    add_executable(
        mqttsn2_cpp_openssl_test
        test/test_openssl_provider.cpp
    )
    target_link_libraries(
        mqttsn2_cpp_openssl_test
        PRIVATE
            mqttsn2_cpp_openssl
    )
    add_test(
        NAME mqttsn2_cpp_openssl_test
        COMMAND mqttsn2_cpp_openssl_test
    )
endif()
