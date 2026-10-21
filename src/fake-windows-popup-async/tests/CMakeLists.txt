cmake_minimum_required(VERSION 3.18)
project(fake-windows-popup-host-tests LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

enable_testing()
add_executable(policy-tests policy_tests.cpp ../src/policy.cpp)
target_include_directories(policy-tests PRIVATE ../src)
target_compile_options(policy-tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME policy COMMAND policy-tests)

add_executable(args-tests args_tests.cpp ../src/args.cpp)
target_include_directories(args-tests PRIVATE ../src)
target_compile_options(args-tests PRIVATE -Wall -Wextra -Wpedantic)
add_test(NAME args COMMAND args-tests)
