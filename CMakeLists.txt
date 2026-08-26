cmake_minimum_required(VERSION 3.21)
project(websocket-codec LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

file(CREATE_LINK "${CMAKE_BINARY_DIR}/compile_commands.json"
     "${CMAKE_SOURCE_DIR}/compile_commands.json" SYMBOLIC COPY_ON_ERROR)

function(wsc_add_warnings target)
  target_compile_options(
    ${target}
    PRIVATE -Wall
            -Wextra
            -Wpedantic
            -Werror
            -Wconversion
            -Wformat=2
            -Wmissing-prototypes
            -Wshadow
            -Wstrict-prototypes)
endfunction()

add_library(wsc src/wsc.c)
target_include_directories(wsc PUBLIC include)
wsc_add_warnings(wsc)

option(WSC_EXAMPLES "Build examples" ${PROJECT_IS_TOP_LEVEL})
option(WSC_TESTS "Build tests" ${PROJECT_IS_TOP_LEVEL})

if(WSC_EXAMPLES)
  add_subdirectory(examples)
endif()

if(WSC_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
