cmake_minimum_required(VERSION 3.21)
project(websocket-codec LANGUAGES C)

set(CMAKE_C_STANDARD 23)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

if(PROJECT_IS_TOP_LEVEL)
  file(REMOVE "${CMAKE_SOURCE_DIR}/compile_commands.json")
  file(CREATE_LINK "${CMAKE_BINARY_DIR}/compile_commands.json"
       "${CMAKE_SOURCE_DIR}/compile_commands.json" SYMBOLIC COPY_ON_ERROR)
endif()

add_library(wsc_warnings INTERFACE)
target_compile_options(
  wsc_warnings
  INTERFACE -Wall
            -Wextra
            -Wpedantic
            -Werror
            -Wconversion
            -Wformat=2
            -Wmissing-prototypes
            -Wshadow
            -Wstrict-prototypes)
add_library(wsc_sanitize INTERFACE)
if(PROJECT_IS_TOP_LEVEL AND (CMAKE_C_COMPILER_ID STREQUAL "Clang" OR CMAKE_C_COMPILER_ID STREQUAL "GNU"))
  target_compile_options(wsc_sanitize INTERFACE -g -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all)
  target_link_options(wsc_sanitize INTERFACE -fsanitize=address,undefined)
endif()

option(WSC_HOSTED "Heap-backed decoder and wsc_encode" ON)
if(NOT WSC_HOSTED)
  unset(WSC_HOSTED CACHE)
  set(WSC_HOSTED OFF)
endif()

if(WSC_HOSTED)
  add_library(wsc src/wsc_common.c src/wsc_hosted.c)
  target_compile_definitions(wsc PUBLIC WSC_HOSTED=1)
else()
  include(FetchContent)
  FetchContent_Declare(
    ringalloc
    GIT_REPOSITORY https://github.com/JoakimJoensuu/ringalloc.git
    GIT_TAG 43098d590c0670ea0ca67eb7634abab4047485f1)
  FetchContent_MakeAvailable(ringalloc)
  add_library(wsc src/wsc_common.c src/wsc_freestanding.c)
  target_compile_options(wsc PRIVATE -ffreestanding)
  target_link_libraries(wsc PUBLIC ringalloc)
endif()

target_include_directories(wsc PUBLIC include)
target_compile_features(wsc PUBLIC c_std_23)
target_link_libraries(wsc PRIVATE wsc_warnings wsc_sanitize)

option(WSC_EXAMPLES "Build examples" ${PROJECT_IS_TOP_LEVEL})
option(WSC_TESTS "Build tests" ${PROJECT_IS_TOP_LEVEL})

if(WSC_EXAMPLES AND WSC_HOSTED)
  add_subdirectory(examples)
endif()

if(WSC_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()
