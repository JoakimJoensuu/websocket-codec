include(FetchContent)
enable_language(CXX)

set(CGREEN_WITH_UNIT_TESTS OFF CACHE BOOL "" FORCE)
set(CGREEN_WITH_STATIC_LIBRARY ON CACHE BOOL "" FORCE)
set(CGREEN_WITH_XML OFF CACHE BOOL "" FORCE)
set(CGREEN_WITH_LIBXML2 OFF CACHE BOOL "" FORCE)

FetchContent_Declare(
  cgreen
  GIT_REPOSITORY https://github.com/cgreen-devs/cgreen.git
  GIT_TAG 1.7.0
  GIT_SHALLOW TRUE)
set(CMAKE_EXPORT_COMPILE_COMMANDS OFF)
FetchContent_MakeAvailable(cgreen)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

add_executable(test_wsc wsc.c)
target_link_libraries(test_wsc PRIVATE wsc cgreen_static)
wsc_add_warnings(test_wsc)
target_include_directories(test_wsc SYSTEM PRIVATE ${cgreen_SOURCE_DIR}/include)
add_test(NAME wsc COMMAND test_wsc)
