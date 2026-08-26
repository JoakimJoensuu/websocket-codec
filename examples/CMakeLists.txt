add_executable(example hello.c)
target_link_libraries(example PRIVATE wsc)
wsc_add_warnings(example)
