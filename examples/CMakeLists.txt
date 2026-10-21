add_executable(example hello.c)
target_link_libraries(example PRIVATE wsc wsc_warnings wsc_sanitize)
