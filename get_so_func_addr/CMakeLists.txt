
add_executable(get_so_func_addr main.c ../binary_analyzer.h ../binary_analyzer.c)
target_link_libraries(get_so_func_addr bfd)