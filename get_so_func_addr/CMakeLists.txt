
add_executable(get_so_func_addr main.c ../binary_analysis.h ../binary_analysis.c)
target_link_libraries(get_so_func_addr bfd)
install(TARGETS get_so_func_addr DESTINATION "bin/")