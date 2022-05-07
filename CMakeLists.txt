cmake_minimum_required(VERSION 3.0.0)
project(binary_analysis VERSION 0.1.0 LANGUAGES "C")

include(CTest)
enable_testing()

add_subdirectory(./get_so_func_addr)

set(CPACK_PROJECT_NAME ${PROJECT_NAME})
set(CPACK_PROJECT_VERSION ${PROJECT_VERSION})
include(CPack)
