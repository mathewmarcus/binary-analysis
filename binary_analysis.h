#ifndef binary_analysis_H
#define binary_analysis_H

#include <stdint.h>
#include <bfd.h>

enum function_type {
    func_import,
    func_export
};

struct function {
    uint64_t addr;
    char *name;
    enum function_type func_type;

    struct function *next;
};

struct binary {
    bfd *handle;

    struct function *funcs;
};

int load_binary(const char *filename, struct binary *binary);
void unload_binary(struct binary *binary);
long get_lib_func_off(struct binary *binary, const char *func_name);

#endif