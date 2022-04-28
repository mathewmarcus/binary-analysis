#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "binary_analyzer.h"


int load_binary(const char *filename, struct binary *binary) {
    static int bfd_inited = 0;

    if (!bfd_inited) {
        bfd_init();
        bfd_inited = 1;
    }

    if (!(binary->handle = bfd_openr(filename, NULL))) {
        fprintf(stderr, "Failed to open file %s: %s\n", filename, bfd_errmsg(bfd_get_error()));
        return 1;
    }

    if (!bfd_check_format(binary->handle, bfd_object)) {
        fprintf(stderr, "File %s has an invalid format: %s\n", filename, bfd_errmsg(bfd_get_error()));
        bfd_close(binary->handle);
        return 1;
    }

    bfd_set_error(bfd_error_no_error);
    if (bfd_get_flavour(binary->handle) == bfd_target_unknown_flavour) {
        fprintf(stderr, "File %s has an invalid flavour: %s\n", filename, bfd_errmsg(bfd_get_error()));
        bfd_close(binary->handle);
        return 1;
    }

    return 0;
}


void unload_binary(struct binary *binary) {
    bfd_close(binary->handle);
}


long get_lib_func_addr(struct binary *binary, const char *func_name) {
    long nsyms, sym_table_max;
    asymbol **sym_table;
    struct function *func;

    switch ((sym_table_max = bfd_get_dynamic_symtab_upper_bound(binary->handle))) {
        case 0:
            fprintf(stderr, "No dynamic symbols found in %s: %s\n", binary->handle->filename, bfd_errmsg(bfd_get_error()));
            return 0;
        case -1:
            fprintf(stderr, "Failed to load dynamic symbols in %s: %s\n", binary->handle->filename, bfd_errmsg(bfd_get_error()));
            return -1;
        default:
            break;
    }

    if (!(sym_table = malloc(sym_table_max))) {
        fprintf(stderr, "Failed to allocate space for dynamic symbol table: %s\n", strerror(errno));
        exit(1);
    }

    if ((nsyms = bfd_canonicalize_dynamic_symtab(binary->handle, sym_table)) < 0) {
        fprintf(stderr, "Failed to read dynamic symbol table in %s: %s\n", binary->handle->filename, bfd_errmsg(bfd_get_error()));
        return -1;
    }

    for (long i = 0; i < nsyms; i++) {
        if (
            sym_table[i]->flags & BSF_FUNCTION &&
            sym_table[i]->flags & BSF_GLOBAL &&
            bfd_section_name(bfd_asymbol_section(sym_table[i])) != BFD_UND_SECTION_NAME &&
            !strcmp(func_name, bfd_asymbol_name(sym_table[i]))
        ) {
            fprintf(stderr, "name: %s, addr: 0x%08lx\n", bfd_asymbol_name(sym_table[i]), bfd_asymbol_value(sym_table[i]));
            return (long) bfd_asymbol_value(sym_table[i]);
        }
    }

    fprintf(stderr, "Failed to find symbol for func %s\n", func_name);
    return -1;
    
}