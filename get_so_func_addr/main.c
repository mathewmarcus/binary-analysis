#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <libgen.h>

#include "../binary_analyzer.h"

static char *pid_max_filename = "/proc/sys/kernel/pid_max";
static char *usage = "Usage: %s LIBRARY PROCEDURE FUNCTION\n";


ssize_t get_pid_max_strlen() {
    FILE *pid_max_file = NULL;
    char *pid_max_str = NULL;
    int ret;
    size_t len;

    if (!(pid_max_file = fopen(pid_max_filename, "r"))) {
        fprintf(stderr, "Failed to open %s: %s\n", pid_max_filename, strerror(errno));
        goto err_exit;
    }

    switch (fscanf(pid_max_file, "%m[0-9]", &pid_max_str)) {
        case 1:
            len = strlen(pid_max_str);
            goto exit;
        case EOF:
            if (ferror(pid_max_file))
                fprintf(stderr, "Failed to read PID max from %s: %s\n", pid_max_filename, strerror(errno));
            else
                fprintf(stderr, "Failed to read PID max from %s: EOF reached\n", pid_max_filename);
            goto err_exit;
        default:
            fprintf(stderr, "Failed to read PID max from %s: invalid formatting\n", pid_max_filename);
            goto err_exit;
    }

err_exit:
    len = -1;

exit:
    free(pid_max_str);
    if (pid_max_file)
        fclose(pid_max_file);

    return len;

}

ssize_t get_load_addr(char *maps, const char *soname) {
    FILE *pid_maps_file = NULL;
    ssize_t addr;
    char *sopath = NULL, *line_ptr = NULL;
    size_t line_len = 0;

    if (!(pid_maps_file = fopen(maps, "r"))) {
        fprintf(stderr, "Failed to open file %s: %s\n", maps, strerror(errno));
        goto err_exit;
    }

    while (1) {
        if (getline(&line_ptr, &line_len, pid_maps_file) == -1) {
            if (ferror(pid_maps_file))
                fprintf(stderr, "Failed to read line from %s: %s\n", maps, strerror(errno));
            goto err_exit;
        }

        if (sscanf(line_ptr, "%lx-%*x %*s %*s %*s %*s %ms", &addr, &sopath) == 2) {
            free(line_ptr);
            if (strstr(sopath, soname)) {
                free(sopath);
                goto exit;
            }
            free(sopath);
            sopath = NULL;
        }
        else
            free(line_ptr);
        line_ptr = NULL;
        line_len = 0;
    }

err_exit:
    addr = -1;

exit:
    if (pid_maps_file)
        fclose(pid_maps_file);
    return addr;
}

ssize_t get_library_load_addr(const char *process_name, const char *soname) {
    DIR *proc = NULL;
    struct dirent *proc_dir;
    pid_t pid;
    char *pid_template = "/proc/%i/";
    char *status = NULL, *maps = NULL, *proc_name = NULL;
    FILE *pid_status_file;
    ssize_t ret, pid_max_strlen;


    if ((pid_max_strlen = get_pid_max_strlen()) == -1) {
        fprintf(stderr, "Failed to get pid_max\n");
        goto err_exit;
    }

    if (!(status = malloc(7 + pid_max_strlen + 6 + 1)) || !(maps = malloc(7 + pid_max_strlen + 4 + 1))) {
        fprintf(stderr, "Failed to allocate space for PID status and maps files: %s\n", strerror(errno));
        goto err_exit;
    }

    if (!(proc = opendir("/proc"))) {
        fprintf(stderr, "Failed to open /proc directory: %s\n", strerror(errno));
        goto err_exit;
    }

    while ((proc_dir = readdir(proc))) {
        if (proc_dir->d_type == DT_DIR && sscanf(proc_dir->d_name, "%i", &pid) == 1) {
            if ((ret = snprintf(status, 7 + pid_max_strlen + 1, pid_template, pid)) == -1 || ret >= 7 + pid_max_strlen) {
                fprintf(stderr, "Failed to format PID dirname /proc/%i", pid);
                goto err_exit;
            }
            strcpy(maps, status);
            strcat(status, "status");
            strcat(maps, "maps");

            // check program name
            if (!(pid_status_file = fopen(status, "r"))) {
                fprintf(stderr, "Failed to open file %s: %s\n", status, strerror(errno));
                goto err_exit;
            }

            switch (fscanf(pid_status_file, "Name:\t%ms\n", &proc_name)) {
                case 1:
                    fclose(pid_status_file);
                    break;
                case EOF:
                    if (ferror(pid_status_file))
                        fprintf(stderr, "Failed to read process name from %s: %s\n", status, strerror(errno));
                    else
                        fprintf(stderr, "Failed to read process name from %s: EOF reached\n", status);
                    fclose(pid_status_file);
                    goto err_exit;
                default:
                    fclose(pid_status_file);
                    fprintf(stderr, "Failed to read process name from %s: invalid formatting\n", status);
                    goto err_exit;
            }

            if (strcmp(process_name, proc_name))
                continue;

            fprintf(stderr, "%s PID: %i\n", process_name, pid);
            
            if ((ret = get_load_addr(maps, soname)) == -1)
                fprintf(stderr, "Failed to find load address for %s in %s\n", soname, maps);
            else
                fprintf(stderr, "%s addr: 0x%lx\n", soname, ret);
            goto exit;
        }
    }

err_exit:
    ret = -1;

exit:
    free(status);
    free(maps);

    if (proc)
        closedir(proc);
    
    return ret;
}


int main(int argc, char *argv[]) {
    long func_addr;
    ssize_t load_addr;
    struct binary binary = { 0 };

    if (argc < 4) {
        fprintf(stderr, usage, argv[0]);
        return 1;
    }

    if ((load_addr = get_library_load_addr(argv[2], basename(argv[1]))) == -1)
        return 1;

    if (load_binary(argv[1], &binary))
        return 1;


    if ((func_addr = get_lib_func_addr(&binary, argv[3])) == -1)
        return 1;

    printf("0x%lx\n", load_addr + func_addr);

    unload_binary(&binary);
    return 0;
}