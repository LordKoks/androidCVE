/**
 * kernel_info_extractor.c - Извлечение информации о ядре без root
 * 
 * Этот скрипт пытается получить информацию о ядре и символах
 * без root-прав через различные обходные пути.
 * 
 * Компиляция: gcc -o kernel_info_extractor kernel_info_extractor.c
 * Запуск: ./kernel_info_extractor
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/utsname.h>
#include <sys/sysinfo.h>
#include <ctype.h>
#include <dirent.h>

#define OUTPUT_FILE "kernel_info_report.txt"
#define MAX_BUFFER 8192

// Структура для хранения информации
typedef struct {
    // Информация о системе
    char kernel_version[256];
    char machine[256];
    char nodename[256];
    char release[256];
    char version[256];
    
    // Информация о памяти
    uint64_t total_ram;
    uint64_t free_ram;
    
    // Попытка получить базу ядра
    uint64_t kernel_base_guess;
    int have_kernel_base;
    
    // Параметры ядра из /proc/cmdline
    char cmdline[1024];
    
    // Информация из /proc/config.gz если доступна
    int has_config;
    
} kernel_info_t;

// Инициализация структуры
void init_kernel_info(kernel_info_t* info) {
    memset(info, 0, sizeof(kernel_info_t));
}

// Получение базовой информации о системе
void get_system_info(kernel_info_t* info) {
    struct utsname uts;
    struct sysinfo si;
    
    printf("[*] Gathering system information...\n");
    
    if (uname(&uts) == 0) {
        strncpy(info->kernel_version, uts.version, sizeof(info->kernel_version)-1);
        strncpy(info->machine, uts.machine, sizeof(info->machine)-1);
        strncpy(info->nodename, uts.nodename, sizeof(info->nodename)-1);
        strncpy(info->release, uts.release, sizeof(info->release)-1);
        strncpy(info->version, uts.version, sizeof(info->version)-1);
        
        printf("    Kernel: %s\n", info->release);
        printf("    Machine: %s\n", info->machine);
        printf("    Version: %s\n", info->version);
    }
    
    if (sysinfo(&si) == 0) {
        info->total_ram = si.totalram;
        info->free_ram = si.freeram;
        printf("    RAM: %lu MB total\n", info->total_ram / (1024*1024));
    }
}

// Попытка прочитать /proc/cmdline
void get_cmdline(kernel_info_t* info) {
    FILE* fp = fopen("/proc/cmdline", "r");
    if (fp) {
        if (fgets(info->cmdline, sizeof(info->cmdline), fp)) {
            // Удаляем перевод строки
            info->cmdline[strcspn(info->cmdline, "\n")] = '\0';
            printf("[*] Kernel cmdline: %s\n", info->cmdline);
            
            // Пытаемся найти информацию о базе ядра в cmdline
            char* androidboot = strstr(info->cmdline, "androidboot.kernel");
            if (androidboot) {
                printf("    Found kernel boot info: %.50s...\n", androidboot);
            }
        }
        fclose(fp);
    }
}

// Проверка /proc/config.gz
void check_kernel_config(kernel_info_t* info) {
    printf("[*] Checking for kernel config...\n");
    
    // Проверяем /proc/config.gz
    if (access("/proc/config.gz", R_OK) == 0) {
        printf("    [+] /proc/config.gz is readable!\n");
        info->has_config = 1;
        
        // Пытаемся извлечь информацию
        FILE* fp = popen("zcat /proc/config.gz 2>/dev/null | grep -E '(CONFIG_KGSL|CONFIG_DEBUG_KERNEL|CONFIG_KALLSYMS)' | head -20", "r");
        if (fp) {
            char line[256];
            printf("    Relevant kernel config:\n");
            while (fgets(line, sizeof(line), fp)) {
                printf("      %s", line);
            }
            pclose(fp);
        }
    } else {
        printf("    [-] /proc/config.gz not accessible\n");
    }
    
    // Проверяем /boot/config-*
    DIR* dir = opendir("/boot");
    if (dir) {
        struct dirent* entry;
        while ((entry = readdir(dir)) != NULL) {
            if (strncmp(entry->d_name, "config-", 7) == 0) {
                char path[512];
                snprintf(path, sizeof(path), "/boot/%s", entry->d_name);
                if (access(path, R_OK) == 0) {
                    printf("    [+] Found %s\n", path);
                }
            }
        }
        closedir(dir);
    }
}

// Эвристическая оценка базы ядра
void guess_kernel_base(kernel_info_t* info) {
    printf("[*] Attempting to estimate kernel base address...\n");
    
    // Обычно ядро Android располагается по этим адресам
    uint64_t common_bases[] = {
        0xffffff8008000000ULL,  // Common ARM64 kernel base
        0xffffff8010000000ULL,  // Alternative base
        0xffffff9000000000ULL,  // Samsung/Qualcomm sometimes use this
        0xffffffc000000000ULL,  // Another common base
    };
    
    printf("    Common kernel base addresses for ARM64:\n");
    for (size_t i = 0; i < sizeof(common_bases)/sizeof(common_bases[0]); i++) {
        printf("      0x%016llx\n", (unsigned long long)common_bases[i]);
    }
    
    // Пытаемся получить информацию от ядра через другие пути
    FILE* fp = fopen("/sys/kernel/debug/kernel_page_tables", "r");
    if (fp) {
        printf("    [+] /sys/kernel/debug/kernel_page_tables accessible!\n");
        // Читаем первые строки
        char line[256];
        int lines = 0;
        while (fgets(line, sizeof(line), fp) && lines < 10) {
            printf("      %s", line);
            lines++;
        }
        fclose(fp);
    }
}

// Проверка SELinux статуса
void check_selinux_status() {
    printf("[*] Checking SELinux status...\n");
    
    FILE* fp = fopen("/sys/fs/selinux/enforce", "r");
    if (fp) {
        char status[16];
        if (fgets(status, sizeof(status), fp)) {
            int enforcing = atoi(status);
            printf("    SELinux is %s\n", enforcing ? "ENFORCING (strict)" : "PERMISSIVE");
        }
        fclose(fp);
    } else {
        printf("    Cannot determine SELinux status\n");
    }
    
    // Проверяем current context
    fp = fopen("/proc/self/attr/current", "r");
    if (fp) {
        char context[256];
        if (fgets(context, sizeof(context), fp)) {
            printf("    Current process context: %s", context);
        }
        fclose(fp);
    }
}

// Поиск информации о KGSL в sysfs
void check_kgsl_info() {
    printf("[*] Checking KGSL GPU driver info...\n");
    
    const char* kgsl_paths[] = {
        "/sys/class/kgsl",
        "/sys/devices/soc/*.qcom,kgsl-3d0",
        "/sys/bus/platform/drivers/kgsl",
        "/sys/kernel/debug/kgsl",
    };
    
    for (size_t i = 0; i < sizeof(kgsl_paths)/sizeof(kgsl_paths[0]); i++) {
        if (access(kgsl_paths[i], F_OK) == 0) {
            printf("    [+] Found KGSL path: %s\n", kgsl_paths[i]);
        }
    }
    
    // Проверяем информацию о GPU
    FILE* fp = popen("cat /sys/class/kgsl/kgsl-3d0/gpu_model 2>/dev/null || cat /sys/class/misc/kgsl/kgsl-3d0/gpu_model 2>/dev/null || echo 'N/A'", "r");
    if (fp) {
        char model[64];
        if (fgets(model, sizeof(model), fp)) {
            model[strcspn(model, "\n")] = '\0';
            printf("    GPU Model: %s\n", model);
        }
        pclose(fp);
    }
}

// Главная функция генерации отчета
void generate_full_report(kernel_info_t* info) {
    FILE* fp = fopen(OUTPUT_FILE, "w");
    if (!fp) {
        fprintf(stderr, "[-] Cannot create output file: %s\n", strerror(errno));
        return;
    }
    
    fprintf(fp, "=====================================================================\n");
    fprintf(fp, "           KERNEL INFO EXTRACTOR REPORT                               \n");
    fprintf(fp, "           For KGSL CVE-2023-33107 Exploit Development                \n");
    fprintf(fp, "=====================================================================\n\n");
    
    fprintf(fp, "SYSTEM INFORMATION:\n");
    fprintf(fp, "  Kernel Release: %s\n", info->release);
    fprintf(fp, "  Machine: %s\n", info->machine);
    fprintf(fp, "  Nodename: %s\n", info->nodename);
    fprintf(fp, "  Version: %s\n", info->version);
    fprintf(fp, "  Total RAM: %lu MB\n", info->total_ram / (1024*1024));
    fprintf(fp, "\n");
    
    fprintf(fp, "KERNEL CMDLINE:\n");
    fprintf(fp, "  %s\n\n", info->cmdline);
    
    fprintf(fp, "KERNEL BASE ESTIMATES:\n");
    fprintf(fp, "  Common ARM64 kernel base addresses:\n");
    fprintf(fp, "    0xffffff8008000000 (most common)\n");
    fprintf(fp, "    0xffffff8010000000 (alternative)\n");
    fprintf(fp, "    0xffffff9000000000 (Qualcomm/Samsung)\n");
    fprintf(fp, "    0xffffffc000000000 (another common)\n");
    fprintf(fp, "\n");
    
    fprintf(fp, "NEXT STEPS FOR EXPLOIT DEVELOPMENT:\n");
    fprintf(fp, "  1. Since /proc/kallsyms requires root, use these alternatives:\n");
    fprintf(fp, "     a) Temporary root via Magisk or other exploit\n");
    fprintf(fp, "     b) Extract from boot.img using tools like aik-magic\n");
    fprintf(fp, "     c) Use KGSL exploit's memory read to scan for signatures\n");
    fprintf(fp, "\n");
    fprintf(fp, "  2. For KGSL CVE-2023-33107 exploit on SD888:\n");
    fprintf(fp, "     - Look for marker KETO0422 in memory dumps\n");
    fprintf(fp, "     - task_struct usually has K-PTR density > 100\n");
    fprintf(fp, "     - cred structure is usually 0x400-0x500 bytes from task_struct start\n");
    fprintf(fp, "     - On SD888, check for non-standard offsets due to extra GPU fields\n");
    fprintf(fp, "\n");
    fprintf(fp, "  3. Manual analysis steps:\n");
    fprintf(fp, "     - Run: zcat /proc/config.gz 2>/dev/null | grep KGSL\n");
    fprintf(fp, "     - Check: ls -la /sys/class/kgsl/\n");
    fprintf(fp, "     - Read: cat /proc/modules 2>/dev/null\n");
    fprintf(fp, "\n");
    
    fprintf(fp, "=====================================================================\n");
    fprintf(fp, "                      END OF REPORT                                   \n");
    fprintf(fp, "=====================================================================\n");
    
    fclose(fp);
    printf("[+] Detailed report saved to: %s\n", OUTPUT_FILE);
}

int main(int argc, char* argv[]) {
    printf("=====================================================================\n");
    printf("          Kernel Info Extractor v1.0 (NO-ROOT VERSION)               \n");
    printf("          For KGSL CVE-2023-33107 Exploit Development                    \n");
    printf("=====================================================================\n\n");
    
    kernel_info_t info;
    init_kernel_info(&info);
    
    // Собираем доступную информацию
    get_system_info(&info);
    get_cmdline(&info);
    check_kernel_config(&info);
    guess_kernel_base(&info);
    check_selinux_status();
    check_kgsl_info();
    
    // Проверяем доступность kallsyms (скорее всего не доступен)
    printf("\n[*] Checking /proc/kallsyms access...\n");
    if (access("/proc/kallsyms", R_OK) == 0) {
        printf("    [+] /proc/kallsyms is readable!\n");
        printf("    [!] You have root or kptr_restrict is disabled\n");
    } else {
        printf("    [-] /proc/kallsyms not accessible (Permission denied)\n");
        printf("    [!] This is normal for non-root users with kptr_restrict enabled\n");
    }
    
    // Проверяем /proc/modules
    printf("\n[*] Checking /proc/modules...\n");
    FILE* fp = fopen("/proc/modules", "r");
    if (fp) {
        char line[256];
        int count = 0;
        printf("    Loaded modules (first 10):\n");
        while (fgets(line, sizeof(line), fp) && count < 10) {
            char* space = strchr(line, ' ');
            if (space) *space = '\0';
            printf("      - %s\n", line);
            count++;
        }
        fclose(fp);
    } else {
        printf("    [-] Cannot read /proc/modules\n");
    }
    
    // Генерируем отчет
    printf("\n");
    generate_full_report(&info);
    
    // Финальные рекомендации
    printf("\n");
    printf("=====================================================================\n");
    printf("                    NEXT STEPS                                       \n");
    printf("=====================================================================\n");
    printf("\n");
    printf("Since you don't have root access, here are your options:\n");
    printf("\n");
    printf("OPTION 1: Use your KGSL exploit's memory read capability\n");
    printf("  - The exploit can already read kernel memory via UAF\n");
    printf("  - Add code to scan for 'init_task' or 'KETO0422' signatures\n");
    printf("  - Look for kernel pointers in the 0xffffff80xxxxxxxx range\n");
    printf("\n");
    printf("OPTION 2: Get temporary root\n");
    printf("  - Use Magisk or other root method temporarily\n");
    printf("  - Run this tool with root to get kallsyms\n");
    printf("  - Save the output and unroot\n");
    printf("\n");
    printf("OPTION 3: Analyze boot.img\n");
    printf("  - Extract boot.img from your device\n");
    printf("  - Use 'aik-magic' or similar tool to unpack\n");
    printf("  - Use vmlinux-to-elf to get symbols\n");
    printf("\n");
    printf("OPTION 4: Use known SD888 offsets (educated guess)\n");
    printf("  - SD888 + ROG Phone likely uses standard Qualcomm layout\n");
    printf("  - Try cred offset at 0x4A8 or 0x538 from task_struct\n");
    printf("  - Check for real_cred vs cred (two pointers)\n");
    printf("\n");
    printf("For KGSL exploit debugging specifically:\n");
    printf("  - Add verbose logging in your exploit\n");
    printf("  - Print hex dumps around KETO0422 marker\n");
    printf("  - Look for patterns: kernel pointers are 0xffffff80xxxxxxxx\n");
    printf("  - cred structure usually has uid=0x3e8 (1000) or your uid\n");
    printf("\n");
    
    return 0;
}
