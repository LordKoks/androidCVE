/**
 * kallsyms_dumper.c - Дампер символов ядра для диагностики смещений
 * 
 * Этот скрипт читает /proc/kallsyms и извлекает ключевые символы
 * для анализа смещений task_struct, cred и других структур.
 * 
 * Компиляция: gcc -o kallsyms_dumper kallsyms_dumper.c
 * Запуск: ./kallsyms_dumper [output_file]
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <ctype.h>

#define KALLSYMS_PATH "/proc/kallsyms"
#define DEFAULT_OUTPUT "kallsyms_dump.txt"

// Ключевые символы для поиска
static const char* critical_symbols[] = {
    // task_struct related
    "init_task",
    "init_pid_ns",
    "current",
    
    // cred related  
    "init_cred",
    "prepare_creds",
    "commit_creds",
    "override_creds",
    "revert_creds",
    
    // SELinux related
    "selinux_enforcing",
    "selinux_enabled",
    "selinux_state",
    "selinux_avc",
    
    // Kernel functions
    "kernel_read",
    "kernel_write",
    "do_execve",
    "__do_execve_file",
    "sys_call_table",
    
    // Memory management
    "mem_map",
    "vmalloc_base",
    "page_offset_base",
    
    // Module related
    "modules",
    "find_module",
    
    NULL
};

// Структура для хранения символа
typedef struct {
    uint64_t address;
    char type;
    char name[256];
    char module[256];
} ksymbol_t;

// Структура для хранения дампа
typedef struct {
    ksymbol_t* symbols;
    size_t count;
    size_t capacity;
    uint64_t kernel_base;
    int have_kernel_base;
} kallsyms_dump_t;

// Инициализация дампа
static void dump_init(kallsyms_dump_t* dump) {
    dump->capacity = 10000;
    dump->symbols = malloc(dump->capacity * sizeof(ksymbol_t));
    dump->count = 0;
    dump->kernel_base = 0;
    dump->have_kernel_base = 0;
}

// Добавление символа
static void dump_add_symbol(kallsyms_dump_t* dump, const ksymbol_t* sym) {
    if (dump->count >= dump->capacity) {
        dump->capacity *= 2;
        dump->symbols = realloc(dump->symbols, dump->capacity * sizeof(ksymbol_t));
    }
    memcpy(&dump->symbols[dump->count], sym, sizeof(ksymbol_t));
    dump->count++;
    
    // Определение базы ядра по _text
    if (strcmp(sym->name, "_text") == 0 && !dump->have_kernel_base) {
        dump->kernel_base = sym->address;
        dump->have_kernel_base = 1;
    }
}

// Парсинг строки kallsyms
static int parse_kallsyms_line(const char* line, ksymbol_t* sym) {
    char addr_str[32];
    char type_str[8];
    int ret;
    
    // Сброс структуры
    memset(sym, 0, sizeof(ksymbol_t));
    
    // Формат: "address type name [module]"
    ret = sscanf(line, "%31s %7s %255s %255s", 
                 addr_str, type_str, sym->name, sym->module);
    
    if (ret < 3) {
        return -1; // Недостаточно полей
    }
    
    // Парсинг адреса
    char* endptr;
    sym->address = strtoull(addr_str, &endptr, 16);
    if (*endptr != '\0') {
        return -1; // Некорректный адрес
    }
    
    // Тип
    sym->type = type_str[0];
    
    return 0;
}

// Загрузка kallsyms
static int load_kallsyms(kallsyms_dump_t* dump) {
    FILE* fp = fopen(KALLSYMS_PATH, "r");
    if (!fp) {
        fprintf(stderr, "[-] Failed to open %s: %s\n", KALLSYMS_PATH, strerror(errno));
        return -1;
    }
    
    char line[1024];
    int count = 0;
    
    while (fgets(line, sizeof(line), fp)) {
        // Удаление перевода строки
        line[strcspn(line, "\n")] = '\0';
        
        ksymbol_t sym;
        if (parse_kallsyms_line(line, &sym) == 0) {
            dump_add_symbol(dump, &sym);
            count++;
        }
    }
    
    fclose(fp);
    printf("[+] Loaded %d symbols from %s\n", count, KALLSYMS_PATH);
    return 0;
}

// Поиск символа по имени
static ksymbol_t* find_symbol(kallsyms_dump_t* dump, const char* name) {
    for (size_t i = 0; i < dump->count; i++) {
        if (strcmp(dump->symbols[i].name, name) == 0) {
            return &dump->symbols[i];
        }
    }
    return NULL;
}

// Вывод статистики
static void print_stats(kallsyms_dump_t* dump, FILE* out) {
    fprintf(out, "\n");
    fprintf(out, "=== KALLSYMS STATISTICS ===\n");
    fprintf(out, "Total symbols: %zu\n", dump->count);
    
    if (dump->have_kernel_base) {
        fprintf(out, "Kernel base (_text): 0x%016llx\n", (unsigned long long)dump->kernel_base);
    } else {
        fprintf(out, "Kernel base: NOT FOUND\n");
    }
    
    // Подсчет типов
    int types[256] = {0};
    for (size_t i = 0; i < dump->count; i++) {
        types[(unsigned char)dump->symbols[i].type]++;
    }
    
    fprintf(out, "\nSymbol types:\n");
    const char* type_names[] = {
        ['T'] = "Text (code)",
        ['t'] = "Local text",
        ['D'] = "Initialized data",
        ['d'] = "Local data", 
        ['B'] = "BSS (uninitialized)",
        ['b'] = "Local BSS",
        ['R'] = "Read-only data",
        ['r'] = "Local read-only",
        ['A'] = "Absolute",
        ['W'] = "Weak",
        ['V'] = "Weak object",
        ['v'] = "Weak func",
        ['U'] = "Undefined"
    };
    
    for (int i = 0; i < 256; i++) {
        if (types[i] > 0) {
            const char* name = type_names[i] ? type_names[i] : "Unknown";
            fprintf(out, "  %c (%s): %d\n", i, name, types[i]);
        }
    }
    fprintf(out, "\n");
}

// Вывод критических символов
static void print_critical_symbols(kallsyms_dump_t* dump, FILE* out) {
    fprintf(out, "=== CRITICAL SYMBOLS ===\n");
    fprintf(out, "%-40s %-18s %s\n", "Name", "Address", "Type");
    fprintf(out, "%s\n", "----------------------------------------------------------------------------");
    
    int found_count = 0;
    int total_count = 0;
    
    for (int i = 0; critical_symbols[i] != NULL; i++) {
        total_count++;
        ksymbol_t* sym = find_symbol(dump, critical_symbols[i]);
        if (sym) {
            fprintf(out, "%-40s 0x%016llx %c\n", 
                    sym->name, 
                    (unsigned long long)sym->address, 
                    sym->type);
            found_count++;
        } else {
            fprintf(out, "%-40s %-18s %s\n", 
                    critical_symbols[i], 
                    "NOT FOUND", 
                    "-");
        }
    }
    
    fprintf(out, "\nFound %d/%d critical symbols (%.1f%%)\n", 
            found_count, total_count, 
            (total_count > 0) ? (100.0 * found_count / total_count) : 0.0);
    fprintf(out, "\n");
}

// Вывод символов с определенным префиксом
static void print_symbols_with_prefix(kallsyms_dump_t* dump, const char* prefix, int max_count, FILE* out) {
    fprintf(out, "=== SYMBOLS WITH PREFIX '%s' ===\n", prefix);
    fprintf(out, "%-50s %-18s %s\n", "Name", "Address", "Type");
    fprintf(out, "%s\n", "----------------------------------------------------------------------------");
    
    int count = 0;
    size_t prefix_len = strlen(prefix);
    
    for (size_t i = 0; i < dump->count && count < max_count; i++) {
        if (strncmp(dump->symbols[i].name, prefix, prefix_len) == 0) {
            fprintf(out, "%-50s 0x%016llx %c\n", 
                    dump->symbols[i].name,
                    (unsigned long long)dump->symbols[i].address,
                    dump->symbols[i].type);
            count++;
        }
    }
    
    if (count >= max_count) {
        fprintf(out, "\n(Showing first %d matches, more available...)\n", max_count);
    }
    fprintf(out, "Total found: %d\n\n", count);
}

// Функция для поиска смещений структур
static void analyze_structure_offsets(kallsyms_dump_t* dump, FILE* out) {
    fprintf(out, "=== STRUCTURE OFFSET ANALYSIS ===\n");
    fprintf(out, "This section helps identify potential offsets for exploit development.\n\n");
    
    // Ищем символы, связанные с task_struct
    fprintf(out, "1. TASK_STRUCT related symbols:\n");
    size_t prefix_len = strlen("task_struct");
    int count = 0;
    for (size_t i = 0; i < dump->count && count < 20; i++) {
        if (strstr(dump->symbols[i].name, "task_struct") ||
            strstr(dump->symbols[i].name, "__switch_to") ||
            strstr(dump->symbols[i].name, "wake_up_new")) {
            fprintf(out, "   0x%016llx %s\n", 
                    (unsigned long long)dump->symbols[i].address,
                    dump->symbols[i].name);
            count++;
        }
    }
    fprintf(out, "\n");
    
    // Ищем символы, связанные с cred
    fprintf(out, "2. CRED structure related symbols:\n");
    count = 0;
    for (size_t i = 0; i < dump->count && count < 15; i++) {
        if (strstr(dump->symbols[i].name, "prepare_creds") ||
            strstr(dump->symbols[i].name, "commit_creds") ||
            strstr(dump->symbols[i].name, "override_creds") ||
            strstr(dump->symbols[i].name, "revert_creds") ||
            strstr(dump->symbols[i].name, "init_cred")) {
            fprintf(out, "   0x%016llx %s\n",
                    (unsigned long long)dump->symbols[i].address,
                    dump->symbols[i].name);
            count++;
        }
    }
    fprintf(out, "\n");
    
    // Ищем символы SELinux
    fprintf(out, "3. SELinux related symbols:\n");
    count = 0;
    for (size_t i = 0; i < dump->count && count < 15; i++) {
        if (strstr(dump->symbols[i].name, "selinux_") ||
            strstr(dump->symbols[i].name, "selinuxfs") ||
            strstr(dump->symbols[i].name, "avc_")) {
            fprintf(out, "   0x%016llx %s\n",
                    (unsigned long long)dump->symbols[i].address,
                    dump->symbols[i].name);
            count++;
        }
    }
    fprintf(out, "\n");
    
    // Kernel base info
    fprintf(out, "4. Kernel memory layout:\n");
    ksymbol_t* sym = find_symbol(dump, "_text");
    if (sym) {
        fprintf(out, "   Kernel text base: 0x%016llx\n", (unsigned long long)sym->address);
    }
    sym = find_symbol(dump, "_end");
    if (sym) {
        fprintf(out, "   Kernel end:       0x%016llx\n", (unsigned long long)sym->address);
    }
    fprintf(out, "\n");
}

// Основная функция вывода
static void generate_report(kallsyms_dump_t* dump, const char* output_path) {
    FILE* out = fopen(output_path, "w");
    if (!out) {
        fprintf(stderr, "[-] Failed to open output file %s: %s\n", output_path, strerror(errno));
        return;
    }
    
    fprintf(out, "=====================================================================\n");
    fprintf(out, "           KERNEL SYMBOLS DUMP - KGSL EXPLOIT DIAGNOSTIC              \n");
    fprintf(out, "=====================================================================\n");
    fprintf(out, "Generated: %s\n", __DATE__ " " __TIME__);
    fprintf(out, "Source: %s\n", KALLSYMS_PATH);
    fprintf(out, "=====================================================================\n\n");
    
    // Статистика
    print_stats(dump, out);
    
    // Критические символы
    print_critical_symbols(dump, out);
    
    // Анализ структур
    analyze_structure_offsets(dump, out);
    
    // Примечания по использованию для эксплойта
    fprintf(out, "\n");
    fprintf(out, "=====================================================================\n");
    fprintf(out, "                    EXPLOIT DEVELOPMENT NOTES                         \n");
    fprintf(out, "=====================================================================\n");
    fprintf(out, "\n");
    fprintf(out, "1. TASK_STRUCT OFFSETS:\n");
    fprintf(out, "   - comm (task name):  Обычно смещение 0x4A0-0x5C0 (зависит от ядра)\n");
    fprintf(out, "   - pid:               Обычно 0x400-0x4A0\n");
    fprintf(out, "   - cred pointer:      Обычно 0x498-0x5A8 (ДВА указателя: real_cred и cred)\n");
    fprintf(out, "   - mm_struct:         Обычно 0x350-0x3E0\n");
    fprintf(out, "\n");
    fprintf(out, "2. CRED STRUCTURE:\n");
    fprintf(out, "   - uid/euid:          Обычно смещение 0x04-0x28\n");
    fprintf(out, "   - gid/egid:          Следуют после UID\n");
    fprintf(out, "   - capabilities:      Обычно 0x30-0x60 (cap_inheritable, cap_permitted, etc.)\n");
    fprintf(out, "   - security (SELinux): Обычно указатель на 0x78-0x98\n");
    fprintf(out, "\n");
    fprintf(out, "3. ROG PHONE / SD888 SPECIFIC:\n");
    fprintf(out, "   - Проверьте символы kallsyms выше для точных адресов\n");
    fprintf(out, "   - task_struct на SD888 может иметь расширенные поля для GPU\n");
    fprintf(out, "   - cred может быть на нестандартном смещении из-за SELinux hooks\n");
    fprintf(out, "\n");
    fprintf(out, "4. KGSL EXPLOIT TIPS:\n");
    fprintf(out, "   - Используйте spray с marker KETO0422 для идентификации\n");
    fprintf(out, "   - K-PTR density > 100 указывает на task_struct\n");
    fprintf(out, "   - Проверяйте наличие букв в comm для валидации\n");
    fprintf(out, "   - cred_ptr должен указывать на структуру с UID процесса\n");
    fprintf(out, "\n");
    fprintf(out, "=====================================================================\n");
    fprintf(out, "                      END OF REPORT                                   \n");
    fprintf(out, "=====================================================================\n");
    
    fclose(out);
    printf("[+] Report saved to: %s\n", output_path);
}

// Быстрый режим - только критические символы
static void quick_mode(kallsyms_dump_t* dump) {
    printf("\n");
    printf("=== QUICK MODE - CRITICAL SYMBOLS ===\n");
    printf("%-40s %-18s %s\n", "Name", "Address", "Type");
    printf("%s\n", "----------------------------------------------------------------------------");
    
    int found = 0;
    for (int i = 0; critical_symbols[i] != NULL; i++) {
        ksymbol_t* sym = find_symbol(dump, critical_symbols[i]);
        if (sym) {
            printf("%-40s 0x%016llx %c\n", 
                   sym->name, 
                   (unsigned long long)sym->address, 
                   sym->type);
            found++;
        }
    }
    
    printf("\nFound %d critical symbols\n", found);
    
    if (dump->have_kernel_base) {
        printf("Kernel base: 0x%016llx\n", (unsigned long long)dump->kernel_base);
    }
}

int main(int argc, char* argv[]) {
    printf("=====================================================================\n");
    printf("              Kernel Symbols Dumper v1.0                               \n");
    printf("           For KGSL CVE-2023-33107 Exploit Dev                         \n");
    printf("=====================================================================\n\n");
    
    // Проверяем доступность kallsyms
    if (access(KALLSYMS_PATH, R_OK) != 0) {
        fprintf(stderr, "[-] Cannot read %s: %s\n", KALLSYMS_PATH, strerror(errno));
        fprintf(stderr, "[!] Try running as root or check kernel.kptr_restrict setting\n");
        return 1;
    }
    
    // Инициализация
    kallsyms_dump_t dump;
    dump_init(&dump);
    
    // Загрузка символов
    if (load_kallsyms(&dump) != 0) {
        fprintf(stderr, "[-] Failed to load kallsyms\n");
        free(dump.symbols);
        return 1;
    }
    
    // Определение режима работы
    int quick = 0;
    const char* output_path = DEFAULT_OUTPUT;
    
    if (argc > 1) {
        if (strcmp(argv[1], "-q") == 0 || strcmp(argv[1], "--quick") == 0) {
            quick = 1;
        } else {
            output_path = argv[1];
        }
    }
    
    if (argc > 2 && (strcmp(argv[1], "-q") == 0 || strcmp(argv[1], "--quick") == 0)) {
        output_path = argv[2];
    }
    
    if (quick) {
        quick_mode(&dump);
    }
    
    // Генерация полного отчета
    printf("\n[*] Generating full report to %s...\n", output_path);
    generate_report(&dump, output_path);
    
    // Очистка
    free(dump.symbols);
    
    printf("\n[+] Done! Use this report to analyze kernel structure offsets.\n");
    printf("[+] Next steps for KGSL exploit development:\n");
    printf("    1. Check 'init_task' and 'init_cred' addresses\n");
    printf("    2. Use these addresses to calculate task_struct layout\n");
    printf("    3. Update exploit with correct offsets for your SD888\n");
    
    return 0;
}
