# Android Kernel Exploit - CVE-2024-23380 (KGSL UAF)

## Описание

Эксплойт для уязвимости Use-After-Free в драйвере GPU Qualcomm KGSL (CVE-2024-23380) на устройстве ASUS ROG Phone 5S.

## Устройство

- Модель: ASUS ROG Phone 5S (ZS676KS / I005_1)
- Процессор: Qualcomm Snapdragon 888+ (SM8350)
- GPU: Adreno 660
- Ядро: 5.4.210-qgki-perf
- ОС: Android 13 (SDK 33)
- Прошивка: WW-33.0210.0210.200

## Компиляция

```bash
gcc -O2 ex_rog_working.c -o exploit -pthread -w
./exploit
