/* SPDX-License-Identifier: GPL-2.0-or-later */
/* Derived from WonderLantern Z6 profile; Z5 C1.50 Q1/Q2 research only.
 * Cortex-A15, CBAR, GIC revision and timing are execution assumptions,
 * not identified Z5 silicon. RAM pools follow the checked Z5 scatter table;
 * C1800000..C8700000 is an SDK validity window. Native boot allocator
 * literals10231c8c/10231d04 add C8500000..CC400000. The native boot DMA
 * requests add CC400000..CCB00000; classification routine102319d4
 * supplies low auxiliary windows. None is a measured DRAM capacity.
 */
#ifndef NIKON_Z5_PROFILE_H
#define NIKON_Z5_PROFILE_H
#include "nikon-model-config.h"
#define Z5_MAIN_SHA256 "1d9742a951ea8a8ebe695fa9bb1f29a3be73e16dfe4a8372d997e903bbc58e98"
typedef struct NikonZ5Profile {
    const char *cpu_type;
    uint32_t cbar, timer_hz, main_base, main_bytes;
    unsigned gic_version, serial_fifo_depth;
    NikonRawGeometry raw;
    NikonFunctionalTiming timing;
} NikonZ5Profile;
static const NikonZ5Profile nikon_z5_profile = {
    .cpu_type = "cortex-a15-arm-cpu", .cbar = 0x2c000000,
    .timer_hz = 48000000, .main_base = 0x10020000, .main_bytes = 34603578,
    .gic_version = 1, .serial_fifo_depth = 16,
    /* Donor ISP geometry is provisional; not Z5 sensor dimensions. */
    .raw = {2034, 1434, 4080, 64, 4095},
    .timing = {100000, 100000, 1000000, 1000000, 33333333, 16666667},
};
typedef struct NikonRAMWindow { uint32_t base, size; } NikonRAMWindow;
static const NikonRAMWindow nikon_z5_ram_windows[] = {
    {0x80000000, 0x10000},
    {0x80100000, 0x5e0000},
    {0x80800000, 0x22e2400},
    {0x82b00000, 0x7ae1c00},
    {0x8a600000, 0x2027400},
    {0x8c700000, 0x329b1c00},
    {0xbf300000, 0xc4fa00},
    {0xc0000000, 0xd8a0000},
    {0xcd900000, 0x10e0000},
    {0xcea00000, 0x63cb400},
    {0xd4e00000, 0xd320000},
    {0xe2200000, 0x1dd15400},
};
#endif
