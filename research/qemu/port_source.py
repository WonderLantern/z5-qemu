# SPDX-License-Identifier: GPL-2.0-or-later
"""从固定 Z6 源码派生 Q1/Q2 Z5 机器；只创建新文件，不修改原有基线。

生成代码保留上游 GPL 标识。外设仍为显式继承的模型假设，不能作为 Z5 硬件事实。
"""
import argparse
import hashlib
from pathlib import Path
import subprocess

from inspect_inputs import BASE, COPY, MAIN_SHA256, MAIN_SIZE, SCATTER_END, SCATTER_START, ZERO
from inspect_inputs import check_identity, read_scatter

ROOT = Path(__file__).resolve().parents[2]
DONOR_COMMIT = '419a1f2a91a1f2d3a0209027c29606475f7fe26f'
BOARD_SHA256 = '9a92f19510f6730312158079cea39717826648da0d245d766ed39ce412e9091c'

PROCESSING_INIT_CODE = '''/* Z5-only diagnostic initialization stand-in. No processing engine runs.
 * C1.50 102e0942/102e06ce/102e10ca/102e05a4 supply these configuration fields.
 * 102e0b70 requires status58 bits16..21 == 0x11 after programming is released.
 * This optional readiness is synthetic, never a claim of silicon behavior. */
static bool nikon_z5_processing_init_access(NikonLabState *s, hwaddr addr,
        unsigned size, bool write, uint64_t *value)
{
    if ((addr < 0x2a900000 || addr >= 0x2a901000) &&
        addr != 0x2b200000 && addr != 0x2b200058 && addr != 0x2b20005c) { return false; }
    if (g_strcmp0(getenv("Z5_PROCESSING_INIT_STANDIN"), "1") || size != 4 || (addr & 3)) { return false; }
    if (addr == 0x2b200058 || addr == 0x2b20005c) {
        if (write) { return false; }
        *value = addr == 0x2b200058 && s->processing_init_ready &&
                 (s->processing_init_command & 4) ? 0x110000 : 0;
        nikon_mmio_trace(addr, size, write, *value);
        return true;
    }
    if (addr == 0x2b200000) {
        if (write && (*value & ~UINT64_C(0x11f))) { return false; }
        if (write) { s->processing_init_command = *value; }
        else { *value = s->processing_init_command; }
        nikon_mmio_trace(addr, size, write, *value);
        return true;
    }
    static const struct { unsigned off; uint32_t mask; } regs[] = {
        {0x004, 0x147}, {0x010, 0xfffffff0}, {0x014, 0xfffffff0},
        {0x018, 0xfffffff0}, {0x01c, 0xfffffff0}, {0x020, 0xfffffff0}, {0x024, 0xfffffff0},
        {0x050, 0x7f0000}, {0x078, 0xff4ff}, {0x07c, 0x3f000},
        {0x080, 0xc0000ff3}, {0x088, 0x11f1fff}, {0x08c, 0xf},
        {0x090, 0x10000}, {0x098, 0x41f}, {0x0a0, 0x20ffbf},
        {0x80c, 0x20000}, {0x8bc, 1}, {0x900, 1}, {0x904, 0xff8cf81f},
        {0x908, 0xd7260000}, {0x90c, UINT32_MAX}, {0x910, 0},
        {0x914, UINT32_MAX}, {0x918, UINT32_MAX}, {0x91c, 0}
    };
    unsigned off = addr - 0x2a900000;
    for (unsigned i = 0; i < ARRAY_SIZE(regs); i++) {
        if (off != regs[i].off) { continue; }
        uint32_t *reg = &s->processing_init_regs[off / 4];
        if (write) {
            if (*value & ~(uint64_t)regs[i].mask) { return false; }
            if (off == 0x8bc) {
                if (*value) { s->processing_init_ready = false; }
                else if (*reg == 1) {
                    s->processing_init_ready = true;
                    fprintf(stderr, "Z5_PROCESSING_INIT_STANDIN ready=1 synthetic_status=00110000 data_path_unmodeled=1\\n");
                }
            }
            *reg = *value;
        } else { *value = *reg; }
        nikon_mmio_trace(addr, size, write, *value);
        return true;
    }
    return false;
}

'''


def derive_windows(rows):
    # SDK 指针检查上限不是启动分配器上限。原厂 10231bb0/c8 使用
    # 10231c8c 的 C8500000 起点；10231bee 用 10231d04 的 CC400000 算余量。
    # Q2 原厂复制引擎请求：10000000 -> CC400000 长 300000；
    # 随后 10300000 -> CC700000 长 400000。
    intervals = [(0xC1800000, 0xC8700000), (0xC8500000, 0xCC400000),
                 (0xCC400000, 0xCCB00000),
                 # 102319d4 的软件分类表：指令 10231a62..7e、
                 # 10231ad4..b0e；80300000 另有原厂 DMA 请求证实。
                 (0x80100000, 0x80400000), (0xBF300000, 0xBFB00000),
                 (0xC0000000, 0xC1800000)]
    for row in rows:
        start = int(row['destination'], 16)
        end = start + row['size']
        if 0x04008000 <= start < end <= 0x04009000:
            continue  # boot SRAM 由机器单独建立。
        intervals.append((start, end))
    merged = []
    for start, end in sorted(intervals):
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return [(start, end - start) for start, end in merged]


def make_profile(windows):
    records = '\n'.join(f'    {{0x{base:x}, 0x{size:x}}},' for base, size in windows)
    return f'''/* SPDX-License-Identifier: GPL-2.0-or-later */
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
#define Z5_MAIN_SHA256 "{MAIN_SHA256}"
typedef struct NikonZ5Profile {{
    const char *cpu_type;
    uint32_t cbar, timer_hz, main_base, main_bytes;
    unsigned gic_version, serial_fifo_depth;
    NikonRawGeometry raw;
    NikonFunctionalTiming timing;
}} NikonZ5Profile;
static const NikonZ5Profile nikon_z5_profile = {{
    .cpu_type = "cortex-a15-arm-cpu", .cbar = 0x2c000000,
    .timer_hz = 48000000, .main_base = 0x10020000, .main_bytes = 34603578,
    .gic_version = 1, .serial_fifo_depth = 16,
    /* Donor ISP geometry is provisional; not Z5 sensor dimensions. */
    .raw = {{2034, 1434, 4080, 64, 4095}},
    .timing = {{100000, 100000, 1000000, 1000000, 33333333, 16666667}},
}};
typedef struct NikonRAMWindow {{ uint32_t base, size; }} NikonRAMWindow;
static const NikonRAMWindow nikon_z5_ram_windows[] = {{
{records}
}};
#endif
'''


Z5_INGRESS_BYTES = 2272 * 1006

# Z5 RAW engine 0x200 configuration observed from guest writes
# (output/qemu-sensor-cal-20261107-codex-02/qemu.log): 20069514=6,
# 20069518=05E40000, 2006951C=03EE0000, 20069A08=8E0, 20069A50=82B00000.
# 1508x1006 with stride 2272 fits packed 12-bit rows aligned to 32 bytes, as the
# donor 1380x918/2080 does. The packing itself remains an emulator hypothesis.
Z5_INGRESS_EDITS = (
    ('''        s->capture_processing[0x1514 / 4] != 6 ||
        s->capture_processing[0x1518 / 4] != 0x05640000 ||
        s->capture_processing[0x151c / 4] != 0x03960000 ||
        s->capture_processing[0x1a08 / 4] != 2080) { return; }''',
     '''        s->capture_processing[0x1514 / 4] != 6 ||
        s->capture_processing[0x1518 / 4] != 0x05e40000 ||
        s->capture_processing[0x151c / 4] != 0x03ee0000 ||
        s->capture_processing[0x1a08 / 4] != 2272) { return; }'''),
    ('    if (destination < 0x44c00000 || (uint64_t)destination + s->capture_ingress_length > 0x4fbd2400) { return; }',
     '''    /* Z5 C1.50 submits 82B00000, the start of scatter RAM window
     * 82B00000..8A5E1C00. The donor 44C00000 pool does not exist here. */
    if (destination < 0x82b00000 || (uint64_t)destination + s->capture_ingress_length > 0x8a5e1c00) { return; }'''),
    ('info.st_size != 1909440', f'info.st_size != {Z5_INGRESS_BYTES}'),
    ('s->capture_ingress_length != 1909440', f's->capture_ingress_length != {Z5_INGRESS_BYTES}'),
    ('needs periodic test and a 1909440-byte input', f'needs periodic test and a {Z5_INGRESS_BYTES}-byte input'),
    ('Z5_RAW_INGRESS_TEST_SOURCE width=1380 height=918 stride=2080',
     'Z5_RAW_INGRESS_TEST_SOURCE width=1508 height=1006 stride=2272'),
    ('''static void nikon_capture_ingress_test(NikonLabState *s)
{
''', '''static void nikon_capture_ingress_test(NikonLabState *s)
{
    {
        /* Z5 research log: print each new RAW engine configuration once, so
         * native geometry is read from guest writes rather than assumed. */
        static uint32_t last[13];
        static unsigned reports;
        const uint32_t now[13] = {
            s->capture_isp_gate[0], s->capture_isp_gate[1], s->capture_isp_gate[2],
            s->capture_processing[0x1514 / 4], s->capture_processing[0x1518 / 4],
            s->capture_processing[0x151c / 4], s->capture_processing[0x1a08 / 4],
            s->capture_processing[0x1a50 / 4], s->capture_processing[0x1500 / 4],
            s->capture_processing[0x1504 / 4], s->capture_processing[0x1508 / 4],
            s->capture_processing[0x1808 / 4], s->capture_processing[0x1850 / 4] };
        if (memcmp(now, last, sizeof(now)) && reports < 64) {
            reports++;
            memcpy(last, now, sizeof(now));
            fprintf(stderr, "Z5_RAW_ENGINE_CONFIG gate=%x/%x/%x e200=%x/%x/%x/%u/%08x "
                    "e400=%x/%x/%x/%u/%08x\\n", now[0], now[1], now[2], now[3], now[4],
                    now[5], now[6], now[7], now[8], now[9], now[10], now[11], now[12]);
        }
    }
'''),
)


# Opt-in Z5_LV_ENGINE1_EVENTS=1 (route experiment, default off). After the
# first engine-0x200 frame, C1.50 stops it and enables engines 0x1d
# (observed gate=0/1d/1d, output/qemu-sensor-20261107-222154); the donor model
# only continues events for engine 0x400, so the firmware then waits forever.
# Re-arm the inherited ISP boundary cycle while engine 1 runs. No pixels are
# moved and no engine-1 completion semantics are claimed.
Z5_LV_ENGINE1_EDITS = (
    ('    uint32_t capture_processing[0x2000 / 4];',
     '    uint32_t capture_processing[0x2000 / 4];\n'
     '    unsigned z5_ingress_total, z5_engine1_rearms;\n'
     '    bool z5_lv_engine1_events;'),
    ('        s->image_process_test = g_strcmp0(getenv("Z5_IMAGE_PROCESS_TEST"), "1") == 0;',
     '        s->image_process_test = g_strcmp0(getenv("Z5_IMAGE_PROCESS_TEST"), "1") == 0;\n'
     '        s->z5_lv_engine1_events = g_strcmp0(getenv("Z5_LV_ENGINE1_EVENTS"), "1") == 0;'),
    ('''    s->capture_ingress_done = true;
    g_autofree char *hash = g_compute_checksum_for_data(G_CHECKSUM_SHA256, check, s->capture_ingress_length);''',
     '''    s->capture_ingress_done = true;
    s->z5_ingress_total++;
    g_autofree char *hash = g_compute_checksum_for_data(G_CHECKSUM_SHA256, check, s->capture_ingress_length);'''),
    ('    if (s->capture_isp_boundary_test && s->capture_ingress_done) {',
     '''    if (s->z5_lv_engine1_events && s->z5_ingress_total && !s->capture_ingress_done &&
        !(s->capture_isp_gate[0] & 1) && (s->capture_isp_gate[1] & 1) && (s->capture_isp_gate[2] & 1)) {
        s->capture_ingress_done = true;
        fprintf(stderr, "Z5_LV_ENGINE1_EVENTS rearm=%u gate=%x/%x/%x pixels_moved=0 diagnostic_only=1\\n",
                ++s->z5_engine1_rearms, s->capture_isp_gate[0], s->capture_isp_gate[1], s->capture_isp_gate[2]);
    }
    if (s->capture_isp_boundary_test && s->capture_ingress_done) {'''),
    # C1.50 100B9D10/100B9D6E map bank4 bit8 -> PREPRO 0x4000 and bank3 bit31
    # -> PREPRO 0x2000; both run 100B8FD0, which dequeues four buffers from the
    # FRNTELB1 ring C2664B2C (100B8F76). After the engine switch nothing refills
    # that ring, so never signal these two completions for a re-armed cycle.
    ('''        s->capture_isp_irq_status[3] |= bank3;
        s->capture_isp_irq_status[4] |= bank4;''',
     '''        if (s->z5_engine1_rearms) {
            bank3 &= ~0x80000000u;
            bank4 &= ~0x100u;
        }
        s->capture_isp_irq_status[3] |= bank3;
        s->capture_isp_irq_status[4] |= bank4;'''),
)


# Opt-in Z5_LV_BACKGROUND=<720x480 RGB24 file>: a UI reference layer, not live
# view. The firmware's processed-image plane stays empty (uniform) until a real
# RAW/ISP path exists, so when the scanned-out base YUV plane is uniform the
# host substitutes the supplied picture, then composites the native GUI and AF
# overlays on top exactly as before. Non-uniform base planes (playback etc.)
# are never replaced.
Z5_LV_BACKGROUND_EDITS = (
    ('    bool z5_lv_engine1_events;',
     '    bool z5_lv_engine1_events;\n'
     '    uint8_t *z5_lv_background;\n'
     '    unsigned z5_lv_background_frames;'),
    ('        s->lcd_scanout_test = g_strcmp0(getenv("Z5_LCD_SCANOUT_TEST"), "1") == 0;',
     '''        s->lcd_scanout_test = g_strcmp0(getenv("Z5_LCD_SCANOUT_TEST"), "1") == 0;
        const char *lv_background = getenv("Z5_LV_BACKGROUND");
        if (lv_background) {
            GError *error = NULL;
            gchar *data = NULL;
            gsize length = 0;
            if (!s->lcd_scanout_test ||
                !g_file_get_contents(lv_background, &data, &length, &error) || length != 720 * 480 * 3) {
                error_report("Z5_LV_BACKGROUND needs LCD scanout and a 720x480 RGB24 file: %s",
                             error ? error->message : "size/configuration");
                exit(2);
            }
            s->z5_lv_background = (uint8_t *)data;
            g_autofree char *hash = g_compute_checksum_for_data(G_CHECKSUM_SHA256, (guchar *)data, length);
            fprintf(stderr, "Z5_LV_BACKGROUND_SOURCE width=720 height=480 format=RGB24 sha256=%s "
                    "firmware_pipeline=0 composited_by_host=1\\n", hash);
        }'''),
    ('static void nikon_lcd_present(void *opaque)\n{',
     '''/* Z5 UI-reference helper: count GUI overlay pixels that are at least half
 * opaque. Full-screen menus cover most of the panel; the shooting screen only
 * draws icons. Reads the same validated regions as nikon_lcd_overlay. */
static size_t z5_lcd_overlay_coverage(uint32_t *r, unsigned w, unsigned h)
{
    const unsigned base = 0x2000;
    uint32_t format = r[(base+0x200)/4];
    if (!(r[(base+0x110)/4] & 1) || (format != 0x30006 && format != 0x30016)) { return 0; }
    unsigned bank = (r[(base+0x214)/4] >> 8) & 3;
    uint32_t color_base = r[(base+0x440)/4+bank];
    size_t covered = 0;
    for (unsigned region=0; region<10; region++) {
        if (!(r[(base+0x5c0)/4] & (1U<<region))) { continue; }
        uint32_t size = r[(base+0x400)/4+region], xy = r[(base+0x580)/4+region];
        unsigned rw=size&0xffff, rh=(size>>16)&0x3fff, x0=xy&0xffff, y0=(xy>>16)&0x3fff;
        unsigned cs=r[(base+0x500)/4+region], as=r[(base+0x540)/4+region];
        uint64_t ca=region ? r[(base+0x47c)/4+region] : color_base;
        uint32_t aa=r[(base+0x4c0)/4+region];
        if (!rw || !rh || x0>=w || y0>=h || rw>4096 || rh>4096 ||
            cs<((rw+1)&~1U)*2 || as<rw || ca>UINT32_MAX ||
            !nikon_gpu_range(ca,(uint64_t)cs*rh,false) ||
            !nikon_gpu_range(aa,(uint64_t)as*rh,false)) { continue; }
        g_autofree uint8_t *cp=g_malloc(cs), *ap=g_malloc(as);
        for (unsigned y=0; y<MIN(rh,h-y0); y++) {
            cpu_physical_memory_read(ca+(uint64_t)y*cs,cp,cs);
            cpu_physical_memory_read(aa+(uint64_t)y*as,ap,as);
            for (unsigned x=0; x<MIN(rw,w-x0); x++) {
                uint8_t top[4];
                nikon_gpu_pixel_read(cp,ap,0x107,false,x,top);
                covered += top[3] >= 128;
            }
        }
    }
    return covered;
}

static void nikon_lcd_present(void *opaque)
{'''),
    ('''    unsigned overlay=nikon_lcd_overlay(r,0,out,surface_stride(surface),w,h);''',
     '''    if (s->z5_lv_background && z5_native_lcd) {
        bool uniform = true;
        for (size_t i = 1; i < (size_t)ys * h && uniform; i++) { uniform = yp[i] == yp[0]; }
        for (size_t i = 2; i < (size_t)us * uvh && uniform; i++) { uniform = up[i] == up[i & 1]; }
        /* Never show the reference picture behind full-screen GUI (menus). */
        if (uniform && z5_lcd_overlay_coverage(r, w, h) * 2 < (size_t)w * h) {
            for (unsigned y = 0; y < h; y++) {
                const uint8_t *src = s->z5_lv_background + (size_t)y * w * 3;
                for (unsigned x = 0; x < w; x++) {
                    stl_p(out + y * surface_stride(surface) + x * 4,
                          (src[x * 3] << 16) | (src[x * 3 + 1] << 8) | src[x * 3 + 2]);
                }
            }
            if (!(s->z5_lv_background_frames++ % 30)) {
                fprintf(stderr, "Z5_LV_BACKGROUND_COMPOSITE frame=%u base=uniform firmware_pipeline=0\\n",
                        s->z5_lv_background_frames);
            }
        }
    }
    unsigned overlay=nikon_lcd_overlay(r,0,out,surface_stride(surface),w,h);'''),
)


# Patched MAIN (our own firmware builds): the probe first rebuilds the image
# from the stock MAIN plus the patch report (every edit's original bytes,
# every append, nothing else changed) and only then exports the verified hash
# as Z5_ALLOWED_MAIN_SHA256. The model accepts exactly that hash, within the
# mapped ROM capacity; anything else still stops as before.
Z5_PATCHED_MAIN_EDITS = (
    ('''        if (length != s->model->main_bytes) {
            error_report("Expected extracted Z5 C1.50 MAIN (34603578 bytes)");
            exit(1);
        }
        g_autofree gchar *digest = g_compute_checksum_for_data(
            G_CHECKSUM_SHA256, (const guchar *) data, length);
        if (g_strcmp0(digest, Z5_MAIN_SHA256) != 0) {
            error_report("Z5 C1.50 MAIN SHA-256 mismatch");
            exit(1);
        }''',
     '''        g_autofree gchar *digest = g_compute_checksum_for_data(
            G_CHECKSUM_SHA256, (const guchar *) data, length);
        const char *allowed = getenv("Z5_ALLOWED_MAIN_SHA256");
        bool stock = length == s->model->main_bytes && g_strcmp0(digest, Z5_MAIN_SHA256) == 0;
        bool patched = allowed && g_strcmp0(digest, allowed) == 0 &&
                       length >= s->model->main_bytes && length <= 0x02101000;
        if (!stock && !patched) {
            error_report("Z5 C1.50 MAIN SHA-256 mismatch (patched images need a verified report)");
            exit(1);
        }
        if (patched) {
            fprintf(stderr, "Z5_PATCHED_MAIN bytes=%zu sha256=%s report_verified_by_probe=1\\n",
                    (size_t)length, digest);
        }'''),
)


def transform_z5_ingress(result):
    for old, new in Z5_INGRESS_EDITS + Z5_LV_ENGINE1_EDITS + Z5_LV_BACKGROUND_EDITS + Z5_PATCHED_MAIN_EDITS:
        if result.count(old) != 1:
            raise ValueError('donor RAW ingress anchor changed: ' + old.splitlines()[0])
        result = result.replace(old, new, 1)
    return result


def transform_board(original):
    if hashlib.sha256(original.encode('utf-8')).hexdigest() != BOARD_SHA256:
        raise ValueError('donor board is not the pinned source; abort')
    result = original.replace('z6', 'z5').replace('Z6', 'Z5').replace('C3.80', 'C1.50')
    lcd_anchor = '''    unsigned uvh = nv12 ? h/2 : h;
    if (!(r[0x1200/4] & 1) || !(r[0x110/4] & 1) || (r[0x200/4] != 0x300000 && !nv12) ||
        w != 1024 || (h != 682 && h != 680) || ys != w || us != w ||'''
    if result.count(lcd_anchor) != 1:
        raise ValueError('donor LCD acceptance anchor changed')
    result = result.replace(lcd_anchor, '''    /* C1.50 10284f36 writes native720x480/300100. Captured GPU105
     * targets the identical Y base, with UV at Y+720*480 and stride720:
     * full-height interleaved UV. Bit8 color processing is not bit-accurate;
     * retain the inherited functional BT.601 conversion and native overlays. */
    bool z5_native_lcd = s->z5_profile && w == 720 && h == 480 && r[0x200/4] == 0x300100;
    bool legacy_lcd = w == 1024 && (h == 682 || h == 680) &&
                      (r[0x200/4] == 0x300000 || nv12);
    unsigned uvh = nv12 ? h/2 : h;
    if (!(r[0x1200/4] & 1) || !(r[0x110/4] & 1) || !(z5_native_lcd || legacy_lcd) ||
        ys != w || us != w ||''', 1)
    overlay_anchor = '    if (!(r[(base+0x110)/4] & 1) || r[(base+0x200)/4] != 0x30006) { return 0; }'
    if result.count(overlay_anchor) != 1:
        raise ValueError('donor overlay format anchor changed')
    result = result.replace(overlay_anchor, '''    /* C1.50 102862b8 selects30016; GPU107 writes the same color and
     * alpha bases, with strides2*w/w. Bit4 processing remains functional,
     * not bit-accurate; never substitute the separate RGBA GUI probe. */
    uint32_t format = r[(base+0x200)/4];
    if (!(r[(base+0x110)/4] & 1) || (format != 0x30006 && format != 0x30016)) { return 0; }''', 1)
    result = result.replace('    MemoryRegion main_rom;',
        '    MemoryRegion main_rom;\n    uint32_t processing_init_regs[0x1000 / 4];\n'
        '    uint32_t processing_init_command;\n    bool processing_init_ready;', 1)
    result = result.replace('static uint64_t nikon_unknown_read(',
                           PROCESSING_INIT_CODE + 'static uint64_t nikon_unknown_read(', 1)
    result = result.replace('    uint64_t fill_value = 0;',
        '    uint64_t fill_value = 0;\n'
        '    if (nikon_z5_processing_init_access(s, addr, size, false, &fill_value)) { return fill_value; }', 1)
    write_anchor = '    if (nikon_exmcu_access(s, addr, size, true, &value)) { return; }'
    if result.count(write_anchor) != 1:
        raise ValueError('donor write dispatch changed')
    result = result.replace(write_anchor,
        '    if (nikon_z5_processing_init_access(s, addr, size, true, &value)) { return; }\n' + write_anchor, 1)
    result = result.replace('33502842', str(MAIN_SIZE))
    needle = '0x02000000, &error_fatal);'
    if result.count(needle) != 1:
        raise ValueError('donor ROM capacity anchor changed')
    result = result.replace(needle, '0x02101000, &error_fatal);')
    result = result.replace('0x12020000', '0x12121000').replace('absent_flash_12020000', 'absent_flash_12121000')
    # 上游对当前机型的未知访问只记录后放行；Q1 必须进入下面的严格停止分支。
    start = result.index('    if (s->z5_profile && current_cpu) {', result.index('static void nikon_unknown_access'))
    end = result.index('    if (!current_cpu) {', start)
    result = result[:start] + result[end:]
    anchor = '        rom_add_blob_fixed("z5-main-payload", data, length, s->model->main_base);'
    if result.count(anchor) != 1:
        raise ValueError('donor payload anchor changed')
    guard = '''        g_autofree gchar *digest = g_compute_checksum_for_data(
            G_CHECKSUM_SHA256, (const guchar *) data, length);
        if (g_strcmp0(digest, Z5_MAIN_SHA256) != 0) {
            error_report("Z5 C1.50 MAIN SHA-256 mismatch");
            exit(1);
        }
'''
    result = result.replace(anchor, guard + anchor)
    config_anchor = '             off == 0x2648 || off == 0x2490 || off == 0x24a0 ||'
    if result.count(config_anchor) != 1:
        raise ValueError('donor platform configuration anchor changed')
    result = result.replace(config_anchor,
        '             (off >= 0x6d50 && off <= 0x6d5c) || /* Z5 startup 1002be1c..34: write latches */\n'
        '             off == 0x6000 || off == 0x6d40 || /* Z5 1002be40/4c, observed write 1 */\n'
        + config_anchor)
    gpio_anchor = '    bool config = off == 0x30 || off == 0x34 || off == 0x38 ||'
    reset_anchor = '        if (!s->setup_written[i] && off != 0x34 && off != 0x38 && !runtime_gate &&'
    if result.count(gpio_anchor) != 1 or result.count(reset_anchor) != 1:
        raise ValueError('donor GPIO configuration anchors changed')
    result = result.replace(gpio_anchor, gpio_anchor + ' off == 0x44 ||', 1)
    result = result.replace(reset_anchor,
        '        if (!s->setup_written[i] && off != 0x34 && off != 0x38 && off != 0x44 && !runtime_gate &&', 1)
    config_start = '    static const struct { hwaddr addr; uint32_t mask; bool write_only; unsigned width; } regs[] = {'
    if result.count(config_start) != 1:
        raise ValueError('donor recovery configuration table changed')
    result = result.replace(config_start, config_start + '''
        /* Z5 102ffad0/102ffc1a/102ffcc6: config fields at +0..+10.
         * Z5 102ffd54: +24 preserves two gate bits; +28/+2c pack flags.
         * Zero reset is provisional. No data/interrupt completion is implied. */
        /* 102e0a60 also reads +0 back; retain the submitted control bits. */
        { 0x2b200000, 0x11f }, { 0x2b200004, 0x111 },
        { 0x2b200008, 0x1101 },
        { 0x2b20000c, 0x31111033 }, { 0x2b200010, 0x10111 },
        /* Z5 102ffce2 write-only flag submissions; no completion inferred. */
        { 0x2b200014, 0x31111013, true }, { 0x2b200018, 0x111, true },
        { 0x2b200024, 0x10001 },
        { 0x2b200028, 0xbbbbbbbb, true }, { 0x2b20002c, 0xbbbbbbbb, true },''', 1)
    config_end = '        { 0x2b200028, 0xbbbbbbbb, true }, { 0x2b20002c, 0xbbbbbbbb, true },'
    result = result.replace(config_end, config_end + '''
        /* Z5 10300182/1030020c: matching configuration setters/getters. */
        { 0x2b20003c, 0x70010011 }, { 0x2b20004c, 0x10001 },
        { 0x2b200050, 0x11111111 }, { 0x2b200054, 0x10001 },
        /* Z5 102e0942: +100 bit8 and +300 bit0 RMW gates. */
        { 0x2b200100, 0x100 }, { 0x2b200300, 1 },
        /* Z5 101a78e6/101a7948..99c: observed gates plus packed fields.
         * No command completion is synthesized. */
        { 0x2c012000, 0x57ff },
        /* Z5 101a796a/101a79d4: low byte and bits10..12 configuration. */
        { 0x2c012008, 0x1cff },''', 1)
    start = result.index('        /* Z5 scatter records10034040')
    end = result.index('        const NikonRAMWindow *z5_regions', start)
    result = result[:start] + '''        /* Z5 windows: checked C1.50 scatter plus software RAM validity.
         * Donor peripheral behavior elsewhere is provisional, not Z5 proof. */
''' + result[end:]
    start = result.index('        fprintf(stderr, "Z5_RAM_PROFILE scatter=')
    end = result.index('\n    }', start)
    result = result[:start] + '''        fprintf(stderr, "Z5_RAM_PROFILE scatter=10034000..10034120 "
                "runtime_window=c0000000..cd8a0000 physical_capacity_verified=0\\n");''' + result[end:]
    result = transform_z5_ingress(result)
    return '''/* Z5 Q1/Q2 port from WonderLantern/z6-qemu 419a1f2.
 * All inherited instruction references in comments remain Z6 research leads,
 * including mechanically renamed comments. No Z5 peripheral equivalence proven.
 * Unknown guest accesses stop; no host-injected RAM or function calls in Q1.
 */
''' + result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--main', required=True, type=Path)
    parser.add_argument('--target', type=Path, default=ROOT / 'reference/z5-qemu')
    parser.add_argument('--replace-generated', action='store_true',
                        help='replace generated files that still match the last build manifest')
    args = parser.parse_args()
    target = args.target.resolve()
    if target != (ROOT / 'reference/z5-qemu').resolve():
        parser.error('target must be shared reference/z5-qemu')
    revision = subprocess.check_output(['git', '-C', str(target), 'rev-parse', 'HEAD'], text=True).strip()
    if revision != DONOR_COMMIT:
        parser.error('target is not the pinned donor revision')
    data = args.main.read_bytes()
    check_identity(data, MAIN_SIZE, MAIN_SHA256)
    rows = read_scatter(data, BASE, SCATTER_START, SCATTER_END, COPY, ZERO)
    source = ROOT / 'reference/z6-qemu'
    board = (source / 'qemu/nikon-z6.c').read_text(encoding='utf-8')
    prepare = (source / 'qemu/prepare_source.py').read_text(encoding='utf-8')
    prepare = prepare.replace('z6', 'z5').replace('Z6', 'Z5')
    build = (source / 'tools/build.py').read_text(encoding='utf-8')
    build = build.replace('nikon-z6', 'nikon-z5').replace('qemu/prepare_source.py', 'qemu/prepare_z5_source.py')
    generated = {
        'qemu/nikon-z5.c': transform_board(board),
        'qemu/nikon-z5-profile.h': make_profile(derive_windows(rows)),
        'qemu/prepare_z5_source.py': prepare,
        'tools/build_z5.py': build,
    }
    built = {}
    if args.replace_generated:
        import json
        built = json.loads((target / '.local/build-manifest.json').read_text(encoding='utf-8'))['sources']
    pending = {}
    for name, text in generated.items():
        path = target / name
        if not path.exists():
            pending[name] = 'x'
            continue
        current = path.read_bytes()
        if current == text.encode('utf-8'):
            continue
        # Only replace an earlier generated file that is exactly what was built;
        # anything edited by hand since the last build is refused.
        if not args.replace_generated or hashlib.sha256(current).hexdigest() != built.get(name):
            parser.error(f'refusing to overwrite {name}')
        pending[name] = 'w'
    for name, mode in pending.items():
        with (target / name).open(mode, encoding='utf-8', newline='\n') as stream:
            stream.write(generated[name])
        print(('Created ' if mode == 'x' else 'Replaced ') + name)
    if not pending:
        print('Generated sources already current')


if __name__ == '__main__':
    main()
