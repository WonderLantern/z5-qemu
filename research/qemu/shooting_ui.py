# SPDX-License-Identifier: GPL-2.0-or-later
"""Explicit display-only readiness assistance; no capture/ISP completion claimed."""
import struct

UI_BUSY, UI_BUSY_SET = 0xC1828D48, 0x1036815C
ACTIVE_APP = 0xC18119A0       # 1007FB04: current GUI application, 3 = APPLV
DISPLAY_PAGE = 0xC20282B4 + 0x18e
UI_MODE = 0xC18289DC         # 103123F2: native shooting UI subpage
SETTING_READ, SETTING_WRITE = 0x10456098, 0x104560A4
# C1.50 i-panel gate reads the observed group-18 values; 1804 is also used
# by the quality renderer. Initial zeros are synthetic, not camera settings.
I_MENU_SETTINGS = (0x181d, 0x1803, 0x1804, 0x1835, 0x1807, 0x181c, 0x180e,
                   0x181f, 0x1805, 0x180a, 0x183d, 0x1808)

# C1.50 setting descriptors map 0501..0503 and 1803..1804 to these RAM cells.
QUALITY_SOURCE = 0xC252856C
QUALITY_MIRROR = 0xC25044D8


def enable_simplified_chinese(call, records):
    """Select a diagnostic Simplified Chinese session using C1.50 services."""
    before = call('language_setting_before', SETTING_READ, bytes(4), [0x1400])
    if not before or 'return_r0' not in before:
        raise RuntimeError('Simplified Chinese setting read before write failed')
    result = call('language_setting_zh_hans', SETTING_WRITE, bytes(4), [0x1400, 26])
    if not result or int(result.get('return_r0', '0'), 16) != 1:
        raise RuntimeError('Simplified Chinese setting write failed')
    call('language_select_zh_hans', 0x10525C70, bytes(4), [8])
    setting = call('language_setting_readback', SETTING_READ, bytes(4), [0x1400])
    selected = call('language_select_readback', 0x10525C88, bytes(4), [])
    if (not setting or not selected or int(setting['return_r0'], 16) != 26 or
            int(selected['return_r0'], 16) != 8):
        raise RuntimeError('Simplified Chinese selection readback failed')
    records.append(dict(setting=26, before=before['return_r0'], resource_index=8,
                        source='host diagnostic', camera_verified=False))


def quality_mirror_values(kind, compression, star):
    """Map the observed native quality components to the i-panel components."""
    if kind not in (0, 1, 3) or compression not in (0, 1, 2) or star not in (0, 1):
        return None
    return (compression if kind == 0 else 3 if kind == 1 else 5 + compression, star)


def sync_quality_mirror(remote, call, mirror, owned, records):
    """Synchronize only synthetic guest settings, yielding to native writers."""
    source = struct.unpack('<III', remote.memory(QUALITY_SOURCE, 12))
    current = struct.unpack('<II', remote.memory(QUALITY_MIRROR, 8))
    for key, value in zip((0x1803, 0x1804), current):
        if key in owned and value != mirror[key]:
            owned.remove(key)
            records.append(dict(setting=hex(key), event='native value changed; fixture ownership released',
                                value=hex(value), camera_verified=False))
    desired = quality_mirror_values(*source)
    if desired is None:
        return False
    changed = False
    for key, value in zip((0x1803, 0x1804), desired):
        if key not in owned or mirror[key] == value:
            continue
        result = call(f'i_quality_sync_{key:04x}', SETTING_WRITE, bytes(4), [key, value])
        if not result or int(result.get('return_r0', '0'), 16) != 1:
            raise RuntimeError(f'i-menu quality setting {key:#x} write failed')
        actual = struct.unpack('<II', remote.memory(QUALITY_MIRROR, 8))[key - 0x1803]
        if actual != value:
            raise RuntimeError(f'i-menu quality setting {key:#x} did not retain fixture')
        records.append(dict(setting=hex(key), before=hex(mirror[key]), after=hex(value),
                            source=[hex(v) for v in source], camera_verified=False))
        mirror[key] = value
        changed = True
    return changed


def ensure_i_menu_settings(remote, call, records):
    """Seed missing observed UI values once through the native setting service."""
    if remote.memory(ACTIVE_APP, 1)[0] != 3:
        raise ValueError('i-menu setting stand-in requires the shooting application')
    for key in I_MENU_SETTINGS:
        def read():
            result = call(f'i_menu_read_{key:04x}', SETTING_READ, bytes(4), [key])
            if not result or 'return_r0' not in result:
                raise RuntimeError(f'i-menu setting {key:#x} read failed')
            return int(result['return_r0'], 16)
        before = read()
        injected = before == 0xffffffff
        if injected:
            result = call(f'i_menu_seed_{key:04x}', SETTING_WRITE, bytes(4), [key, 0])
            if not result or int(result.get('return_r0', '0'), 16) != 1:
                raise RuntimeError(f'i-menu setting {key:#x} write failed')
            after = read()
            if after != 0:
                raise RuntimeError(f'i-menu setting {key:#x} did not retain fixture')
        else:
            after = before
        records.append(dict(setting=hex(key), before=hex(before), after=hex(after),
                            injected=injected, value_source='synthetic zero' if injected else 'native existing value',
                            camera_verified=False))


def snapshot(remote):
    return dict(application=remote.memory(ACTIVE_APP, 1)[0],
                busy=struct.unpack('<I', remote.memory(UI_BUSY, 4))[0],
                display_page=remote.memory(DISPLAY_PAGE, 1)[0],
                ui_mode=remote.memory(UI_MODE, 1)[0])


def ensure_ready(remote, call, records):
    """Stand in for the missing capture notification's UI unlock, APPLV only.

    102F3E26 sets busy=1; 102F22C0's notification 0x2E branch calls
    1036815C(0). Without that notification 10304108 drops DISP/i actions.
    This only unlocks native GUI actions; sensor and capture remain unmodeled.
    """
    if remote.memory(ACTIVE_APP, 1)[0] != 3:
        return
    before = struct.unpack('<I', remote.memory(UI_BUSY, 4))[0]
    if before == 0:
        return
    if before != 1:
        raise ValueError(f'unexpected shooting UI busy state: {before:#x}')
    call('shooting_ui_readiness_standin', UI_BUSY_SET, bytes(4), [0])
    after = struct.unpack('<I', remote.memory(UI_BUSY, 4))[0]
    if after != 0:
        raise RuntimeError('native shooting UI unlock did not take effect')
    records.append(dict(function=hex(UI_BUSY_SET), field=hex(UI_BUSY), before=before, after=after,
                        reason='missing capture notification 0x2E; UI-only readiness stand-in',
                        firmware_pipeline=False, camera_verified=False))
