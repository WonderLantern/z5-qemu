# SPDX-License-Identifier: GPL-2.0-or-later
"""Conservative visual barrier for interactive keys; not a native-idle proof."""


class InteractiveReadiness:
    def __init__(self, start_ms, minimum_ms=20000, maximum_ms=60000):
        if not 0 <= minimum_ms <= maximum_ms:
            raise ValueError('invalid guest-time limits')
        self.start_ms = start_ms
        self.minimum_ms = minimum_ms
        self.maximum_ms = maximum_ms
        self.previous = None

    def observe(self, current_ms, digest, nonuniform, ui, menu):
        elapsed = (current_ms - self.start_ms) & 0xffffffff
        if elapsed > self.maximum_ms:
            raise TimeoutError('interactive key exceeded guest observation limit')
        if not nonuniform or not isinstance(digest, str) or ui.get('application') is None:
            self.previous = None
            return False
        page = None
        if ui['application'] == 1:
            if not menu or menu.get('status') != 'ok':
                self.previous = None
                return False
            native_page = menu['page']
            page = (native_page['page_id'], native_page['row'])
        current = (digest, ui['application'], ui.get('display_page'), ui.get('ui_mode'), page)
        stable = self.previous == current
        self.previous = current
        return elapsed >= self.minimum_ms and stable
