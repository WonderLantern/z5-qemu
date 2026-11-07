# Notice

The Z6 overlay and tools are adapted from [WonderLantern Z7 QEMU](https://github.com/WonderLantern/z7-qemu), authored by [R3tr0ooo](https://github.com/R3tr0ooo) and its contributors. We thank them for publishing the experimental Nikon machine, graphics pipeline and research tools that made this port possible. The Z6 board/profile, grid scanout and command-dial work are developed separately. Shared functional GPU/ISP implementations remain shared code, rather than an exact EXPEED hardware model.

Overlay, tools, tests and documentation: **GPL-2.0-or-later**, unless a file states otherwise. See COPYING. Upstream QEMU retains its own per-file licensing; see LICENSES/QEMU-LICENSE.txt. No license here applies to Nikon firmware or private camera material. Nikon is not affiliated with this independent project.

## Z5 adaptation

The Z5 machine overlay and supporting probes were adapted in the z5mod-plus research/qemu project from WonderLantern/z6-qemu revision 419a1f2a91a1f2d3a0209027c29606475f7fe26f. Z6 itself builds on WonderLantern/z7-qemu by R3tr0ooo and contributors. The included Z6 source snapshot remains under its original license and attribution. Z30 materials were consulted only; no Z30 code or text is included.
