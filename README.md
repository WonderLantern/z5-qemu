# Nikon Z5 C 1.50 QEMU 研究模拟器

这是针对 **Nikon Z5、C 固件 1.50** 的实验性 QEMU 机器模型，用于观察原厂 GUI、菜单和按键。它并非完整相机模拟器，也不是尼康官方项目；本项目模拟器结论均为 `camera_verified: false`。

## 已实现与限制

- 在显式辅助启动条件下，原厂界面可绘制到虚拟 LCD，基础菜单导航与 MY MENU 有模拟器截图证据；启动时使用处理单元、环境、应用就绪、传感器错误及无卡状态的替身。
- 提供本机浏览器交互界面和按键；`--keep-awake` 仅对本次模拟会话设置不自动待机。DISP 经原厂开关提交接口可翻页（0→1→2→3），i 面板、方向键、OK 可用，半按可返回拍摄画面；拍摄界面需显式 `--shooting-ui-standin`。拨轮和 Fn 快捷键尚不能触发原厂动作；没有 SD 卡模型（只有宿主文件替身）。
- 启动基线（M0）已收口：同一按键序列连续 3 次冷启动结果一致，替身有清单；`native_idle_verified=false` 作为已知限制保留。传感器控制面（M1）未完成。各项进度见 [PROGRESS.md](PROGRESS.md)。
- 主机可将参考底图与原厂 GUI 合成，适合观察布局；**这是宿主合成的底图，不是固件 RAW → ISP 取景输出**（`firmware_pipeline=0`）。
- Z5 RAW 首次输入写入已有模拟器观察，但后续捕获作业、图像处理和扫描显示尚未打通；传感器协议、像素格式和硬件时序未经实机验证。
- 支持对照报告核验自建补丁主模块再加载；本仓库不包含固件补丁或菜单、自启动、快门音研究。水平仪与直方图同屏尚未验证。

## 获取用户自备固件

本仓库不包含尼康固件、解密或补丁镜像、存储卡内容、运行转储、RAW、图像或构建产物。不得将这些文件提交到公开仓库。使用者须自行合法取得 Z5 C 1.50 官方更新包。

在独立位置检出 [z5mod](https://github.com/youyli03/z5mod) 并使用其固件工具（该项目是外部依赖，不包含于此）：

```bash
git clone https://github.com/youyli03/z5mod.git /path/to/z5mod
python3 /path/to/z5mod/firmware/patch.py verify /path/to/Z_5_0150.bin
python3 /path/to/z5mod/firmware/patch.py extract /path/to/Z_5_0150.bin --out /private/path/eg1650_015001.bi
sha256sum /private/path/eg1650_015001.bi
```

原厂包 SHA-256：`efc0ce70dcafdd96c64e95d8d50f6b7f0509fc0c2840b28d12b6f9e4877ee776`；提取的主模块长度 34,603,578 字节，SHA-256：`1d9742a951ea8a8ebe695fa9bb1f29a3be73e16dfe4a8372d997e903bbc58e98`。探针会核验主模块，不支持其他型号或版本。

## 构建与运行

在 Linux 或选择的 WSL 发行版中使用 Python 3.12+；例如 Debian/Ubuntu 所需系统依赖：

```bash
sudo apt-get install build-essential ninja-build pkg-config python3-venv libglib2.0-dev libpixman-1-dev zlib1g-dev libfdt-dev
python3 -B reference/z5-qemu/tools/build_z5.py --work-dir /var/tmp/z5-qemu-build --jobs 1
```

构建脚本下载 QEMU 10.2.4 并验证 SHA-256；若已有官方源码包可加 `--archive /path/to/qemu-10.2.4.tar.xz`。编译清单写入 `reference/z5-qemu/.local/`，每次运行会核验源码和二进制哈希。此仓库已包含 Z5 生成源码，构建无需额外下载 Z6 仓库。

从仓库根目录运行，将路径替换为自己的提取文件与结果目录：

```bash
export Z5_QEMU_OUTPUT=/private/path/z5-qemu-results
python3 -B research/qemu/launcher.py --main /private/path/eg1650_015001.bi \
  --out "$Z5_QEMU_OUTPUT/run-01" --port 8765
```

打开 `http://127.0.0.1:8765`。启动器生成色条参考底图，并启用上述替身、关闭本会话待机。每次 `--out` 都须是结果根目录下不存在的新目录；不设置 `Z5_QEMU_OUTPUT` 时默认为仓库的 `output/`。若已有 720×480 RGB24 参考图，可使用 `--background` 指定结果根目录内文件。也可直接使用 `research/qemu/boot_probe.py --help` 查看诊断选项，包括记录按键和只读采集客体内存；结果包含敏感或固件派生内容，不能上传。

```bash
python3 -B -m unittest discover -s research/qemu -p 'test_*.py'
```

离线测试缺少个人固件时会跳过相关检查。开发期使用的 `port_source.py` 可由 Z6 固定修订重新生成 Z5 源码；该开发流程需要对应的独立 Git 检出及用户自备固件，普通构建不需要。

## 参考项目与致谢

- [WonderLantern/z6-qemu](https://github.com/WonderLantern/z6-qemu)，修订 [`419a1f2`](https://github.com/WonderLantern/z6-qemu/tree/419a1f2a91a1f2d3a0209027c29606475f7fe26f)：Z5 模型、功能图形代码和调试工具的直接供体。本仓库保留构建、测试需要的相关源码快照。
- [WonderLantern/z7-qemu](https://github.com/WonderLantern/z7-qemu)：Z6 的上游，感谢作者 [R3tr0ooo](https://github.com/R3tr0ooo) 和贡献者提供尼康机器、图形管线及研究工具。
- [WonderLantern/z30-qemu](https://github.com/WonderLantern/z30-qemu)：只作为阅读参考，本仓库不复制其代码或文字。
- [QEMU](https://www.qemu.org/)：系统模拟平台，使用官方 QEMU 10.2.4 源码构建。
- [youyli03/z5mod](https://github.com/youyli03/z5mod)：Z5 扩展与固件工具参考；固件提取工具需另行取得。

Z5 适配和工具研究来自 `z5mod-plus/research/qemu`。本仓库叠加层和工具采用 **GPL-2.0-or-later**，除文件另有声明外；参见 [COPYING](COPYING)、[来源声明](UPSTREAM-NOTICE.md) 与 [QEMU 许可](LICENSES/QEMU-LICENSE.txt)。QEMU 保留各文件原有许可；许可不适用于尼康固件。项目与尼康无关联。
