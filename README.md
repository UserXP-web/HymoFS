# HymoFS

HymoFS 是一个面向 Android GKI / Linux 内核的路径控制 LKM（`hymofs_lkm.ko`），用于 root/SU 场景下的重定向、隐藏、合并和伪装能力。

当前仓库是 **LKM 形态**，不是“给内核源码打补丁”的 in-tree 版本。

## 当前状态

- 代码主体在 `src/`，模块名为 `hymofs_lkm.ko`
- 控制面为“匿名 fd + ioctl”，协议定义在 `src/hymo_magic.h`
- 已接入 DDK / CI，按多 KMI 自动构建
- 默认启用 ftrace 尝试，失败自动回退 kprobe
- 针对 6.6+ 的 `arch_ftrace_get_regs` 差异已做兼容处理

## 主要能力

- 路径重定向：`src -> target`
- 路径反查：`d_path` 场景下反向映射
- 目录隐藏：过滤 `iterate_dir` 返回项
- 目录合并/注入：用于 overlay 类场景
- `kstat` 伪装：inode/dev/size/time 等
- `xattr` 过滤/伪装（含 SELinux context 相关路径）
- `uname` 伪装
- `/proc/cmdline` 伪装
- `/proc/*/maps` 规则伪装（ino/dev/pathname）
- mount hide / statfs spoof 等可选特性

> 注意：这些能力会拦截 VFS 与系统调用热点路径，请仅在可控环境使用。

## Hook 架构概览

- GET_FD 路径：tracepoint 优先，回退到 kprobe/kretprobe
- VFS 路径：ftrace（entry）+ kretprobe（ret）优先，失败回退 kprobe
- 符号解析：优先通过 `kallsyms_lookup_name`，否则按符号逐个 kprobe 解析
- 高版本兼容：6.6+ 对 `arch_ftrace_get_regs` 的头文件差异已处理

## 兼容内核（CI 覆盖）

当前 workflow 会构建以下 KMI 目标：

- `android12-5.10`
- `android13-5.10`
- `android13-5.15`
- `android14-5.15`
- `android14-6.1`
- `android15-6.6`
- `android16-6.12`

对应文件见 `.github/workflows/build-lkm.yml` 和 `.github/workflows/ddk-lkm.yml`。

## 构建

### 1) 使用 ddk（推荐）

仓库根目录已有 `.ddk-version`，可直接：

```bash
ddk build
```

或指定目标：

```bash
ddk build android14-6.1
ddk build android15-6.6
```

### 2) 使用内核源码树本地编译

先准备目标内核的 `modules_prepare`，再编译模块：

```bash
make -C /path/to/kernel ARCH=arm64 M=$(pwd)/src modules
```

仓库根目录 `Makefile` 会把 `M` 指向 `src/`；也可以直接进 `src/` 使用其 Makefile。

## 加载与基础参数

加载示例：

```bash
insmod hymofs_lkm.ko
```

常用模块参数（调试用）：

- `hymo_syscall_nr`：GET_FD 的 syscall 编号参数（默认 142 路径兼容）
- `hymo_no_tracepoint=1`：强制跳过 tracepoint，使用 kprobe
- `hymo_skip_vfs=1`：跳过 VFS hooks（排障）
- `hymo_skip_extra_kprobes=1`：跳过额外 kprobes（排障）
- `hymo_skip_getfd=1`：跳过 GET_FD hooks（排障）
- `hymo_skip_kallsyms=1`：跳过 kallsyms 路径，强制逐符号 kprobe
- `hymo_dummy_mode=1`：最小化加载流程（排障）

参数定义在 `src/hymofs_core.c`，实际可用项请以当前源码为准。

## 用户态控制面（fd + ioctl）

1. 用户态先通过 GET_FD 通路获取匿名 fd（仅 root 可获取）。
2. 对该 fd 发送 `ioctl` 管理规则与开关。

协议定义：

- `src/hymo_magic.h`
- `HYMO_PROTOCOL_VERSION` 当前为 `14`

常用 ioctl（示例）：

- `HYMO_IOC_ADD_RULE` / `HYMO_IOC_DEL_RULE`
- `HYMO_IOC_HIDE_RULE`
- `HYMO_IOC_ADD_MERGE_RULE`
- `HYMO_IOC_CLEAR_ALL`
- `HYMO_IOC_SET_ENABLED`
- `HYMO_IOC_GET_FEATURES`
- `HYMO_IOC_GET_HOOKS`
- `HYMO_IOC_ADD_SPOOF_KSTAT`
- `HYMO_IOC_SET_UNAME`
- `HYMO_IOC_SET_CMDLINE`
- `HYMO_IOC_ADD_MAPS_RULE`
- `HYMO_IOC_SET_MOUNT_HIDE`
- `HYMO_IOC_SET_STATFS_SPOOF`

> 建议直接复用 [hymo](https://github.com/Anatdx/hymo) 的用户态实现，避免结构体版本不一致。

## 常见问题（Troubleshooting）

### 1) `arch_ftrace_get_regs` 重定义（6.1）

现象：

- `error: 'arch_ftrace_get_regs' macro redefined`

原因：

- 目标内核头文件已经定义该宏，模块又重复定义。

状态：

- 当前代码已按内核版本和头文件行为处理，6.1 不应再重复定义。

### 2) `arch_ftrace_get_regs` 未声明（6.6）

现象：

- `call to undeclared function 'arch_ftrace_get_regs'`

原因：

- 6.6 某些头文件路径里只调用不定义该宏。

状态：

- 当前代码已在 6.6+ 进行兼容兜底。

### 3) `Unknown symbol __tracepoint_sys_enter`

现象：

- 模块加载时报 `Unknown symbol __tracepoint_sys_enter (err -2)`。

原因：

- 目标内核未导出 tracepoint 相关符号。

处理：

- 使用 `hymo_no_tracepoint=1`，强制走 kprobe 路径。

### 4) 模块能编译但无法加载

优先检查：

- `vermagic` 是否匹配目标内核
- 是否开启了内核模块签名强校验
- `dmesg` 里具体报错（符号缺失、权限、签名）

## 仓库结构

- `src/`：LKM 代码与头文件
- `docs/`：设计与路线文档
- `scripts/`：自动化脚本
- `.github/workflows/`：多 KMI 构建与产物流程

## 开发建议

- 每次改 hook/ABI 后先跑最小加载验证（`insmod` + `dmesg`）
- 用 `HYMO_IOC_GET_HOOKS` / `HYMO_IOC_GET_FEATURES` 做运行态自检
- 多 KMI 变更要至少覆盖 `5.10 / 6.1 / 6.6` 三档验证
- 先保证 fallback（kprobe）可用，再调优 tracepoint/ftrace 路径

## 相关项目

- 用户态控制器：[hymo](https://github.com/Anatdx/hymo)
- 致谢与灵感来源：[susfs4ksu](https://gitlab.com/simonpunk/susfs4ksu)

## 许可证

- SPDX: `Apache-2.0 OR GPL-2.0`
- 非内核链接场景：Apache-2.0
- 以内核模块形式使用时：GPL-2.0 兼容约束适用

详见：

- `LICENSE`
- `LICENSE-GPL-2.0`
- `NOTICE`
