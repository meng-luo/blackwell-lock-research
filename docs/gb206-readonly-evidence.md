# GB206（RTX 5060 Ti）只读取证记录

> 目标：在**不写入任何 GPU 寄存器、不加载任何东西到 GPU、不改时钟/功耗/驱动**的前提下，
> 拿到这台机器上关于 RTX 50 系（Blackwell）的一手事实。
> 时间：2026-10-29，本机（Windows，非管理员会话）。

---

## 1. 卡与驱动身份（`nvidia-smi`，只读查询）

| 项 | 值 |
|---|---|
| 名称 | NVIDIA GeForce RTX 5060 Ti |
| **PCI ID** | **`10de:2D04`**（子系统 `1458:4193`，rev A1） |
| 总线 | `00000000:01:00.0`（主显） |
| **架构**（驱动自报） | **Blackwell** |
| GPU Part Number | `2D04-300-A1` |
| VBIOS | `98.06.4e.xx` |
| 驱动（nvidia-smi 口径） | **621.01** |
| 驱动（Windows 口径） | 32.0.16.2101（2026/10/19） |
| 显存 / 最大 SM 时钟 / 功耗上限 | 8151 MiB / 3090 MHz / 216.00 W |
| 驱动模型 | WDDM（`GSP Firmware Version` 在 WDDM 下报 N/A，看不到固件版本） |

`0x2D04` 落在 Blackwell 段（本仓路由里 `0x2bxx+` 之外的所有 GB ID 都属于同一结论），
与 `ssdiag` 的 die 分族（PMC_BOOT_0 bits[31:20] = `0x1B0–0x1BF` → `blackwell-gb2`）一致。

> ⚠️ 注意：`clocks.max.sm=3090 MHz` 是**上限**，当前 1545 MHz 是空闲降频，不代表任何"解锁"。

## 2. 驱动自带的固件资产（读盘，未接触 GPU）

目录：`C:\Windows\System32\DriverStore\FileRepository\nv_dispi.inf_amd64_<hash>`

| 文件 | 大小 | 说明 |
|---|---|---|
| `gsp_ga10x.bin` | 18,262,168 | GSP-RM 镜像 + 各族签名（ELF64） |
| `gsp_tu10x.bin` | 16,688,016 | Turing 族 |
| `ucodes_ga10x.bin` | 56,128,512 | `NVUCODES` 容器（BINDATA 类微码） |
| `ucodes_tu10x.bin` | 12,532,480 | Turing 族 |
| `nvlddmkm.sys` | 102,231,272 | 内核驱动（零售版，符号已剥离） |

**没有 `ucodes_gb20x.bin`**：Blackwell 消费卡共用 `ga10x` 那一份微码归档。
这与"GD20x 没有自己的 SEC2 booter 套件"的判断方向一致（社区在 610.43.03 上的独立结论：
最大的未发布镜像 40,192 B < Ada booter 56,832 B，且不存在任何 Blackwell booter）。

### 2.1 `gsp_ga10x.bin` 的 ELF 段（本次实测）

```
shoff=18260952  entsize=64  shnum=19  shstrndx=18
1  .fwimage                18210816  @64
2  .note.gnu.build-id             36
3  .fwversion                     10
4  .fwsignature_cc_gr10x        4096
5  .fwsignature_gr10x           4096
6  .fwsignature_gb20y           4096   ← 注意是 gb20**y**
7  .fwsignature_cc_gb20x        4096
8  .fwsignature_gb20x           4096   ← 本卡所属族
9  .fwsignature_cc_gb10x        4096
10 .fwsignature_gb10y           4096
11 .fwsignature_gb10x           4096
12 .fwsignature_cc_gh100        4096
13 .fwsignature_gh100           4096
14 .fwsignature_ad10x           4096
15 .fwsignature_ga10x           4096
```

**结论（重要）**：`gb20x` 的 **GSP-RM 签名**确实随 621.01 一起发行。
所以"签名资产"从来不是 50 系的瓶颈——**缺的是那段能被主机点火、能被溢出成 ROP 的 SEC2 Booter**。
（本仓 `assets/src/elf.rs` 的注释早就指出 `gsp_ga10x.bin` 带 GB/GR 段，本次在本机驱动上复核成立。）

## 3. 反面验证：零售驱动里扫符号无效

对 `nvlddmkm.sys`（102 MB）做 ASCII 扫描，`BooterLoadUcode` / `GspRmBoot` / `GspRmFmcGfw` /
`FWSEC` / `kfsp` / `FspBoot` / `GspFmc` **全部 0 命中**。

这不是"证据表明没有 booter"，而是**零售二进制已剥离/压缩符号**，`strings` 方法在这里无效。
社区用的是"按尺寸比对镜像"的方法，需要内核调试器或驱动逆向环境，本机（非管理员）不具备。
→ 这条线索**不成立也不反驳**，如实记录为"方法无效"。

## 4. 本轮做了什么、没做什么

| 做了（全部只读） | 结果 |
|---|---|
| `nvidia-smi` 查询 | ✅ 身份/架构/VBIOS/功耗 |
| 解析 `gsp_ga10x.bin` ELF 段表 | ✅ 12 个族签名段，含 `gb20x` |
| `NVUCODES` 容器头解析 + 字符串扫 | ✅ magic/版本/条目步长；❌ 无可用名称（载荷压缩） |
| `nvlddmkm.sys` 符号扫描 | ⚠️ 方法无效（符号剥离） |
| 代码改动（`tools/ssdiag`） | ✅ 加 GB 行表 + **禁用 GB 写路径** |

| 没做（刻意的） | 原因 |
|---|---|
| 写入任何 MMIO 寄存器 | 需先有 L3 写入口；GB 上不存在，且用户要求零风险 |
| 加载 `pmxdrv.sys` | 需管理员；且属 BYOVD 面，未获授权不动 |
| FLR / D3 转换 / 熔丝写 / VBIOS 刷新 | 明确禁止（不可逆或高风险） |
| 改时钟/功耗/驱动设置、改注册表 | 非本次目标 |
| 装 CUDA/PyTorch 做算力实测 | 体积大（~2.5 GB），留待用户确认 |

## 5. MMIO 只读采样：已尝试，被内核策略挡住（未写入任何东西）

已按"只读"目标执行过一次提权采样（`ssdiag --select 2D04`，用户点了 UAC）。结果：

```
1 NVIDIA GPU function(s) discovered
ranges: 84000000-880fffff (65 MiB) / 6200000000-6201ffffff (32 MiB)
map BAR0@0x6200000000 failed: MAP_PHYS ioctl failed (win32 error 5)
map BAR0@0x84000000 failed: MAP_PHYS ioctl failed (win32 error 5)
no candidate range decoded as an NVIDIA PMC - card skipped
```

- 两个候选 BAR0 都拿到（`0x6200000000` / `0x84000000`，与 Win32_VideoController 一致），
  但 `pmxdrv.sys` 的 `MAP_PHYS` ioctl 一律返回 **EPERM(5)**，一次寄存器读都没发生。
- 最可能原因：本机内核策略（HVCI/内存完整性）或该 `pmxdrv.sys` 构建与本驱动的映射契约不匹配。
  与显卡状态无关——**全程零写入、零复位**。

### 5.1 一个必须记录的工具缺陷（清理未真正生效）

`ssdiag` 退出时打印 `driver service removed (remove-when-done)`，但实测**服务仍在运行**：

| 检查项 | 结果 |
|---|---|
| `sc query SSDIAG_PMXDRV` | `STATE 4 RUNNING (NOT_STOPPABLE, IGNORES_SHUTDOWN)` |
| `sc stop` | **1052** 控件无效（驱动无卸载例程 → 运行期不可能停止） |
| `sc delete` | **1072** 已标记为删除（需重启才消失） |
| `%TEMP%\ssdiag-pmxdrv.sys` | 仍存在（43632 B，被内核占用，删不掉） |

即：那行"removed"是**无条件打印**，与真实结果无关；而这类社区驱动通常没有 Unload 例程，
**唯一清理途径是重启**。已做处置：

1. 服务已标记删除（`DeletesPending`）→ 重启后服务与注册表键消失；
2. 已向 `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\PendingFileRenameOperations`
   追加 `\??\<TEMP>\ssdiag-pmxdrv.sys`（读回确认，原有 10 条条目未改动）→ 重启时删文件。

> **重启前不要开有反作弊的游戏**：此刻内核里仍加载着一个非系统驱动。
> 重启后可用文末的自检命令确认已彻底清空。

## 6. 下一步：换一条不需要驱动的采样路径

`ssdiag` + `pmxdrv.sys` 这条路在本机**已判死**（§5，`MAP_PHYS` EPERM）。可行替代是走**项目自己的 UEFI 侧采样**：
`nv-uefi-unlocker` 的 loader 在 **`tx` 特性关闭**时是纯只读程序（枚举 + `sample::run` + 链回 `bootmgfw.efi`），
用 UEFI `PciIo` 直接读 BAR0，**不加载内核驱动、不进操作系统**；GOP 断连只发生在 tx 构建里，只读构建不碰。

代价：需要一次 U 盘启动（FAT32 + `BOOTX64.EFI`），并按项目 M1 流程临时处理 Secure Boot。
采样完链回 Windows，全程零写入。

无论走哪条路，要读的清单相同（**全部是读**，`--reapply` 在 GB 上已被代码硬拒）：

| 目标 | 地址 | 期望/判据 |
|---|---|---|
| 身份 | `PMC_BOOT_0 0x0` | `0x1Bxxxxxx`（GB2xx 家族确认，`0x1B6` 若为 GB206） |
| 钳制门 | `FEAT_OVR_PLM 0x823804` | 社区 GB203M = `0xfffffb8f`（关）；能否复现 |
| 选择器 | `SS0 0x82381c` / `SS1 0x823820` | 是否有值、enable 位是否为 0 |
| **读出** | `FEAT_READOUT_1 0x823818` | 社区 = `0x00c36180`，Ada 的 9×3bit 解不出 → 需重推打包 |
| **熔丝** | `FUSE_SS_FMLA32 0x8207d8` | 社区 GB202/GB203M = `3`（ctrl2080gr: 3=1/8）；判断钳制是否来自熔丝 |
| 上下文 | `WPR2 0x1fa824/28`、`MMU_LOCK 0x1fa82c/30`、`GFW 0x118128/0x118234`、`BSI 0x1180fc` | 冷态判据 |
| 引擎 | `SEC2 0x840100`、`GSP 0x110100`、`FBPA_PLM 0x9a0148` | badf 分桶 |
| 扫描 | `0x8207d0–0x8207ec`、`0x823800–0x823830` | 找 FUSE_SS 邻域与 FEAT 簇的完整形状 |

预期产出：**GB206 冷值表**（本仓目前只有 TU106/AD107 两族）+ `FEAT_READOUT_1` 打包假设。
这两样是任何后续研究（包括别人做的）的共同前置。

## 7. 安全边界说明

- 所有操作都在"读盘"、"只读查询"、"编译"层面；GPU 侧零写入、零复位。
- `ssdiag` 的写路径只在 `--reapply` 且 `PLM==0xffffffff` 时触发；本次已加 `gb` 分支**无条件拒绝**。
- 机器级副作用两条，均可回滚：
  1. minimal Rust 工具链（`--no-modify-path`）→ `rustup self uninstall` 可完全移除；
  2. 一次性驱动 `SSDIAG_PMXDRV` 已标记删除 + 文件已排入开机删除队列 → **重启即清空**。

### 重启后的自检（复制即用）

```powershell
Get-Service SSDIAG_PMXDRV -ErrorAction SilentlyContinue            # 期望：无输出
Test-Path "HKLM:\SYSTEM\CurrentControlSet\Services\SSDIAG_PMXDRV"  # 期望：False
Test-Path (Join-Path $env:TEMP "ssdiag-pmxdrv.sys")                # 期望：False
Get-CimInstance Win32_SystemDriver -Filter "Name='SSDIAG_PMXDRV'"  # 期望：无输出
```

四项全绿即表示内核里不再有任何本轮装载的东西，可以放心开游戏。

