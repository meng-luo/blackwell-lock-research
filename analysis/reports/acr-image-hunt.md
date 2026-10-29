# ACR / FMC 应用层镜像搜索 & 7 张 libos 镜像差异分析

- 样本：`gb206-fw\linux-fw\gsp_ga10x.bin`（84,277,400 B，`.fwimage` @0x40，84,226,048 B，`.fwversion=610.43.03`）
  vs `gb206-fw\img00_0x006a000.elf … img11_0x0fa7000.elf`（Windows 包 12 片）
- **补充发现（决定性）**：Windows 包的原始容器就在本机
  `C:\Windows\System32\DriverStore\FileRepository\nv_dispi.inf_amd64_<hash>\gsp_ga10x.bin`
  （18,262,168 B，`.fwversion` = `620.67.01`，`.fwimage` 18,210,816 B）。它的清单 `rel` 字段与给定的 12 个切片偏移
  **逐一精确对应**，因此下面所有 "W0x = 某个 `kernel_*.elf`" 的结论是**被证明的**，不是按顺序猜的。（只读了它，未做任何修改。）
- 只读分析。中间产物全部在 `gb206-fw\tmp2\`（脚本 + `pass*.json`），本报告是唯一新增的交付文件。
- 所有反汇编/计数都基于：可执行段字节 → 重建最小 ELF（e_machine=243、1×PT_LOAD X、`.text`）→ `llvm-objdump --triple=riscv64`；
  指令普查另用自写的 2/4 字节定向扫描（RVC 相位正确）。

## 0. 先说结论（含对既有假设的修正）

1. **找到了权威的名称表**：`.fwimage` 内偏移 **0x6d000** 处是一个镜像清单（magic `0x81b26a705c10e14d`，13 个条目），
   条目里的 `(rel_offset, filesz, prot, vaddr)` 与实际内嵌 ELF 的 phdr **逐字段吻合**。
   ⇒ 12 个 ELF 的真实身份是 `kernel_{ga10x,gh100,gb10x,gb10y,gb20x,gb20y,gr10x}.elf` + `debug.elf` + `init.elf` +
   `rm.elf` + `vgpu.elf` + `mnoc.elf`，再加大数据块 `rm.bindata.bin`。
2. **"7 张近乎同构镜像"= 每**芯片家族**一份 libos 内核**（不是每引擎/每实例）。判据见 §3。
3. **GB206 对应的那张是 `kernel_gb20x.elf`**：Linux 包 = **L04**（`.fwimage`@0x10d000），Windows 包 = **W04**（@0x12e000）。
   两边都由清单 `rel` 字段**证明**（不是推断）。容器里同时有专门的 `.fwsignature_gb20x`（4096 B，与其他 11 个家族签名互不相同）。
4. **两张包里都没有 ACR / FMC 的应用层镜像**（负面结论，见 §2.4）。镜像清单里没有它们的位置。
   Windows 包可以判死（两个数据块明文：32,768 B 近全零 bindata + 1,703,936 B `NVDUMPCONFIGSIG` 配置表，均无 ELF magic、无 ACR/FMC 串）；
   Linux 包只剩一个熵 8.000 的 64,512,000 B 密文 `rm.bindata.bin` 无法静态判定。
5. 修正两处既有描述：
   - 所谓 "BSS 124–155 KB" 实际是**文件里有内容的 RW PT_LOAD**（`0xffffffffa3000000`，`filesz == memsz`），是 rodata/data，**不是 BSS**（真正的 BSS 为 0）。
   - 既有"已确认 libos"的可执行段 `filesz=61440` 对应的是 **Windows 版**；Linux 版是 53248 / 57344。

---

## 1. 指纹总表

### 1.1 容器层（gsp_ga10x.bin 自身的 ELF 结构）

| 项 | 值 |
|---|---|
| e_machine / e_shoff / shnum | 243 (RISC-V) / 0x505f3d8 / 19 |
| `.fwimage` | off 0x40，size **84,226,048** |
| `.fwversion` | `"610.43.03\0"`（10 B @0x5053064） |
| `.note.gnu.build-id` | 36 B @0x5053040，`…3609758e15d41b2720db2ffb49df623c4ac21c62` |
| `.fwsignature_*` | **12 × 4096 B**，非零 1539–1549 B，sha1 各不相同：cc_gr10x/gr10x/gb20y/cc_gb20x/**gb20x**/cc_gb10x/gb10y/gb10x/cc_gh100/gh100/ad10x/ga10x |
| `.strtab` 里的构建路径 | `.../drivers/resman/build/gsp/_out/Linux_amd64_release/LibOS_riscv64/release/firmware/ga10x.firmware.bin` |

`.fwimage` 内部布局（全部实测，`0x12cd000 + 0x3d86000 = 0x50b3000 = 84,226,048` 闭合）：

| `.fwimage` 偏移 | 名称（清单） | 大小 |
|---|---|---|
| 0x000000 | （非 ELF）**stage-0 加载器**：入口在偏移 0，`auipc t0,0x6c; addi t0,+0x80; lb` 读 0x6c080 字节后跳 0x1e0a；含 libos `sbi.c` 失败串、`kernel_<fam>.elf` 名字数组 @0x3b38、清单 @0x6d000 | 450,560（0x6e000），其中 0x10000–0x60000 全零 |
| 0x06e000 | kernel_ga10x.elf | 155,648 |
| 0x094000 | kernel_gh100.elf | 159,744 |
| 0x0bb000 | kernel_gb10x.elf | 167,936 |
| 0x0e4000 | kernel_gb10y.elf | 167,936 |
| 0x10d000 | **kernel_gb20x.elf** | 167,936 |
| 0x136000 | kernel_gb20y.elf | 163,840 |
| 0x15e000 | kernel_gr10x.elf | 167,936 |
| 0x187000 | debug.elf | 41,584（+3,472 零填充） |
| 0x192000 | init.elf | 49,776（+3,472 零填充） |
| 0x19f000 | rm.elf | 17,220,248 |
| 0x120c000 | vgpu.elf | 725,616 |
| 0x12be000 | mnoc.elf | 57,968 |
| 0x12cd000 | **rm.bindata.bin**（数据，非 ELF） | 64,512,000，**熵 8.000/8**，无 magic/头 |

清单条目字段实测（以 `kernel_ga10x.elf` 为例）：
`vaddr=0xffffffff92fff000, file_off=0x0, rel=0x1000, filesz=53248, prot=5` /
`vaddr=0xffffffffa3000000, file_off=0xd000, rel=0xe000, filesz=102400, prot=6`。
7 个内核条目的 `rel` 与实际内嵌 ELF 的容器偏移 **逐一对应**（差 0x6d000），`filesz` 与 phdr 完全相等。

### 1.1b Windows 容器清单（620.67.01）—— 与 Linux 包的两点结构差异

清单基址 0x69000（首个内核条目 @0x69030），**14 个条目**（比 Linux 多一个 `rm.data.bin`）：

| 名称 | rel | 落到切片偏移 | 与给定切片 |
|---|---|---|---|
| kernel_ga10x.elf | 0x001000 | 0x06a000 | img00 ✓ (X 61440 / R 126976) |
| kernel_gh100.elf | 0x02f000 | 0x098000 | img01 ✓ (61440 / 147456) |
| kernel_gb10x.elf | 0x062000 | 0x0cb000 | img02 ✓ (61440 / 155648) |
| kernel_gb10y.elf | 0x097000 | 0x100000 | img03 ✓ (61440 / 126976) |
| **kernel_gb20x.elf** | 0x0c5000 | **0x12e000** | **img04 ✓ (69632 / 147456)** |
| kernel_gb20y.elf | 0x0fa000 | 0x163000 | img05 ✓ (65536 / 147456) |
| kernel_gr10x.elf | 0x12e000 | 0x197000 | img06 ✓ (61440 / 155648) |
| debug.elf | — | 0x1cc000 | img07 ✓ |
| init.elf | — | 0x1d7000 | img08 ✓ |
| rm.elf | — | 0x1e3000 | img09 ✓ (X 13,602,816) |
| vgpu.elf | — | 0xedd000 | img10 ✓ (X 757,760 / R 65,536) |
| mnoc.elf | — | 0xfa7000 | img11 ✓ (X 20,480 / R 36,864) |
| rm.bindata.bin | 0xf4d000 | 0xfb6000 | **32,768 B** |
| rm.data.bin | 0xf55000 | 0xfbe000 | **1,703,936 B**（0xfbe000+0x1a0000 = 0x115e000 = `.fwimage` 末尾 ✓） |

⇒ **打包方式差异**：Linux 包把 RM 数据做成 **一个 64,512,000 B 的 `rm.bindata.bin`**（熵 8.000，密文）；
Windows 包是 **32,768 B `rm.bindata.bin` + 1,703,936 B `rm.data.bin`**，而且这两个明文可读。
这也说明"引擎固件藏在 bindata 里"这条推断需要重新评估（§4.3 第 4 条）。

> 说明：日志/init/vgpu/mnoc/rm 这几条的描述符字段布局与内核条目**不同**（同一个 7 字槽里第 3 个 u64 才是 `rel`，
> 且 4-PT_LOAD 的 `rm.elf` 会把槽撑开）。内核条目是 7×2 字的标准布局，已 100% 对得上；
> 非内核条目的字段语义 **[未确认]**，但它们的内嵌 ELF 位置仍由"实际 ELF 扫描 = 给定切片偏移（identical: True）"独立证实。

### 1.2 逐镜像指纹（Linux 包 L00–L11）

`X` = 可执行 PT_LOAD，`R` = 第二 PT_LOAD（RW，文件里有内容）。`→str` = `auipc+addi` 解析到本镜像字符串起点的命中数。

| img | 清单名 | 容器内偏移 | 文件大小 | X vaddr | X filesz | R filesz | entry | `.c` 数 | 字符串 | ecall | sret | **mret** | csr | auipc+addi | →str | PT_TLS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| L00 | kernel_ga10x.elf | 0x06e000 | 155,648 | 0xffffffff92fff000 | 53,248 | 102,400 | 0xffffffff93000000 | 15 | 94 | 10 | 7 | 0 | 289 | 513 | 103 | no |
| L01 | kernel_gh100.elf | 0x094000 | 159,744 | 0xffffffff92fff000 | 53,248 | 106,496 | 0xffffffff93000000 | 16 | 94 | 11 | 6 | 0 | 292 | 522 | 105 | no |
| L02 | kernel_gb10x.elf | 0x0bb000 | 167,936 | 0xffffffff92fff000 | 53,248 | 114,688 | 0xffffffff93000000 | 16 | 96 | 11 | 6 | 0 | 292 | 522 | 105 | no |
| L03 | kernel_gb10y.elf | 0x0e4000 | 167,936 | 0xffffffff92fff000 | 53,248 | 114,688 | 0xffffffff93000000 | 16 | 93 | 10 | 6 | 0 | 291 | 520 | 105 | no |
| L04 | **kernel_gb20x.elf** | 0x10d000 | 167,936 | 0xffffffff92fff000 | **57,344** | 110,592 | 0xffffffff93000000 | 16 | 121 | 12 | 6 | 0 | 340 | 578 | 130 | no |
| L05 | kernel_gb20y.elf | 0x136000 | 163,840 | 0xffffffff92fff000 | 57,344 | 106,496 | 0xffffffff93000000 | 16 | 115 | 10 | 6 | 0 | 334 | 576 | 130 | no |
| L06 | kernel_gr10x.elf | 0x15e000 | 167,936 | 0xffffffff92fff000 | 53,248 | 114,688 | 0xffffffff93000000 | 16 | 96 | 11 | 6 | 0 | 292 | 522 | 105 | no |
| L07 | debug.elf | 0x187000 | 41,584 | 0x01000000 | 32,768 | 8,192 | 0x010027cc | 0 | 132 | 2 | 0 | 0 | 56 | 367 | 146 | **yes** |
| L08 | init.elf | 0x192000 | 49,776 | 0x01000000 | 32,768 | 16,384 | 0x010025a2 | 0 | 49 | 1 | 0 | 0 | 24 | 445 | 29 | **yes** |
| L09 | rm.elf | 0x19f000 | 17,220,248 | 0x01000000 | 15,298,560 | 1,921,024 | 0x01a9baec | 3* | 16,583 | 268 | 2 | 0 | 3,650 | 160,670 | 4,254 | **yes** |
| L10 | vgpu.elf | 0x120c000 | 725,616 | 0x01000000 | 663,552 | 61,440 | 0x01075290 | 0 | 679 | 6 | 0 | 0 | 99 | 6,580 | 199 | **yes** |
| L11 | mnoc.elf | 0x12be000 | 57,968 | 0x01000000 | 20,480 | 36,864 | 0x010026bc | 0 | 4 | 1 | 0 | 0 | 1 | 152 | 0 | **yes** |

### 1.3 逐镜像指纹（Windows 包 W00–W11）

| img | 清单名（载体清单已证实） | 容器内偏移 | 文件大小 | X vaddr | X filesz | R filesz | entry | `.c` 数 | 字符串 | ecall | sret | **mret** | csr | auipc+addi | →str | PT_TLS |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| W00 | kernel_ga10x.elf | 0x006a000 | 188,416 | 0xffffffff92fff000 | 61,440 | 126,976 | 0xffffffff93000000 | 16 | 115 | 10 | 7 | 0 | 326 | 649 | 147 | no |
| W01 | kernel_gh100.elf | 0x0098000 | 208,896 | 0xffffffff92fff000 | 61,440 | 147,456 | 0xffffffff93000000 | 17 | 119 | 11 | 6 | 0 | 328 | 658 | 151 | no |
| W02 | kernel_gb10x.elf | 0x00cb000 | 217,088 | 0xffffffff92fff000 | 61,440 | 155,648 | 0xffffffff93000000 | 17 | 116 | 11 | 6 | 0 | 328 | 658 | 151 | no |
| W03 | kernel_gb10y.elf | 0x0100000 | 188,416 | 0xffffffff92fff000 | 61,440 | 126,976 | 0xffffffff93000000 | 17 | 118 | 10 | 6 | 0 | 327 | 656 | 151 | no |
| W04 | **kernel_gb20x.elf** | 0x012e000 | 217,088 | 0xffffffff92fff000 | **69,632** | 147,456 | 0xffffffff93000000 | 17 | 143 | 12 | 6 | 0 | 379 | 713 | 176 | no |
| W05 | kernel_gb20y.elf | 0x0163000 | 212,992 | 0xffffffff92fff000 | 65,536 | 147,456 | 0xffffffff93000000 | 17 | 136 | 10 | 6 | 0 | 373 | 713 | 176 | no |
| W06 | kernel_gr10x.elf | 0x0197000 | 217,088 | 0xffffffff92fff000 | 61,440 | 155,648 | 0xffffffff93000000 | 17 | 116 | 11 | 6 | 0 | 330 | 658 | 151 | no |
| W07 | debug.elf | 0x01cc000 | 41,584 | 0x01000000 | 32,768 | 8,192 | 0x01002782 | 0 | 133 | 2 | 0 | 0 | 56 | 349 | 153 | **yes** |
| W08 | init.elf | 0x01d7000 | 45,680 | 0x01000000 | 32,768 | 12,288 | 0x01002fae | 0 | 50 | 1 | 0 | 0 | 24 | 442 | 39 | **yes** |
| W09 | rm.elf | 0x01e3000 | 13,603,416 | 0x01000000 | 13,602,816 | —（单 LOAD） | 0x0193dc90 | 1* | 13,184 | 321 | 2 | 0 | 3,020 | 154,226 | 4,084 | **yes** |
| W10 | vgpu.elf | 0x0edd000 | 823,920 | 0x01000000 | 757,760 | 65,536 | 0x01086f86 | 0 | 494 | 7 | 0 | 0 | 75 | 7,768 | 209 | **yes** |
| W11 | mnoc.elf | 0x0fa7000 | 57,968 | 0x01000000 | 20,480 | 36,864 | 0x01002940 | 0 | 4 | 1 | 0 | 0 | 1 | 151 | 0 | **yes** |

\* `rm.elf` 的 "`.c` 数 3/1" 是误报：命中的是 `.Sin.c` / `H.c` / `o.c` 这种 2–6 字符片段，出现在二进制表里，**不是源路径断言表**。

### 1.4 特征串矩阵（命中次数）

| 镜像 | `findAperture` | `KernelElfMap` | `KernelRootfsMount` | `KernelTaskCreate` | `KernelPartitionParentPort` | `KernelPortAllocate` | `KernelSoftmmuSwapInit` | `SoftmmuSwap` | `heartbeat` |
|---|---|---|---|---|---|---|---|---|---|
| L00 | 1 | 1 | 1 | 2 | 2 | 3 | 0 | 0 | 1 |
| L04 | 1 | 2 | 1 | 3 | 3 | 4 | 0 | 0 | 1 |
| W00 | 1 | 2 | 1 | 3 | 2 | 3 | **1** | **1** | 0 |
| W04 | 1 | 3 | 1 | 4 | 3 | 4 | **1** | **1** | 0 |
| L07/L08/L09/L10/L11 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 |

`mret` 在 **全部 24 张镜像里都是 0**；`la`/`ecall` 之外没有出现 `MQ_*`、`*SoftmmuSwapInit` 之外的 mq 特征。
自定义 opcode（NV 扩展）分布：内核仅 `CUSTOM1(0x2b)×3`；`debug/init/mnoc` 有 `CUSTOM0(0x0b)` 若干；
`rm.elf` 四种自定义 opcode 共 ~13,000 次（L09: 3,341+3,114+3,730+2,823 = 13,008；W09: 3,131+3,958+2,863+3,302 = 13,254）；
`vgpu.elf` 的 `CUSTOM3(0x7b)`：L10 134 次 / W10 28 次。
`rm.elf` 是唯一大量使用「funct3=0 且 imm12 非标准」的 SYSTEM 指令（`sys_priv` 375–378，例如 `csrw 0x5ca`/`csrw 0x5cf`）。

---

## 2. 分层判定

### 2.1 内核层（A 层）：7 张 `kernel_<family>.elf` —— 置信度 **0.97**

**证据（每条都有数字）**
1. **清单命名**：这 7 张在 `.fwimage+0x6d000` 的清单里就叫 `kernel_ga10x.elf` … `kernel_gr10x.elf`；
   名字与 `nv-firmware.h` 里 `nv_firmware_chip_family_to_string()` 的 7 个家族串**完全一致**（gb20x/gb20y/gb10x/gb10y/gr10x/gh100/ga10x）。
2. **地址/链接方式**：高 canonical 地址 `0xffffffff92fff000`（X）+ `0xffffffffa3000000`（RW），`entry = X_vaddr + 0x1000`，
   即 ELF 头占满第一页、代码从 +0x1000 开始（`auipc` 目标是低 2 GB 内的 `0xffffffffa3xxxxxx`，说明它们**不跑在 identity map 上**）。
3. **内核才有的事务**：`KernelElfMap`/`KernelRootfsMountFilesystem`/`KernelTaskCreate`/`KernelPartitionParentPort`/`KernelPortAllocate`
   各命中 1–4 次；断言串表完整（15–17 个 `.c` 路径 = `kernel/mm/*.c`、`kernel/{init,partition,ipi,loader}.c`、`kernel/sched/port.c`、`kernel/server/server.c`、`drivers/dma.c|gdma.c`、`common/nvriscv-2.0/sbi.c`）。
4. **特权级证据**：`sret` 6–7 次、`wfi` 1 次、`csr*` 289–379 次（含 `satp`/`sfence.vma` 系列），**没有 `mret`**
   ⇒ S-mode 内核、自己管理地址空间、通过 `sret` 返回用户态。
5. **结构**：两个 PT_LOAD、无 PT_TLS、`e_shoff` 悬空（section header 表被有意抹掉：`shstrndx` 指向 SHT_NULL）。
6. **不是 BSS**：第二段 `filesz == memsz`（如 102,400 == 102,400），内容是 rodata/数据表；真正的 `.bss` = 0。
7. **隔离于应用层**：`PT_TLS` = no；不含 `debug/init/vgpu/mnoc` 任何消息串。

### 2.2 应用层（B 层）：`debug.elf` / `init.elf` / `rm.elf` / `vgpu.elf` / `mnoc.elf` —— 置信度 **0.85**

**证据**
1. **链接地址 = libos 用户态约定**：X 段 `0x01000000`、entry 落在 `0x0100xxxx`–`0x01a9xxxx`（在 `.text` 内部，`entry_off_from_base` 0x25a2–0xa9baec）；
   这说明它们是「按 libos 加载器约定的固定低地址」链接的**独立任务镜像**，而不是内核。
2. **`PT_TLS`（p_type=7）只出现在这 5 张里**（内核没有）—— 用户态线程局部存储，是进程镜像的直接标志。
3. **进入内核的方式**：`ecall` 1–7 次（`rm.elf` 268/321 次），`sret` 基本为 0（`rm.elf` 的 2 次在 13 MB 段里，可能是数据误判 [未确认]），
   **没有** `wfi`、没有 `satp` 类 CSR（csr 计数 1–99，`rm.elf` 的 3,650 来自大段数据）。
4. **没有 `.c` 源路径断言表**（除 `rm.elf` 的 3 个误报）：它们用的是 `Runtime failure:`/`unable to …` 这类消息串，
   共 4–16,583 条，风格与内核断言表不同。
5. **任务间关系可读**：`init.elf`（L08/W08）含 `"rm.elf"`、`"vgpu"`、`"mnoc"`、
   `"Partition spawned as RM Partition"`、`"Failed to open the VGPU ELF %s %u"`、`"Failed to receive GspFwTaskMappings"`、
   `"task_init_process_init_args"` ⇒ **它是拉起其它分区任务的 init 任务**；
   `debug.elf` 含 `"Debug task ALIVE! partitionId %d …"`、`"PORT receive error"`；
   `vgpu.elf`（L10/W10）含 `"vgpu"×9`、`"Failed to map initArgs"`；`mnoc.elf` 只有 4 条 4 字符碎片、零特征串（纯代码，8,415 条指令）。
   这与 libos 是微内核（`KernelTaskCreate`/`KernelPartitionParentPort`）的模型自洽。
6. **与内核同包共存**：A、B 两层在**同一个 `.fwimage`、同一份清单**里，且 B 层入口地址域（0x01000000）与内核的
   identity-map 基址（`0xffffffffa3000000` 段）不重叠 —— 符合「libos 加载器把 ELF 任务映射到 0x01000000 后 `sret` 进去」的模型。

**置信度说明**：`debug`/`init`/`vgpu`/`mnoc` 高（0.9）；`rm.elf` 稍低（0.8）：它有 `PT_TLS` 和低地址，是用户态任务无疑，
但体积 13–15 MB、含 `ACR/SEC2/PMU/FALCON/VBIOS/NVDEC/FECS/NVJPG/OFA` 等引擎词，是「RM 分区主程序」，属于 B 层里的"重"任务。

### 2.3 其他层

- **stage-0 加载器**（`.fwimage` 0x0–0x6e000，450,560 B，非 ELF）：入口在偏移 0，第一条指令 `auipc t0,0x6c; addi t0,+0x80; lb t0,0(t0)`，
  读 `0x6c080` 的标志字节；含 `"Runtime failure: a0 == 0 @ …/sbi.c:%d"`、`"FB offset %llx fwWprStart %llx"`、
  `kernel_*.elf` 名字数组（0x3b38 起，7×24 B，顺序 gr10x/gb10y/gb20y/gb20x/gh100/ga10x/gb10x，与清单顺序**不同**）、
  以及 7 个 `auipc+addi; ret` 取址小函数（0x17c–0x1c8，各自返回某一家族的内核文件名指针）。**置信度 0.8**（身份=加载器；具体加载地址 [未确认]）。
- **`rm.bindata.bin`**（64,512,000 B，熵 8.0000/8，前 128 B 无任何已知 magic）：**密文**。它是不是引擎 ucode（ACR/FMC/SEC2…）容器 **[未确认，推断]**。

### 2.4 负面结果：ACR / FMC 的应用层镜像 —— 两张包里都没有

- 清单只有 13 个条目（7 内核 + debug + init + rm + vgpu + mnoc + rm.bindata.bin），**没有 ACR/FMC 条目**。
- 全部 24 张镜像里，`ACR` 只作为 **HDMI Audio Clock Regeneration**（`hdmiProgramFrlAcrWar_GA102`）和 RM 注册表键
  （`RmUseAutoAcr`、`RMDisableAcr`、`RMAcrExecuteOnSec2`、`RmAcrSigningAlgo`、`RMCreateAcrRegion1/2` …）出现；
  `FMC` 只出现在 falcon 错误码枚举名 `FLCN_ERR_FMC_BOOT_CHECK_FAIL` 里。
- `ucodes_ga10x.bin`（31,744 B，头 + 全零）是空的 —— 引擎 ucode 的传统投放位置为空。
- **Windows 包可以判死**：它的两个数据块都是明文且都很小 ——
  `rm.bindata.bin` 32,768 B（熵 1.742，几乎全零，无 ELF magic、无字符串）；
  `rm.data.bin` 1,703,936 B（熵 4.428，以 **`NVDUMPCONFIGSIG`** 开头，内容是 `G1450030300`/`10100200882` 这类 **register dump config**）。
  两者都不含 `ACR`/`FMC`/`falcon`/`NVFW`/`ucode`，也没有 ELF magic（`\x7fELF` 计数 = 0）
  ⇒ **Windows 的 GSP 载荷 = 12 个 ELF + 两张配置表，没有任何引擎固件。**
- 唯一未判定的是 **Linux 包的 `rm.bindata.bin`**（64,512,000 B，熵 8.0000，无 magic）。**结论：ACR/FMC 不在明文可分析的 12 张镜像里；
  是否在 Linux 的 `rm.bindata.bin` 内，静态不可判定**（且从 Windows 侧的对照看，它更可能不是引擎固件容器）。

---

## 3. 7 张同构镜像的差异分析

### 3.1 度量方法（避免踩坑）

镜像里 **60–70% 的指令是 2 字节压缩指令**，按 4 字节字对齐比较会把"整体错位 2 字节"误判成"85% 不同"（我先踩了这个坑）。
最终采用两种相位无关度量 + 一种语义度量：

- **P**：32 B 窗口覆盖率（A 的每 32 B 窗口（步长 8）是否在 B 中任意位置出现）——位置无关
- **D**：数据段逐字节同位比较 + 连续差异区扫描
- **S**：断言调用点的 `(源文件, __LINE__)` 表 —— 编译期常量，差异直接反映源码状态/预处理配置

### 3.2 可执行段覆盖率 P（决定性数字）

| A | B | lenA | lenB | A→B | B→A | 零共享区数 | 最大零共享区 |
|---|---|---|---|---|---|---|---|
| W00 | W01 | 61,440 | 61,440 | **36.5%** | 35.9% | 19 | 4,352 B |
| W00 | W02 | 61,440 | 61,440 | 36.5% | 35.8% | 20 | 3,328 B |
| W00 | W03 | 61,440 | 61,440 | 36.9% | 36.6% | 15 | 4,352 B |
| W00 | W04 | 61,440 | 69,632 | 33.2% | 35.4% | 23 | 4,352 B |
| W00 | W05 | 61,440 | 65,536 | 34.2% | 33.2% | 24 | 4,352 B |
| W00 | W06 | 61,440 | 61,440 | 36.3% | 35.7% | 20 | 3,328 B |
| L00 | L01 | 53,248 | 53,248 | 37.7% | 36.4% | 13 | 4,096 B |
| L00 | L02 | 53,248 | 53,248 | 37.7% | 36.4% | 13 | 4,096 B |
| L00 | L03 | 53,248 | 53,248 | 37.7% | 36.6% | 12 | 4,608 B |
| L00 | L04 | 53,248 | 57,344 | 32.8% | 30.5% | 22 | 4,608 B |
| L00 | L05 | 53,248 | 57,344 | 33.1% | 31.3% | 22 | 4,608 B |
| L00 | L06 | 53,248 | 53,248 | 37.0% | 35.5% | 13 | 4,096 B |
| **L02 | L01** | 53,248 | 53,248 | **60.1%** | 60.2% | 3 | 768 B |
| **L02 | L03** | 53,248 | 53,248 | 53.9% | 54.2% | 3 | 2,048 B |
| **L02 | L06** | 53,248 | 53,248 | 48.2% | 48.1% | 5 | 1,536 B |
| L00 | W00 | 53,248 | 61,440 | 33.7% | 30.4% | 23 | 4,608 B |

解读：**代码本体只有 1/3–3/5 逐字节相同**，但它们的**指令普查几乎一致**（同尺寸组内总数差 −0.74%…+0.35%，
例：W01/W02 都恰好 23,033 条、`csr*=328`、`auipc+addi=658`、`→str=151`；L02/L03/L06 在 19,960–19,996 条）：
⇒ 同一程序、同一函数集、同规模，**被重新编译**（不同配置导致结构体布局/立即数/驱动选择变化，进而大范围改变机器码），
而不是"同一二进制改几个字节"。

### 3.3 数据段 D：几乎完全相同，只差一张小表 + 追加尾部

| A | B | R 长度 | B 多出 | 同位差异字节 | 差异区数 | 最大差异区 |
|---|---|---|---|---|---|---|
| W00 | W01 | 126,976 / 147,456 | +20,480 | 95 | 28 | 16 B |
| W00 | W02 | 126,976 / 155,648 | +28,672 | 95 | 28 | 16 B |
| W00 | W03 | 126,976 / 126,976 | 0 | 96 | 27 | 16 B |
| W00 | W04 | 126,976 / 147,456 | +20,480 | 105 | 28 | 16 B |
| W00 | W05 | 126,976 / 147,456 | +20,480 | 96 | 27 | 16 B |
| W00 | W06 | 126,976 / 155,648 | +28,672 | 95 | 28 | 16 B |
| L00 | L01…L06 | 102,400 / 106,496…114,688 | +4,096…+12,288 | 322–347 | 93 | 16 B |

覆盖率口径下数据段 **99.4–99.9% 相同**。差异集中在两处：

1. **va 0xffffffffa300a000–0xffffffffa300af00 的一小片表**：内容形如 `{0xffffffffa3015000, 0x40, 0x6060}` /
   `{0xffffffffa3016000, …, 0x74}` / `{0xffffffffa3018000, …, 0x94}` —— 随镜像变化的**指针/尺寸对**（指向各镜像自身 R 段尾部之后的区域），
   且整段在小图之间**整体位移 8 字节**（W00 指针在 0x0acf0，W01 在 0x0acf8）⇒ 结构体成员按配置增减。
2. **R 段尾部追加**：Linux +4,096 B（L01/L05）、+8,192 B（L04）、+12,288 B（L02/L03/L06）；
   Windows +20,480 B（W01/W04/W05）、+28,672 B（W02/W06）—— 额外 rodata，随配置增加断言/表项。

### 3.4 语义差异 S：断言 `(源文件, 行号)` 表 —— 差异到底是什么

7 张里 65/69（Win）、48/52（Linux）个调用点相同；不同的恰好是**配置开关**：

| 差异 | 谁 | 具体 |
|---|---|---|
| **DMA 驱动二选一** | 索引 0 vs 1–6 | #0 用 `drivers/dma.c`（3 个断言点）；#1–6 用 `drivers/gdma.c`（2 点）+ `drivers/extintr-v2.c`（行 549） |
| **init 路径规模** | #4/#5 vs 其余 | `kernel/init.c` 断言点：15–16（#0–#3,#6）vs **27–28**（#4=gb20x、#5=gb20y） |
| **softmmu swap** | 仅 Windows #1–6 | `kernel/mm/softmmu_swap.c` 多 2 个断言点（W00 无）；Linux 版**完全没有** `softmmu_core.c`/`softmmu_swap.c`（改为 `kernel/sched/heartbeat.c`） |
| **源码版本/行号** | Linux vs Windows | 同一调用点行号不同：`sbi.c` 56 vs 52、`objectpool.c` 122 vs 106、`loader.c` 239 vs 223、`port.c` 1165 vs 1162、`pagestate.c` 492 vs 493 |

代码尺寸也因此分档：Linux 53,248（ga10x/gh100/gb10x/gb10y/gr10x）vs 57,344（gb20x/gb20y）；
Windows 61,440（ga10x/gh100/gb10x/gb10y/gr10x）vs 65,536（gb20y）vs **69,632（gb20x，最大）**。

### 3.5 结论：是"每芯片家族一份"，不是"每 SKU 一份"，也不是"每引擎一份"

**判据（按强度排序）**
1. **清单直接命名**：7 张的名字就是 7 个**芯片家族**（`kernel_gb20x.elf` …），与 `nv-firmware.h` 的
   `NV_FIRMWARE_CHIP_FAMILY_*` 字符串一一对应；容器同时带 12 个 `.fwsignature_<family>`（含 `gb20x`/`gb20y`）。
2. **跨包可复现**：Linux 与 Windows 是**两套独立构建**（行号、`.c` 集合、段大小都不同），但"索引 0 特殊 + 索引 4/5 init 更大"
   的**模式完全相同**。若是"每引擎/每实例"，不会在两套独立构建里与家族边界严丝合缝地对齐。
3. **新型号代码更大**：Blackwell 两档（gb20x 69,632 / gb20y 65,536）比 Turing-DC 系（ga10x/gh100/gb10x/gb10y/gr10x，61,440）大 14%/7%，
   且 init 断言点翻倍 —— 符合"新家族需要更多初始化路径"，而非"某个 SKU 的特殊需求"。
4. **不含任何 SKU 身份**：全部 7 张里 `0x2d04`/`0x1b6`/`0x1b6000a1`/`"GB20"`/`"DEVICE_ID"` **零命中**（§4）。
   若是"每 SKU 一份"，至少应有设备号表或按 SKU 分支。
5. **同包共享**：`debug/init/rm/vgpu/mnoc` 只有**一份**，不随家族重复 —— 说明重复的 7 份是为**家族**分档，而不是为"引擎实例"。

**反证/边界**：文本逐字节只共享 33–61%，说明"同构"是**同源代码、不同配置重编译**，不是同一二进制。7 份的存在意义是：
`.fwimage` 一份载荷要同时服务 7 个家族（12 个签名家族里的 7 个有内核），运行时由 stage-0 加载器按家族挑一份。

---

## 4. GB206 映射尝试

本机 GB206：`PMC_BOOT_0 = 0x1b6000a1`、die id 0x1B6、PCI `10de:2d04`。

### 4.1 找到了什么

1. **静态映射（最硬的一条，已证明）**：Linux 清单把 `kernel_gb20x.elf` 指向 `.fwimage+0x10d000`（`rel=0xa0000`，X 57,344 / R 110,592）；
   Windows 容器（620.67.01，本机 DriverStore）把 `kernel_gb20x.elf` 指向 `.fwimage+0x12e000`（`rel=0xc5000`，X **69,632** / R **147,456**），
   与该容器的第 5 个 RISC-V ELF 完全吻合。`nv-firmware.h` 明确 `NV_FIRMWARE_CHIP_FAMILY_GB20X = 9` → 字符串 `"gb20x"`，GB206 属 GB20x 家族
   ⇒ **GB206 的 libos 内核 = `kernel_gb20x.elf` = Linux 包 L04（@0x10d000）、Windows 包 W04（@0x12e000）**。
2. **签名层**：容器内 `.fwsignature_gb20x`（4096 B，非零 1,546 B，sha1 `55ad7355e5c7621d…`）与
   `.fwsignature_gb20y`（`9ae2ff4a4922f22c…`）、`.fwsignature_cc_gb20x`（`abbee57ca37d1df0…`）互不相同，
   12 个家族签名**共用同一份 `.fwimage`** ⇒ 家族区分发生在"签名校验/加载器选择"层，不靠换载荷。
3. **设备号表在 RM 里，不在内核里**：`rm.elf` 里有成串的 16 位设备号：
   - W09 va 0x1acc97c：`00 2d | 04 2d | 1c 2d | 9c 2d`（0x2d00, **0x2d04**, 0x2d1c, 0x2d9c）
   - W09 va 0x1b176a4：`00 2d | 02 2d | 06 2d | 07 2d | 10 2d`
   - L09 对应 va 0x1c49e7c / 0x1c77edc / 0x1d55c4a（0x2d83）
   ⇒ **0x2d04 确实出现在设备号表里**，但它在 **GSP-RM（rm.elf）**里，不在 7 张内核里。
4. **加载器有家族分派**：stage-0 加载器 0x3b38 有 7×24 B 的名字数组，0x17c–0x1c8 有 7 个"返回某家族文件名指针"的小函数，
   0x6d000 是带 magic 的清单 —— 家族选择一定是运行时做的（按家族号/文件名）。数组顺序（gr10x, gb10y, gb20y, gb20x, gh100, ga10x, gb10x）
   与清单顺序（ga10x, gh100, gb10x, gb10y, gb20x, gb20y, gr10x）不同，**可能是按家族号索引的查找表** [未确认]。

### 4.2 没找到什么（明确列出）

- **没有**任何镜像含 `0x1b6000a1`、`0x1b6`、`"GB20"`、`"GB206"`、`"DEVICE_ID"`/`"device_id"`、`"CHIP_ID"`、
  `"BOOT_0"`/`"bootArgs"` 之类的 SKU 常量或引导参数解析特征（24 张镜像逐个 4/8 字节对齐 + 非对齐扫描，全 0 命中）。
- **没有**按 boot args 分支的痕迹：7 张内核的 `sys_priv`=0（无自定义 SYSTEM 调用）、`mret`=0、`csr*` 289–379 且 CRS 号分布同构；
  GB206 与 GB20y 的内核差异是**编译期**的（init 规模、驱动选择），不是运行期分支。
- **没有**把 `0x2d04` 映射到家族 9 的**明文表**：虽然 RM 里有 0x2d04 和相关设备号，但"设备号 → 家族"的映射逻辑在
  13 MB 的 RM 代码里（`rm.elf` 5.3 M 条指令），本次没有做符号级定位。
- **无法判定** `rm.bindata.bin`（64.5 MB，熵 8.000）里是否含 ACR/FMC/引擎 ucode。

### 4.3 下一步该怎么找（按性价比排序）

1. **动态侧确认家族号**：在驱动侧抓 `nv_firmware_chip_family`（`nv-firmware.h` 里 9 = GB20X）的计算路径，
   或直接在 GPU 上读 `PMC_BOOT_0` 的 ARCHITECTURE 字段期望值 0x1B6（只读、可用现成只读工具，**不要写寄存器**）。
   这一步能把"GB206 → family 9 → gb20x"从推断变成事实。
2. **定位加载器的家族分派代码**：把 stage-0 加载器（`.fwimage` 0x0–0x6e000，450,560 B）在已知加载地址下重定位反汇编
   （本次按 vaddr=0 做的，`auipc` 相对量不受影响，但 CSR/绝对地址会错），跟 0x3b38 名字数组的索引来源。
3. **找设备号→家族表**：在 `rm.elf` 里定位引用 va 0x1acc97c / 0x1b176a4 那两张设备号表的代码
   （搜 `auipc+addi` 目标），表项很可能是 `{u16 deviceId, u16 chipFamily}` 或 `(id, family)` 二元组；
   只要找到家族 9 的边界，就能证明 0x2d04 → GB20X。
4. **若目标是 ACR/FMC**：不要在 GSP 包里找（§2.4 已证）。两条线：
   (a) **GB20B 侧已经有线索**：本机 `gb206-fw\gb20b-fmc\` 下有一套**签名固件包**
   （`g_gsp_gb20b_dyn_prd_gfw_image.bin` 213,112 B / `gb20b_prd_image.bin` 212,296 B + 48 B hash + 384 B pkey + 384 B sig），
   头部 `03 04 48 00 00 3d 03 00 …`，**不是 ELF**，且明文里没有 `FMC`/`ACR`/`NVFW`/`falcon` 字符串 —— 这是"签名+密钥+hash"的
   加载器格式，符合 ACR/FMC 那类被签名固件的投放形态。**该目录不在本次两包范围内，属于另一条工作线**，我只做了只读查头，未深入。
   (b) Linux 包的 `rm.bindata.bin`（64.5 MB，熵 8.000）需要 FWSEC 密钥路径才能解，静态不可行。
5. **验证 L04 就是本机跑的那份**：读 GSP 日志（`/sys/kernel/debug/gcprint` 或 `nvidia-smi -q` 的 GSP 段），
   看 libos 启动时打印的分区/家族信息，与本报告的分区名（debug/init/rm/vgpu/mnoc）对照。

---

## 5. 结论一句话

**两张包（Linux 610.43.03 / Windows 620.67.01）里根本没有 ACR/FMC 的应用层镜像 —— 只有 7 份「每芯片家族一份」的 libos 微内核
（`kernel_ga10x/gh100/gb10x/gb10y/gb20x/gb20y/gr10x.elf`）+ 5 份 libos 用户态任务（`debug/init/rm/vgpu/mnoc.elf`）
+ 数据块（Linux：一个 64.5 MB 密文；Windows：32 KB 几乎全零的 bindata + 1.7 MB 明文 dump-config）；
7 张同构镜像是同源代码、不同编译配置（DMA 驱动二选一、init 规模 ×27、softmmu-swap 开关）的**家族变体**，
GB206 对应其中的 **`kernel_gb20x.elf`（Linux L04@0x10d000 / Windows W04@0x12e000）**，容器再用 **`.fwsignature_gb20x`** 单独签名 ——
即：同一份载荷服务 12 个家族，家族区分只发生在签名和加载器的取名环节，载荷里没有 SKU 身份。**

---

### 附：可复现的中间产物（`gb206-fw\tmp2\`）

| 文件 | 作用 |
|---|---|
| `common.py` | 定位 24 张镜像、解析 ELF、重建 `xr` ELF、字符串抽取 |
| `pass1_structure.py` / `pass1.json` | phdr/section/entry/sha1 结构指纹 |
| `pass1b_scan.py` | `.fwimage` 全量 `\x7fELF` 扫描（确认 12 张是全集，13 处命中里 1 处是假阳性）+ 间隙分析 |
| `pass2_fingerprint.py` / `pass2.json` | 字符串、`.c` 集合、指令普查（定向 2/4 字节）、`auipc+addi`→字符串解析 |
| `pass3_diff.py` | 首次 span diff（结论已被 3b/7 取代，保留作对照） |
| `pass3b_words.py` | 4 字节对齐比较（**演示了 RVC 相位陷阱**） |
| `pass4_align.py` / `pass4.json` | 单调 anchor diff（对象自测失败，仅作对照） |
| `pass5_match.py` | MUM+链化尝试（太慢，已中止） |
| `pass6_gb206.py` | GB206/SKU 常量与 ASCII 特征全扫 |
| `pass7_cover.py` / `pass7.json` | **最终采用的覆盖率 P + opcode 直方图** |
| `pass8_sites.py` / `pass8.json` / `pass8.txt` | **断言 `(file,line)` 表 —— §3.4 的全部证据** |
| `pass9_manifest.py` / `manifest.json` | **`.fwimage+0x6d000` 清单解析 —— 镜像身份的决定性证据** |
| `pass10_table.py` | §1.2/1.3 表格生成 |
| `pass11_windows_container.py` | **解析本机 DriverStore 里的 Windows 容器（620.67.01），证明 12 个切片 ↔ 清单名的对应**（输出 `-> identical: True`） |
| `boot.dis` / `boot.elf` | stage-0 加载器反汇编（vaddr=0 基线） |
