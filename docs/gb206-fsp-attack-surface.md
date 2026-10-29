# GB206 / RTX 50 系：FSP‑FMC 攻击面地图

> **做什么**：把"50 系上主机还能影响哪些东西、每一样由谁校验、兜底是谁"逐条列清，
> 让"值不值得投入研究"从感觉变成判断。
>
> **不做什么**：**不声称存在漏洞**，也不给任何"这样就能解锁"的路径。
> 每个候选都标注它需要什么证据、什么风险等级。
>
> 证据等级：`[源码]` = NVIDIA open‑gpu‑kernel‑modules（**MIT**，commit `57130a2`）；
> `[实测]` = 本机 GB206 冷值（`nv-uefi-unlocker/docs/evidence/m1-gb206-5060ti/`）；
> `[文档]` = kernel.org nova‑core；`[社区]` = 第三方公开实测；`[未确认]` = 公开资料查不到。

---

## 0. 结论先行

1. **没有已公开的免验签路径。** `kfspGspFmcIsEnforced_GH100()` 与 `ksec2GspFmcIsEnforced_GB20B()`
   **恒返回 TRUE**；`DISABLE_GSPFMC` 在 silicon 上被硬拒（`NV_ERR_NOT_SUPPORTED`，
   错误串 "Chain-of-trust (GSP-FMC) cannot be disabled on silicon."）。唯一免验签配置是
   `!silicon && !emulation` 的仿真/模型环境。`[源码]`
2. **debug 路线基本关闭。** 资产选择只有 `DebugSigned`/`ProdSigned` 两种标签，**无 `Unsigned`/`TestSig`**；
   debug 只决定"用哪把钥匙签的镜像"，**没有 skip‑verify 开关**；`NV_FUSE_ZB_OPT_SECURE_GSP_DEBUG_DIS`
   （offset **0x74C**，bit0）出厂 `DATA_INIT=0x1` 即禁 debug。`[源码]`
3. **剩下两个"决定性问题"都在闭源一侧**：
   - **Q1 公钥的信任锚**：COT 里的 `publicKey[96]` 由主机搬运，FSP 用它验 FMC——那公钥本身凭什么可信？
   - **Q2 FMC 对主机给定地址/尺寸的边界校验**：主机决定镜像地址、FRTS 位置、boot args 地址，FMC 拿去做 DMA/建 WPR2。
4. **另有 6 条"驱动侧"可静态复核的不一致**（`§7.1`）——它们是**主机内核侧**缺陷，
   **本身不等于**"能打开 PLM"，但它们是"主机输入进入安全上下文"的路径，值得作为假设去测。

## 1. 目标机已实测状态（本机 `10de:2d04`）

| 事实 | 值 | 意义 |
|---|---|---|
| die | `PMC_BOOT_0 = 0x1b6000a1` → **0x1B6 = GB206** | 消费级 GB20x，FSP 路径 |
| 钳制 | `FEAT_READOUT_1 = 0x00c36180 ≠ 0` | 钳制存在 |
| 速率熔丝 | `FUSE_SS_FMLA32 0x8207d8 = 3`（同区间 4 字 = 3） | 档位可能来自熔丝 |
| 门 | `FEAT_OVR_PLM 0x823804 = 0xfffffb8f`：读 L0–L3 / **写仅 L3** | 与 30/40 系同形 |
| override 总开关 | `FUSE_OPT_FEAT_OVR_DISABLE 0x8203f0 = 0` | **未被关死**，通路结构上还在 |
| 引擎门控 | `SEC2/GSP_CPUCTL = 0xbadf4100`（`0x41xx`=`privErrTargetLocked`） | 两引擎对 PL0 锁定 |
| 引导交接 | `BSI_SCRATCH15 = 0`、`GFW_SCRATCH = 0` | 无 Ampere 式 BSI/GFW 阶段 |

## 2. 为什么"booter 入口"整段消失（源码级）

`[源码]` `kernel/gpu/gsp/kernel_gsp_booter.c:4962-4976` 原话：

> "We use a set of Booter ucodes … **Booter Load loads, verifies, and boots GSP-RM in WPR2** …"
> `if (bPartitionedFmc) { // The secure boot ucode is included in the partitioned FMC, no need for separate Booter ucodes. }`

**Hopper+ 的"安全启动 ucode"被做进了分区式 FMC（内含 ACR）**，主机不再也不需要
把一段 booter 推到 SEC2 邮箱执行。我们实测的三条独立证据（`BSI=0`、`GFW_SCRATCH=0`、
`CPUCTL=0xbadf4100`）与之一致。

三条引导分支与验签方（`kernel_gsp_gh100.c:886-898`）：FSP（silicon 上恒真）/ SEC2‑FWSEC /
直连 BROM（兜底，非正常路径）。

## 3. 主机可控输入清单

### 3.1 COT 消息（`NVDM_PAYLOAD_COT`）

`[源码]` `inc/kernel/gpu/fsp/kern_fsp_cot_payload.h:36-53`：`#pragma pack(1)`，**860 字节平铺**，
11 个字段，**无 TLV、无子版本**：

| 字段 | 尺寸 | 值从哪来 |
|---|---|---|
| `version` / `size` | 16b / 16b | 驱动常量（`KernelFsp` 成员 / `sizeof`） |
| `gspFmcSysmemOffset` | 64b | **主机**：RM 新建 sysmem memdesc 的 GPU 物理地址（`kern_fsp_gh100.c:1030`） |
| `frtsSysmemOffset` / `Size` | 64b / 32b | **主机**：`frtsSize` 来自宏常量 1 MB（:1338），地址来自 memdesc（:1380-1381） |
| `frtsVidmemOffset` / `Size` | 64b / 32b | **主机**：从 FB 末尾**倒算的估算值**（:1446-1452） |
| `hash384[12]` / `signature[96]` / `publicKey[96]` | 48B / 384B / 384B | **驱动内嵌 bindata 的三个独立分段**（`BINDATA_LABEL_UCODE_HASH/_SIG/_PKEY`，:1032/1037/1042） |
| `gspBootArgsSysmemOffset` | 64b | **主机**：`pGspFmcArgumentsDescriptor` 的物理地址（:918-941） |

**关键事实**：COT 里**没有任何字段来自读寄存器**；镜像内容来自驱动里内嵌的
`BINDATA_LABEL_UCODE_IMAGE`（:997/1028），不是运行时解析 FMC ELF。

### 3.2 传输层

- 主机把包写进 **FSP 的 EMEM 窗口**（`NV_PFSP_EMEMD`），先写 `QUEUE_TAIL` 再写 `QUEUE_HEAD`
  （写 HEAD 会中断 FSP）；**通道大小硬编码 1 KB**（`kern_fsp_gh100.c:176-188`）。
  COT 868 B（860 + 8 B 头）→ 单包 SOM/EOM。
- Blackwell 另有 MNOC mailbox 路径（regkey `RmFspUseMnoc`），否则复用 GH100 实现。
- 收方向：长度由**设备侧写的 `MSGQ_TAIL`** 决定（`packetSize = tail - head + 4`，`NvU32` 无符号减法）。

### 3.3 `GSP_FMC_BOOT_PARAMS`（邮箱交付）

`[源码]` `kernel_gsp_gh100.c:732-733`：`MAILBOX0/1 = 物理地址`，FMC 入口读走并清零（:558），
残留非零被当错误码。`kgspPopulateWprMeta_GH100` 只填**尺寸 + 少量 sysmem 物理地址**：

> :323-324 "…The actual offsets get filled in by **ACR ucode** when it sets up WPR2."
> :360-364 "this value isn't needed on Hopper+, since the GSP-FMC can scrub/unlock anything we would need before GSP-RM boots, so we pass 0"

**Ampere 对照**（`arch/turing/kernel_gsp_tu102.c:780-861`）：主机算**绝对布局**并置
`bootCount=0; verified=0;`。→ 主机从"布局参与者"降级为"只报尺寸"。

## 4. 校验与兜底矩阵

| 层 | 内容 | 证据 |
|---|---|---|
| 驱动侧（长度） | `signature`/`publicKey` 各有两条 `NV_ASSERT_OR_GOTO`：须等于 `cotPayloadSignatureSize`/`...PublicKeySize`、不超目标数组 | `kern_fsp_gh100.c:1035-1043` |
| 驱动侧（一致性） | **没有**：镜像↔hash↔sig 一致性、key↔sig 匹配、`gspFmcSysmemOffset` 缓冲区大小与实际镜像大小一致 | 同上（缺失项） |
| 驱动侧（状态机） | `kfspWaitForSecureBoot` → `kfspSafeToSendBootCommands` 四道门；任一失败 `goto failed` | `kern_fsp_gh100.c:1195-1293` |
| 密码学 | 三条路径都是"镜像 + hash + sig + pkey"四件套；**无 skip‑verify**；缺一即 `NV_ERR_NOT_SUPPORTED` | `kernel_sec2_gb20b.c:738-795`、`kern_fsp_gh100.c:1030-1042` |
| PLM | `RISCV_BCR_CTRL` 读被 FMC 挡（:870）；`FALCON_ENGINE.RESET` 需 GSP 主动降 PLM（`kernel_gsp_gb100.c:56-87`）；**COT 期间连 MAILBOX0 都读不到**（:513-521） | `[源码]` |
| 熔丝 | debug 位 0x74C、`OPT_FPF_*_UCODE1_VERSION`（签名槽）| `[源码]` |

⚠️ **`NV_ASSERT_*` 家族**：多条关键检查用的是断言族而非 `NV_CHECK_*`；发布构建下是否被裁掉
取决于宏实现，本次未取 `nvassert.h` → `[未确认]`。这一条决定了 `§7.1` 里几条候选的实际权重。

## 5. 不可变面

- **FSP 本体**：ROM 内 IROT，不可读不可改 → 只能黑盒观测。
- **信任根**：验签材料由芯片内固件/熔丝把关，**具体绑定方式 `[未确认]`**（= Q1）。
- **熔丝**：可读，写 → 拒 POST `[社区]`。

## 6. 只读可观测面（零风险抓手）

`[源码]` `kernel_sec2_gb20b.c:830-890` 的 debug dump 全是**主机可读 scratch**：

`NV_PMC_ZB_SCRATCH_RESET_PLUS_2`（FWSEC 完成 = 0xFF，就绪判据 :519-527，超时 4 s）、
`NV_PBUS_ZB_SW_SCRATCH(54)` COT polling、`(52)` FRTS 完成、`(12)` devinit、
`NV_PSEC_FALCON_COMMON_SCRATCH_GROUP_2(0..3)`（FWSEC 错误码 / Offending PC / 地址）、
`(15)/(16)/(28)`（失败寄存器 / devinit PC / PRI 错误码）。

→ 现有 UEFI 只读构建即可画出 FSP 状态时序，**零写操作**。

## 7. 候选攻击面

### 7.1 驱动侧（可静态复核，**不等于**能开 PLM）

| # | 候选 | 位置 | 为什么值得看 |
|---|---|---|---|
| C1 | `hash384` 拷贝**没有长度相等断言**（与 sig/pkey 不对称，只传目标长度 48B） | `kern_fsp_gh100.c:1032` | 像遗漏；若 bindata 源长度可变 → 截断/越界写语义取决于 `bindataWriteToBuffer` `[未确认]` |
| C2 | `frtsVidmemOffset` 由**估算**得出，只做 `NV_ALIGN_UP`，**不查 FB 上界** | `:1446-1452`，源码自认 "we cannot know how much vidmem reservation RM will need" | 估算偏低 → 1 MB FRTS 写入与 RM 末尾保留区重叠（布局冲突，非经典越界） |
| C3 | `kfspSendPacket_GH100` 自身**不校验 1 KB 通道上限**（上限只在组包处 `NV_MIN`） | `:561-654` | 纵深防御缺口；新调用者传 >1 KB 会写穿通道 |
| C4 | 收方向长度取设备侧 `MSGQ_TAIL`，`NvU32` 无符号减法可回绕，唯一守卫是 `NV_ASSERT` | `:667-725` | 目标缓冲固定 1 KB |
| C5 | 哨兵 `-1` / `0` 与合法物理地址歧义；`bIsKeepWPRGc6` + `DISABLE_*` 组合下可能以哨兵值发出 | `:1457-1462` | FSP 如何解释 `-1`/`0` 决定是否读物理地址 0 `[未确认]` |
| C6 | `kfspFrtsSysmemLocationProgram_*` 把主机 memdesc 物理地址直接写进 `NV_PBUS_SW_FRTS_INSECURE_*`，**编程前无范围校验** | `:1638-1671`（GB100 版同名 `_ZB`） | 寄存器名自称 `INSECURE`：窗口由主机单方面声明，硬件不校验归属 |

**必须说清**：C1–C6 都在**主机驱动**里。即便成立，收益通常是内核/驱动侧，
**不会自动给出 GPU 的 L3 代码执行**；只有当它导致**FSP/FMC 侧**（闭源）误解析、越界或降级，
才可能变成"进 L3"的一步。这一步的判定权在 Q1/Q2。

### 7.2 GPU 侧（决定性未知，闭源）

| # | 问题 | 状态 |
|---|---|---|
| **Q1** | FSP 验签用的 `publicKey` 是否被熔丝/ROM 内的哈希或根密钥约束？ | **证据不足，倾向"不能"（中置信度）**，详见 `§7.2.1` |
| **Q2** | FMC 对 `gspFmcSysmemOffset` / `frtsSysmemOffset` / `gspBootArgsSysmemOffset` 与各自尺寸的**边界校验**是否存在？ | **可开工**：ACR/FMC 代码为明文 RISC-V（`§8.1`） |
| Q3 | PRC knob 空间是否有未公开的速率项 | 只读枚举即可穷举，风险最低 |

#### 7.2.1 Q1 取证结果（2026-10-29）

**一手确认的事实**（`kern_fsp_gh100.c:1031-1081`）：
- COT 的 IMAGE / HASH / SIG / **PKEY** 全部取自驱动自带 bindata（`BINDATA_LABEL_UCODE_PKEY`），
  公钥**只做长度断言**（`== cotPayloadPublicKeySize`，384）后原样拷入；
  **驱动不校验公钥归属、不读熔丝、不与镜像内公钥比对**。
- 公钥的构建期来源就是 FMC ELF 的 `publickey` 段（nouveau `extract-firmware-nouveau.py` 用同一批
  bindata label 重建 hash/signature/publickey/image 四段）→ **公钥随镜像走**。
- nova-core（NVIDIA 工程师署名）原文：hash/publickey/signature 是
  "FSP Chain of Trust verification needs these to validate the FMC image"；
  且 `FSP_PKEY_SIZE=384` 允许**更短、补零** → 主机把密钥当**数据块**传，不是"密钥槽 ID"。

**三条间接证据指向"芯片只接受熔丝允许的那组密钥"**：
1. **Debug/Prod 两套签名 + 两把公钥，选择靠熔丝**：`kernel_gsp_ga100.c:44-48` 读
   `NV_FUSE_OPT_SECURE_GSP_DEBUG_DIS`、`kernel_gsp_gb100.c:321-322` 读 `NV_FUSE_ZB_OPT_SECURE_GSP_DEBUG_DIS`，
   据此在 `GspRmFmcGfwDebugSigned` / `...ProdSigned` / `CcFmcGfwProdSigned` 间选择，各 archive 自带独立 `UCODE_PKEY`。
2. **FSP 确实做熔丝校验且失败即判安全启动失败**：`kern_fsp_gb100.c:161-183`
   （`NV_PFSP_FUSE_ERROR_CHECK` = SCRATCH_GROUP_3(3)，失败 → `NV_ERR_SECURE_BOOT_FAILED`）。
   该 32 位校验的具体内容公开材料未说明 `[未确认]`。
3. 全量扫 `swref/published/*/dev_fuse*.h`：与安全相关的熔丝只有 `OPT_SECURE_GSP_DEBUG_DIS` 与
   `OPT_FPF_*_UCODE*_VERSION`，**没有公开的 PKC 公钥/哈希字段**（但驱动从不需要读它，
   可以只存在于 ROM/FSP 视野，不能据此断言不存在）。

**纠正一条流传的说法**：key #37 **不是**"签名测试密钥"，而是 debug **booter 的 AES-128 加密密钥编号**，
与 PKC/RSA 签名密钥无关 `[社区]`。所以"用测试密钥签一个镜像"这条路本身就不成立。

> **关键逻辑澄清**：Q1 若为"不能"，**不否定 Q2 的价值**。
> 攻击者并不需要自签 FMC——只需要让**原厂 FMC** 在处理"主机给的数据/尺寸"时出错
> （例如把主机指定的 FRTS 区域当可信、或地址/长度没有边界检查 → FMC 在 L3 里写错位置）。
> Q1 卡的是"自制镜像"，Q2 卡的是"**骗原厂镜像**"；后者才是现实路径。

#### 7.2.2 "各代是否共用同一把 prod 公钥"的本地测试 —— **未结论**（并发现一个陷阱）

思路：若 `.fwsignature_*` 段里能取到公钥，且各代相同，则"熔丝哈希即便存在也只能是它"→ 实务落到"不能"。

实测（本机 621.01 的 `gsp_ga10x.bin`，6 个族的 4096 B 签名段互相比对）：
- 段结构=**16 B 头**（`ver=1, cnt=2, f1=2248, f2=12`）+ ~2.2 KB 结构化数据 + **约 1.5 KB 全零填充**。
- 各代之间 offset 0–2304 的内容**全部不同**；offset 2304 之后**完全相同**——但那是因为**那里全是零**（`nonzero=0`）。
- 段内出现的 `01 00 01` 是 `01 00 01 00 01` 这种小整数表的重复模式，**不是 RSA 公钥指数**。

⚠️ **陷阱记录**：按 384 B 对齐做哈希时，全零块会让"跨族完全一致"的假象出现（我先看到了 4 个块 sha 相同）。
**比对签名/密钥类数据时必须先剔除零填充块**，否则会把"都是零"当成"都是同一把公钥"。

**结论**：`.fwsignature_*` 段里**没有明文 384 B RSA 模数**，公钥不在这一层可取。
要做真正的 action A，必须从 `nvlddmkm.sys` 里**解压 deflate 后的 `BINDATA_LABEL_UCODE_PKEY`**——
那是独立工作量，本次未做。

### 7.3 已排除

- ~~debug 镜像用公开测试密钥加密~~：key #37 复核无命中 `[社区]`；且无 `TestSig` 标签 `[源码]`。
- ~~`DISABLE_GSPFMC` 跳过 COT~~：silicon 硬拒，enforce 恒 TRUE `[源码]`。
- ~~`0x82380c = 0x00888888` 是 GB 选择器~~：AD107 同值，是通用常量 `[实测]`。

## 8. 止损与执行纪律

### 8.1 明文固件是否可得 —— **部分可得；FMC 本体仍未拿到**（2026-10-29 修正）

> ⚠️ **撤回上一版的一个结论**。上一版写"7 个小镜像 = ACR/FMC 候选，Q2 可开工"。
> 用 `llvm-objdump --triple=riscv64` 实际反汇编后**不成立**，见下表。

`gsp_ga10x.bin` 的 `.fwimage` 是**裁剪过的 ELF 包**（每张图的节头表未随包存储，
`e_shoff` 悬空 → 需先重建最小 ELF 才能反汇编）。12 张图实测：

| 图 | 大小 | 反汇编结果 | 判读 |
|---|---|---|---|
| img09 | 13.6 MB | **4,505,054 条 RISC-V 指令**；含 `0x1fa*`(WPR2/PBUS) 64 处、`0x1100*`(GSP 邮箱) 6 处、`0x82*`(FEAT) 1722 处 | **主 GSP‑RM，明文可读** |
| img10 | 804 KB | 268,444 条指令 | vGPU/插件组件，明文 |
| img07 / img08 / img11 | 32 / 32 / 20 KB | 7,881 / 9,181 / 3,784 条指令，**语法有效** | 小型 RISC‑V 组件，明文 |
| **img00–img06** | 61–70 KB 代码段 | 解码出 18,706 条指令，有效率 37.8%；`<unknown>` 占多数 | ~~不是明文代码~~ → **见 `§8.3`：是明文，只是含 NVIDIA 自定义指令** |

**修正后的结论**：
- **GSP‑RM 是明文**（4.5 M 条指令可读，WPR2/FEAT 立即数都在），但它运行在 FMC **之后**，帮不上"给 FMC 喂坏输入"。
- **FMC/ACR 本体尚未到手**：既不在这个包的明文代码里，也还没从
  `ucodes_ga10x.bin`（37 个低熵段）或 `nvlddmkm.sys`（deflate bindata）里定位出来。
- 所以 `Q2` 的状态从"已解锁"**回退为"未解锁，但有明确的三个待查位置"**：
  ① `ucodes_ga10x.bin` 的明文段（最可能：它就叫 "ucodes"）② 驱动 `.sys` 的 deflate bindata
  ③ `.fwimage` 里那 7 张编码段的解码方式。

**方法论教训（值得写进项目习惯）**：
1. "机器类型 = RISC‑V + 能解析 ELF 头" **不等于**"内容是明文代码"——必须真正反汇编，看指令有效率。
2. 程序头 `p_offset = 0` 是危险信号：它意味着"段"从 ELF 头开始，通常说明这是打包器生成的容器段。
3. 段内"可打印率 48%"且带大段断言串时，大概率是**数据+编码代码**混合，别急着当代码读。
4. **自制启发式检测器必须先跑阳性对照**：我先用"4 字节操作码白名单滑窗"扫，结论是"ucodes 里没有代码"；
   但拿它去扫**已验证含 13.6 MB 明文代码**的 `gsp_ga10x.bin`，最长只找到 2 KB → **检测器本身坏了**
   （RISC‑V 压缩指令 2 字节，4 字节窗口必然跨界）。改用 `llvm-objdump` 自身当解码器后才发现真相。
   教训：**阴性结果必须先被阳性对照校准**，否则"没找到"只是"工具瞎了"。

### 8.2 `ucodes_ga10x.bin` 的首轮代码定位（2026-10-29）

用 objdump 解码有效率逐段扫 37 个低熵段，最高分的三段异常突出（对照组：已知明文 RM = **0.513**，
已知编码块 = 0.378）：

| 段 | 大小 | 有效率 | 判读 |
|---|---|---|---|
| **0x1b50000–0x1b90000** | 256 KB | **0.564** | **真代码**：`auipc`+`addi` 取址、`jal`/`beq` 控制流、`sw zero, -0x630(a4)` 式全局清零、`csrr`×19、**`mret`×1** → 裸机引导级 RISC‑V 镜像 |
| 0x1950000–0x1a20000 | 832 KB | 0.474 | 次高，待查 |
| 0x16d0000–0x1700000 | 192 KB | 0.413 | 待查 |

**状态**：`ucodes_ga10x.bin` 里**确实有明文 RISC‑V 代码**，且已定位到一个强候选（256 KB、含 `mret`/CSR 的引导级镜像）。
但**身份未定**——没有容器索引就无法断言"这就是 FMC/ACR"。下一步要么解出 `NVUCODES` 的条目表
（每条 = target/size/offset，定位到具体引擎），要么用行为指纹（读写 WPR2/邮箱的指令序列）确认。

**注意**：这一条**不改变** `§7.2` 的结论——FMC 明文候选存在，但"是哪一个"和"有没有边界缺陷"都还没答案。

#### 8.2.1 行为指纹结果（2026-10-29）——**"WPR2 写入"是误报**

对 `0x1b50000` 段的 256 KB 做完整反汇编（75,429 条解码行，其中 40,768 条 `<unknown>`），然后按寄存器立即数找指纹：

| 指纹 | 命中 | 判定 |
|---|---|---|
| `sw a5, 0x1fa(a4)` 之类 | 34 处 | ❌ **误报**。前面紧跟 `auipc a4, 0x7d`，所以目标 = `PC + 0x7d000 + 0x1fa`，是**auipc 相对的数据/BSS 偏移**，**不是** WPR2 的 MMIO 地址 `0x1fa824`。我的 grep 把"偏移量"当成了"寄存器地址" |
| `lui 0x1400/0x1403` + `sw …, 0x520/0x524/0x52c` | 多组 | ✅ **真 MMIO 写**，基址 `0x14000000` 量级；但是否为 GPU 寄存器窗口取决于该镜像**被加载到哪个基址**——目前未知 |
| `csrrci/csrw mstatus`、`csrw mtvec`、`mret`、`csrrs/csrrc 0x7d5` | 112 / 1 | ✅ **确证是机器态裸机程序**：有 trap 向量、`mret` 返回、以及 **NVIDIA 自定义 CSR `0x7d5`**（0x7c0–0x7ff 是自定义区间） |

**结论**：这一段**确实是真实的机器态 RISC-V 引导代码**（比上一轮"是代码"更进了一步：有 `mret`/`mtvec`/自定义 CSR），
但**行为归属做不下去**——`auipc` 相对寻址意味着所有地址都是"相对镜像基址"的，
而**镜像基址只有容器索引（NVUCODES 条目表）才给得出**。

**方法论教训（第 5 条）**：反汇编里 grep 立即数找 MMIO 时，**必须先判断指令是 `lui` 还是 `auipc`**：
`lui` 给的是绝对高 20 位（可能是 MMIO），`auipc` 给的是 PC 相对（几乎总是数据段偏移）。
把两者混为一谈会造出"找到了 WPR2 写入"这种假发现。

**当前唯一的真阻塞点**：`NVUCODES` 条目表（每条应含 target / size / offset / 加载地址）。
没有它：镜像切不准、基址不知、引擎归不了属、Q2 无法开始。这已经从"可选"升级为**下一步的唯一目标**。

#### 8.2.2 `NVUCODES` 索引格式：**公开渠道没有，结构反推未收敛**（2026-10-29）

三条尝试与结果：

| 尝试 | 结果 |
|---|---|
| 找公开文档 | 无。`open-gpu-kernel-modules` 的 `nouveau/extract-firmware-nouveau.py`（42 KB）**不构建也不解析** `ucodes_*.bin`（全文无 `NVUCODES`/`ucodes` 命中）→ 该容器是 **Windows 驱动包专有**，Linux 侧用 `gsp_*.bin` + 独立文件替代 |
| 按 0x18 步长解记录表 | 前 7 条合理（`size`=364/368896/379904…），随后归零 → 表不连续 |
| 全文件扫"记录起始"特征并聚类 | 命中 **1220** 条候选，分属 424 个"簇"；最大簇 @`0x4ab0` 有 268 条连续 0x18 记录、次大 @`0x38e0` 87 条、@`0x748` 70 条 → 结构像"**多个分块，每块自带表**"，但块的边界规则未定 |

**一个值得记下的巧合**：候选记录数 **1220**，而头部 `+0x0c` 字段 = **0x4c7 = 1223**。
差 3 条——很可能确实等于记录总数，只是我的模式匹配漏了 3 条（或因零填充误判）。这是下一步唯一的结构线索。

**结论**：索引未破解。继续硬推的性价比已明显下降，建议换路线（见 `§8.2.3`）。

#### 8.2.3 Linux 驱动包实测（2026-10-29）——**没有独立 `fmc-*.bin`**

取 `NVIDIA-Linux-x86_64-610.43.03.run`（440 MB，sha256 `45E2D4C1…2ED392`；payload 是
**zstd 压缩的 tar**，偏移 `0x2737b`，`skip=1022`），解出关键文件后的事实：

| 文件 | 大小 | 结论 |
|---|---|---|
| `kernel/common/inc/nv-firmware.h` | 5,715 B（**MIT**） | **最重要的一条**：`NV_FIRMWARE_CHIP_FAMILY_GB20X = 9`；且 GA10X/AD10X/GH100/GB10X/GB10Y/GB20X/GB20Y **全部共用** `gsp_ga10x` + `ucodes_ga10x` 两个文件名 → **这一代驱动不存在独立的 `fmc-*.bin`**（社区所说的 `fmc-*.bin` 不在本代包里） |
| `firmware/ucodes_ga10x.bin` | **31,744 B** | **空容器**：`NVUCODES` 头（ver=1）+ 之后**全是零**。只在 `NV_VMWARE` 的 bindata 路径用到 → 对定位 FMC 无用 |
| `firmware/gsp_ga10x.bin` | 84,277,400 B | 节结构与 Windows 版同构，但 `.fwimage` 有 **84 MB**（Windows 仅 18 MB）→ 含更多族的镜像 |

Linux `.fwimage` 里扫出 **12 个 RISC‑V ELF64**（与 Windows 版组合不同）：
7 个 libos 型（有效率 ~0.378、CSR 215–251 处）、2 个中型（0.413/0.474）、
主 RM 15.3 MB（0.556）、663 KB（0.579）、20 KB（0.470）。

**"行为指纹"这条路同时判死**：12 个镜像里 **`lui 0x1fa8`（WPR2 基址）命中数为 0**。
合理解释：FMC 访问寄存器用的是**从配置结构载入的基址**，不是绝对立即数——
所以"靠 grep 立即数认引擎"这个方法**在原理上就不成立**，不只是数据问题。

#### 8.2.4 至此，四条廉价路线全部试过并各自有了明确的失败原因

| 路线 | 结果 | 失败原因 |
|---|---|---|
| 公开文档 / nouveau 脚本 | 无 | `NVUCODES` 是 Windows 专有容器，上游不解析它 |
| `NVUCODES` 结构反推 | 未收敛 | 头后是稀疏/分块表，边界规则未知 |
| Linux 独立 `fmc-*.bin` | **不存在** | `nv-firmware.h` 明示各代共用两个文件（`[源码]` MIT） |
| 寄存器立即数指纹 | 判死 | FMC 用配置基址而非绝对立即数，grep 立即数原理上不成立 |

### 8.3 **突破：libos/FMC 代码是明文，且含防御性校验（2026-10-29）**

#### 8.3.1 先纠正 `§8.1` 的错误结论

`§8.1` 说那 7 张镜像"不是明文代码（字符串表+编码代码）"。**这个结论是错的**，证据如下：

- 熵 6.69–6.76 —— **加密/压缩应该是 7.9+**，这个值本身就是明文代码的典型区间；
- 决定性测试：把 `auipc`+`addi` 的目标地址算出来，**127 处精确命中同段内的断言字符串地址**
  （如 `@0xffffffff93001146 → 0xffffffff9300c1d8 = "index < MPU_COUNT"`）。
  加密数据不可能产生这种自洽引用 → **代码是明文**。
- `<unknown>` 的原因（**已于 `§8.6` 查明，此处原判断作废**）：不是自定义指令集，
  而是 **objdump 少了 `--mattr=+c`**（12 张镜像的 `e_flags` 全是 `EF_RISCV_RVC`）
  + 扫掠起点错（从段基址起而非 `e_entry`）+ 把段尾 8 KiB rodata 当代码扫。
  修好后代码区解码率 **100.00%（0 个 unknown）**。

**教训（第 6 条）**：判断"是否明文代码"，**不要只数可解码指令比例**。
正确做法是**验证引用自洽性**（`auipc` 目标是否落在本段字符串/数据上）——
比例低可能只是工具配置不对，而引用自洽是加密数据不可能伪造的。
（补：引用自洽这条判据本身是对的，它确实证明了"明文"；错的是我对"为什么解不出"的解释。）

#### 8.3.2 这批镜像的身份：**libos 内核（FMC/ACR 的运行环境）**

字符串表把模块结构暴露得很完整（全部取自 `0xffffffff9300c000`–`0xffffffff9300d4a0`）：

| 模块 | 文件 |
|---|---|
| 内存管理 | `mm/memorypool.c` `mm/objectpool.c` `mm/pagestate.c` `mm/pagetable.c` `mm/address_space.c` **`mm/softmmu_core.c`** `mm/softmmu_swap.c` **`mm/identity.c`** |
| 内核 | `kernel/init.c` `kernel/partition.c` `kernel/server/server.c` `kernel/sched/port.c` `kernel/ipi.c` `kernel/loader.c` |
| 驱动 | `drivers/dma.c` |
| 运行库 | `common/nvriscv-2.0/sbi.c` |

⇒ 这是 **`libos-v3.1.0`（`uproc/os`）**，FMC/ACR 就是跑在它上面的。"分区式 FMC"在软件侧的形态到此确认。

#### 8.3.3 首批发现的**防御性校验**（对 Q2 不利）

| 断言（源码原文，`[实测]` 段内字符串） | 含义 |
|---|---|
| `physicalAddress + size <= (node->physicalLast+1)` | **物理区间上界校验**（`mm/pagestate.c`） |
| `index < MPU_COUNT` / `idx < MPU_COUNT` | 软 MMU 表索引校验（`mm/softmmu_core.c`） |
| `vaBase <= LIBOS_CONFIG_IDENTITY_MAPS_END` | 恒等映射虚拟地址上界（`mm/identity.c`） |
| `((NvU64)header->kind) < IpiMessageNull` | IPI 消息类型校验 |
| `header->size <= (LIBOS_CONFIG_MESSAGE_PAGE_SIZE - readingPageOffset - …)` | **消息长度上界校验**（`kernel/ipi.c`） |
| `map->size == SWAP_PAGE_SIZE`、`index < tcmPages` | 尺寸/索引校验 |

并在 `mm/identity.c` 的引用点（`0xffffffff930014a6`）反汇编出实际校验逻辑：

```asm
0x148c:  ...                       # 进入校验
0x147a:  add   s8, a1, a0          # s8 = begin + size
0x147e:  bltu  s8, a1, 0x14a6      # 加法回绕 -> 跳断言
0x1492:  ld    s9, 0x8(a4)         # s9 = node->physicalLast
0x1496:  sub   a3, s8, a3
0x149a:  bgeu  s9, a3, 0x14ce      # physicalLast >= end ? 通过 : 落断言
0x14a6:  li    a3, 0xf7            # 断言行号 247
0x14c4:  jal   0xffffffff930060e6  # -> assert/panic
```

**即：这段代码在把物理区间加入恒等映射前，同时检查了"回绕"和"上界"。**
这与 `§7.2` 里"FMC 可能不校验主机给的地址/尺寸"的假设**方向相反**——
至少 identity/pagestate 这一层是有校验的。

**注意边界**：这**不等于** Q2 已被否定。已证实的是"这些模块有校验"；
**未证实**的是"`wprShadow[]` 的填充路径上是否也有校验"（`findAperture(wprShadow[i].begin, …)`
本身就是一条断言，暗示代码**预期**这个查找会成功——预期从哪来的，尚未追）。

#### 8.3.4 已定位 `mm/identity.c` 的恒等映射函数（`0xffffffff930013xx`–`0xffffffff9300161e`）

通过"assert 站点坐标系"（把 56 个 assert 点连同**文件名 + 源码行号 + 断言原文**全部解析出来），
定位到 `findAperture(wprShadow[i]…)` 的引用在 **`mm/identity.c:247`**，紧邻
`vaBase <= LIBOS_CONFIG_IDENTITY_MAPS_END`（**同文件 :261**）。该函数的实际逻辑：

```asm
; --- 循环准备 ---
auipc a2, ..; addi a2, a2, ..    ; a2 = 0xffffffffa300c180   <-- wprShadow[] 起点（BSS）
auipc t5, ..; addi t5, t5, ..    ; t5 = 0xffffffffa300c300   <-- 数组终点（384 字节）
auipc t4, ..; addi t4, t4, ..    ; t4 = 0xffffffffa300ad00   <-- 输出/映射表

; --- 每个 wprShadow[i] ---
0x147a:  add   s8, a1, a0        ; s8 = begin + size
0x147e:  bltu  s8, a1, 0x14a6    ; ① 加法回绕 -> 断言
0x1492:  ld    s9, 0x8(a4)       ; s9 = 该区间的上界（来自镜像内数据 0xffffffff9300d968+8）
0x1496:  sub   a3, s8, a3
0x149a:  bgeu  s9, a3, 0x14ce    ; ② end-base <= limit ? 通过 : 断言
0x14a6:  ... identity.c:247 "findAperture(wprShadow[i].begin, wprShadow[i].size, &apertureId)"
0x14ce:  bnez  s7, 0x15d2        ; 标志位分流
0x14d6:  add   a4, a0, t3        ; t3 = 0xfd
0x14da:  sd    a4, 0x8(s4)
0x14de:  sd    a1, 0x10(s4)
0x14e2:  sd    a0, 0x0(t4)       ; 写入映射表
0x14e8:  bne   a2, t5, 0x1470    ; 循环
...
0x15e8:  bgeu  t1, a5, 0x1614    ; ③ vaBase <= IDENTITY_MAPS_END
0x15ec:  ... identity.c:261 "vaBase <= LIBOS_CONFIG_IDENTITY_MAPS_END"
```

**判读**：
1. **`wprShadow[]` 位于 BSS（`0xffffffffa300c180`），是运行期状态**，不是主机直接传进来的缓冲区；
   它由 libos 自己在引导阶段填好，然后在这里被遍历、逐个建立恒等映射。
2. 该路径有**三层检查**：加法回绕（`bltu`）、区间上界（`bgeu`）、虚拟地址上界（`bgeu` + 常量）。
3. `findAperture(...)` 那条断言是**自洽性检查**（"每个 WPR shadow 都必须能落进某个 aperture"），
   失败即 panic，属于 fail-safe 而非可利用的越界。

**对 Q2 的意义（诚实版）**：这是又一层"写得很防御"的证据。
到此为止，**所有能静态看到的路径都有边界校验**，没有出现"主机给什么就信什么"的写法。
`§7.2` 里"FMC 不校验主机输入"的假设，目前的支持度**明显下降**。

**仍未追的问题**（下一步）：
`wprShadow[]` 这个 BSS 数组**由谁填、从什么来源填**——若来源是主机可影响的
`GSP_FMC_BOOT_PARAMS`/WprMeta，则需检查填充侧的校验强度（目前只看到消费侧的）。

#### 8.3.5 追填充侧：**未得到结论，并暴露了一个硬限制**

做法：全镜像扫描所有 `auipc` 解析到 `wprShadow[]` BSS 区间（`0xffffffffa300c180`–`0xffffffffa300c300`）
的引用点。

**结果：只有 2 处，且都在消费侧同一函数内**（`0xffffffff93001432`、`0xffffffff9300144c`）。
**但这个阴性结果不能当结论**，原因见下。

**架构上的重新认识（比结果本身更重要）**：libos 的 assert 表显示它是一个**完整的微内核**——
`KernelTaskCreate` / `KernelPartitionParentPort` / `KernelPortAllocate` / `KernelTaskHandleTableCreate`
/ `KernelRootfsMountFilesystem(imagePhysical)` / `KernelElfMap(addressSpace, initElf, …)` /
`KernelTaskRegisterObject` / IPI / server。⇒ **ACR/FMC 的"应用层"很可能是 libos 拉起的独立 ELF 任务**，
而不是与内核同镜像。所以"FMC 代码"是**两层**：libos 内核 + ACR 任务镜像。
继续审计必须先确定是哪一层、哪一张图。

**"硬限制"已解除（`§8.6`）**：原先以为解不出的 62% 是自定义指令，实为 objdump 特征集缺省导致。
修正后代码区 **100% 可解码**，所以**唯一真正未解的仍是密码学那一层**，不是工具层。

**阶段性判断**：到此为止，能静态看到的每一层（`identity.c`、`pagestate.c`、`softmmu_core.c`、
`ipi.c`）**都有边界/回绕/长度校验**。`Q2`（"FMC 不校验主机输入"）的假设**支持度持续下降**。
这与全局结论一致：50 系的锁不是"输入校验写漏了"这种类型的问题。

**当前状态（诚实版）**：libos/FMC 的代码**已到手且是明文**（`§8.3`），
"是哪一个二进制"仍靠推理（`libos-v3.1.0` 标识 + WPR/identity 相关断言，高置信度但非确证），
但**加载基址与 SKU 归属**仍未知——这不再是"能不能看"的问题，而是"对应关系"的问题。
`Q2` 已**部分开工**：已能证明 identity/pagestate 层有回绕+上界校验（对"FMC 完全不校验"的假设不利）；
尚未追的是 `wprShadow[]` 的填充路径。

继续往下的两条重路：① 追 `wprShadow[]` ← `GSP_FMC_BOOT_PARAMS`/WprMeta 的数据流（纯静态，**推荐**）；
② 硬件在环动态观测（需专用研究卡）。

### 8.4 **决定性发现：FMC 镜像本身在 MIT 源码里，且它是加密的**（2026-10-29）

#### 8.4.1 FMC 不是从固件包里猜出来的，它有精确出处

`open-gpu-kernel-modules` 的生成源码里，每个芯片族都有**独立的 FMC bindata 文件**：

```
src/nvidia/generated/g_bindata_kgspGetBinArchiveGspRmFmcGfwProdSigned_GB20B.c
// FUNCTION: kgspGetBinArchiveGspRmFmcGfwProdSigned_GB20B("BINDATA_LABEL_UCODE_IMAGE")
// FILE NAME: kernel/inc/gspcc/bin/g_gsp_gb20b_dyn_prd_gfw_image.bin
// COMPRESSION: NO
// DATA SIZE (bytes): 212296
```

各族的 IMAGE / HASH / SIG / PKEY **四段都在同一个 .c 文件里**（按 label 分开）。实测：

| 族 | IMAGE 大小 | IMAGE 熵 | SIG 大小 | PKEY 大小 | 签名体制 |
|---|---|---|---|---|---|
| ProdSigned **GB20B** | **212,296** | **7.999** | 384 | 384 | **RSA-3K** |
| ProdSigned **GH100** | 165,448 | **7.999** | 384 | 384 | **RSA-3K** |
| ProdSigned **GB100** | 197,960 | **7.999** | 96 | 97 | **ECDSA P-384**（`0x04‖X‖Y` = 97） |
| ProdSigned **GB202** | 287,304 | **7.999** | 96 | 97 | **ECDSA P-384**（同上） |
| DebugSigned GB20B | 212,296 | 7.998 | 384 | 384 | RSA-3K（**与 prod 不同钥**） |

#### 8.4.2 三条硬结论

1. **FMC 影像是加密的**（熵 7.999，零字符串、零 ELF 头）。载荷从偏移 `0x48` 起就是密文。
   ⇒ **`§8.3` 里"FMC 代码是明文"的说法必须限定范围**：那 7 张带 libos 字符串的镜像是
   **`.fwimage`（GSP-RM 包）内部组件**，**不是 FMC 本体**。FMC 本体是另一个独立的、加密的 bindata。
2. **各族公钥不同**：GB20B ≠ GH100 ≠ GB100/GB202；但 **GB100 与 GB202 的公钥完全相同**
   （`sha256[:16] = af870e5dde972840`）→ 说明公钥是**按族（甚至按族组合）分配**的，不是"一把全球通用"。
3. **Debug 与 Prod 是两把不同的钥**（同尺寸、不同内容）。

#### 8.4.3 对 Q1（公钥信任锚）的意义 —— **实务结论落到"不能"**

- 若 FSP 真的"无条件相信主机送来的公钥"，那么**按族分配密钥、区分 debug/prod** 这两件事在工程上毫无意义。
  这种密钥结构**只有在"芯片侧知道该用哪把钥"时才有价值**——即熔丝/ROM 侧存在族→密钥的绑定。
- 攻击者的处境：即便让主机送自己的公钥，也要**伪造 NVIDIA 对应族的私钥签名**。
  RSA-3K / ECDSA-P384 都不可行。
- 置信度评级：这是**结构性旁证（强），不是逐字证据**——FSP 内部的比较逻辑仍未公开 `[未确认]`。

#### 8.4.4 对 Q2（FMC 边界校验）的意义 —— **静态路径被加密堵死**

FMC 不透明 ⇒ `§8.3` 里对 `identity.c`/`pagestate.c`/`softmmu_core.c`/`ipi.c` 的审计
**只覆盖了 `.fwimage` 里那些 libos 组件，覆盖不到 FMC 本体**。
要继续 Q2 只有两条路：① 让硬件解密（不可及）；② 硬件在环动态观测（需专用研究卡）。

**但这轮仍有净收益**：我们现在**手里有 GB20B FMC 的精确字节（212,296 B）+ 它的 hash/sig/pkey**，
这恰好是"自造镜像喂给 FSP"实验（原 B 方案）所需要的全部外围材料——将来换专用卡时可精确设计。

### 8.5 代际分界点的确切位置：40 系的 booter 用**非机密测试密钥**加密，50 系的 FMC 不行

问题："40 系怎么解密 FMC？" —— **答案是：40 系不用解 FMC；它解的是 booter，而那把钥匙是 NVIDIA 自己给的非机密测试密钥。**

#### 8.5.1 先纠正本节的旧版（整文件熵不可作为判据）

旧版说"30/40 系 booter 是明文（熵 5.49）"——**错**。整文件熵是**明文头 + 密文 + 零填充的混合值**。
按段测熵后真相清楚（AD102 / GA102 的 `IMAGE_DBG`、`IMAGE_PROD` 实测）：

| 区段 | 大小 | 熵 | 判定 |
|---|---|---|---|
| `[0x0000, 0x0100)` NS 前导 | 256 B | **0.000** | 明文（Falcon 非安全前导） |
| **`[0x0100, 0x8700)` HS 代码** | **34,304 B** | **7.790 / 7.792 / 7.995** | **AES 密文** |
| `[0x8700, 末尾)` 数据/填充 | 22,272–25,856 B | 0.105 / 0.418 | 明文/零填充 |

**34,304 字节**这个数字与社区公开的"secure code 34,304 B、AES-128-ECB 从 `0x100` 起"完全一致。

#### 8.5.2 40 系"能解密"的真正原因

`[社区]` 一手结论（cmp170hx 项目文档）：**debug 与 production 的 booter 镜像含完全相同的明文代码，
只有 AES 密钥不同；debug 镜像用非机密的"编号测试密钥"加密，编号 = 37**。

本机独立验证，**吻合**：GA102 的 `IMAGE_DBG` 在 `0x89c0` 处出现了该密钥下的密文尾标记
`71 7D 14 94 EA CA 31 7F F1 06 19 52 58 B3 83 77`（这是"解密后应回归全零"的零填充密文），
而 `IMAGE_PROD` 没有。

⇒ **所以不是"40 系有解密能力"，而是 NVIDIA 交付的 debug 副本用的是非机密测试钥匙。**
社区用 key #37 解出 debug 镜像，即得到与 prod 相同的代码，再反汇编挖 ROP gadget。

#### 8.5.3 为什么 50 系不行（同样的手法失效）

| 环节 | 30/40 系 | 50 系（GB20B） |
|---|---|---|
| 对应产物 | Falcon **booter ucode**（`IMAGE_DBG`/`PROD` 都在 MIT 源码里） | **FMC**（`GspRmFmcGfwDebugSigned_GB20B` 等，也在 MIT 源码里） |
| 产物大小 | 56,832 / 60,416 B | **212,296 B** |
| 密文起止 | `[0x100, 0x8700)` = 34,304 B | `[0x48, 0x33d48)` ≈ 212 KB，**几乎全载荷** |
| 熵 | 7.79（局部） | **7.998**（整载荷） |
| **key #37 尾标记** | **有**（GA102 @`0x89c0`） | **无**（debug 版实测未找到） |
| debug vs prod 载荷差异 | 同一明文、不同密钥 | **99.5% 字节不同** |
| 验签体制 | Falcon AES-MAC / RSA | **RSA-3K / ECDSA P-384**（见 `§8.4`） |

⇒ **50 系的 debug 副本不是用那把非机密测试钥匙加密的**（很可能是熔丝派生密钥或另一套方案），
所以"解 debug 副本 → 得到 prod 明文代码"这条 40 系的通路**在 50 系上不成立**。

#### 8.5.4 并行研究佐证（同题目、独立得出）

`[社区]` `phiraml/gpu-unlock-blackwell`（GB20x 移植研究）独立得出同一结论且更进一层：
- 实测 RTX 5090（GB202）FP16→FP32 累加率 **0.676**（我们文档早前记录的第三方 0.67 吻合）；
- **"公开不存在 GB20x booter"**：`kgspGetBinArchiveBooterLoadUcode` 的 HAL 只有
  TU102/TU116/GA100/GA102/AD102 变体，其余（含 Blackwell）落到共享 fallback `_80f438`，
  而该 fallback 在开源源码里是 **NULL 桩**（对象单独生成）→ GB20x booter 只存在于闭源 `nv-kernel.o`。
- 他们的"下一步 = 拿到解密的 GB20x debug booter"，**在本项目看来方向需要修正**：
  Blackwell 根本没有 booter 这一形态（`bPartitionedFmc`），对应物是 FMC；
  而 FMC 的 debug 副本不是 key #37 加密的（本节实测）。**这是本项目能补上的一块。**

### 8.6 解码问题已彻底解决：**不存在"自定义指令集"**（第 1 线子代理结果）

#### 8.6.1 根因（按贡献排序）

| # | 原因 | 证据 |
|---|---|---|
| 1 | **`llvm-objdump --triple=riscv64` 默认是裸 RV64I，C 扩展是关的** | 12 张镜像的 `e_flags` **全部 = `0x1` = `EF_RISCV_RVC`**（psABI 规定的"C 已启用"标志）；而 objdump **不读 `e_flags`** 来选特征集 |
| 2 | **扫掠起点错**：RX 段 `p_offset=0`，段基址上放的是镜像自己的 ELF 头，而 `e_entry = 段基址 + 0x1000` | 从段基址扫，LLVM 会从 `7f 45 4c 46` 开始解码且**永不重同步**到 `+0x1000` 的指令网格 |
| 3 | **把 rodata 当代码扫**：段尾 8 KiB（`0x9300c000–0x9300e000`）是 libos 源路径 + 断言串，可打印率 90–96% | 整段 403 个 unknown 里有 **384 个**在这里 |

#### 8.6.2 修正后的覆盖率

| 口径 | token | 默认 | `--mattr=+m,+a,+c` |
|---|---|---|---|
| **代码区 48 KiB**（段内 `0x1000–0xd000`） | 16,162 | 42.43%（9,305 unknown） | **100.00%（0 unknown）** |
| 整段 61,440 B | 18,706 | 37.84% | 96.63%（最大特征集 97.85%） |

原来的 62.16%（18,706 / 11,627）被精确复现——**问题在调用参数，不在目标文件**。

#### 8.6.3 四个假设的判决（负面结果同样记档）

| 假设 | 判决 | 关键数字 |
|---|---|---|
| custom-0/1/2/3 opcode（0x0B/0x2B/0x5B/0x7B） | **证伪** | 代码区 **0 次**；整段仅 3 次且是 rodata 里的 ASCII（`" + Li"`）；img09（4.5 M 指令）前 10 MB **100% 覆盖、0 次** |
| 非标准字段位置 | **证伪** | `auipc`+consumer **855/855 = 100%** 落进程序自己的段（RX 221 / RW 494 + BSS 尾部 140）；**150 对精确命中 libos 断言串** |
| 变长前缀扩展 | **证伪** | 长度直方图只有 `{2 字节: 9,256, 4 字节: 6,906}`；`0x1F/0x3F/0x5F/0x7F` 出现 0 次 |
| 罕见标准指令被误标 | **成立** | 9,305 个 unknown 里 **9,256（99.47%）是 16 位 RVC**；剩 49 个是 `mul/div/rem` 族 |

#### 8.6.4 三个会污染后续所有统计的陷阱（教训第 8 条）

1. **LLVM 把 16 位指令打印成"未压缩别名"**（`4515`→`li a0,5`、`8082`→`ret`）。
   按 `c.` 前缀统计压缩指令会得 0.4%，**真实占比 57.36%**（必须按编码长度算；或加 `-M no-aliases`）。
2. **`auipc` 的立即数在 objdump 输出里是未移位的 20 位字段，必须 `<<12`**。
   我之前"653 对中只有 30% 落段内"就是因为漏了这次左移、且只查了 RX 段（实际 494/715 的合法目标指向数据段）。修正后 = 100%。
3. **跳转目标对齐率不能用来区分特征集**（LLVM 的步进长度只由原始比特决定，与 `-mattr` 无关）。
   真正能证明"必须存在 16 位指令"的是：3,089 个直接目标里 **1,469 个（47.3%）落在 ≡2 (mod 4)** 的地址上——纯 RV64I 不可能。

#### 8.6.5 真正的"自定义"在 **CSR**，不在 opcode —— 而且正好是 Q2 要的东西

启动存根语义（全部正常解码）：

```asm
9300002a: csrw 0x5ca, 8            ; 选择子 / 索引
9300002e: csrw 0x5cc, 0x93000000   ; 基址
93000048: csrw 0x5cb, 0x93000001   ; 上界（带标记位）
93000034: csrw 0x5ce, 0x1000       ; 大小
93000040: csrw 0x5cf, 0x40028      ; 属性
93000052: csrs satp, t0
```

即 **libos 的软件 MMU 通过自定义 CSR 编程 MPU 窗口**：`0x5ca`=索引、`0x5cb`=上界、`0x5cc`=基址、
`0x5ce`=大小、`0x5cf`=属性（与 `index < MPU_COUNT`、`softmmu_core.c`、`identity.c` 完全吻合）。
另有 `0x5c0`（`ecall` 后立即写、上下文保存时读回，疑似陷入 CSR）与 `0x8d0`（循环内 `+0x40` 步进，疑似 softmmu 表窗口）。
**语义均 `[未确认]`。**

> 这条对 Q2 有直接价值：今后若要审"主机给的地址/尺寸如何进入 MPU 窗口"，
> **这就是看门狗**——只要盯住 `csrw 0x5ca..0x5cf` 的写入点，就能看到窗口是如何被配置的。

#### 8.6.6 今后统一使用的命令

```powershell
llvm-objdump -d --triple=riscv64 --mattr=+m,+a,+c,+zicsr,+zifencei -M no-aliases <file>
# 且 .text 必须从 e_entry 起，不要从段基址起
```

验收判据：**代码区 0 个 `<unknown>`** + 3,089 个跳转目标 100% 落在指令边界。

交付物：`gb206-fw/tools/nvrx.py`（`info`/`extract`/`analyze`/`sweep`/`batch`）、
`gb206-fw/reports/nvriscv-decode.md`、`reports/nvrx-coverage.csv`、`reports/nvrx-img00-code.json`。

### 8.7 `.fwimage` 里有权威清单：12 张镜像的身份已确定（第 2 线子代理结果）

#### 8.7.1 清单本身

Linux 容器 `.fwimage` 内偏移 **`0x6d000`** 有一张带 magic **`0x81b26a705c10e14d`** 的镜像清单，
13 个条目，且每个条目的 `(rel_offset, filesz, prot, vaddr)` 与内嵌 ELF 的 program header
**逐字段吻合**（`rel` 差 0x6d000 全中）。所以真实名字是：

`kernel_{ga10x, gh100, gb10x, gb10y, gb20x, gb20y, gr10x}.elf` +
`debug.elf`、`init.elf`、`rm.elf`、`vgpu.elf`、`mnoc.elf` + 数据块 `rm.bindata.bin`。

**跨包验证**：Windows 包（`nv_dispi.inf…` 目录，`.fwversion = 620.67.01`，`.fwimage` 18,210,816 B；
Linux 是 610.43.03）的清单 `rel` 与之前手工切的 12 个偏移**逐一精确对应**（脚本输出 `identical: True`）
⇒ **Windows W00–W11 ↔ 名字是被证明的，不是推断的。**

#### 8.7.2 GB206 的精确归属

**GB206 = `kernel_gb20x.elf`** = Linux **L04 @`0x10d000`** / Windows **W04 @`0x12e000`**。

- `nv-firmware.h`：`NV_FIRMWARE_CHIP_FAMILY_GB20X = 9` → `"gb20x"`；容器另有独立的
  `.fwsignature_gb20x`（4096 B，非零 1546 B，sha1 `55ad7355…`，与 `gb20y` 的 `9ae2ff4a…` 不同）。
  **12 个家族签名共用同一份 `.fwimage`** ⇒ 家族区分不在载荷里，在签名/元数据里。
- **设备号表在 `rm.elf` 里，不在内核里**：W09 va `0x1acc97c` = `00 2d | 04 2d | 1c 2d | 9c 2d`
  —— **含 `0x2d04`（本机 RTX 5060 Ti）**；va `0x1b176a4` = `00 2d | 02 2d | 06 2d | 07 2d | 10 2d`。
- 明确**没找到**：24 张镜像里 `0x1b6000a1` / `0x1b6` / `"GB20"` / `"DEVICE_ID"` / `"CHIP_ID"`
  / `"bootArgs"` 全部零命中；7 张内核 `mret`=0、csr 分布同构，无 boot-args 分支迹象。
  ⇒ 从"设备号 → 家族"的映射逻辑在 `rm.elf`（或更外层），不在内核里。

#### 8.7.3 7 张"同构"镜像 = **每芯片家族一份 libos 内核**（不是每引擎/每 SKU）

度量要点（方法本身踩过坑）：这些段 **60–70% 是 2 字节压缩指令**，按 4 字节对齐比较会假报"85% 不同"。

- 文本逐字节只共享 **33–61%**，但指令普查几乎一致（同尺寸组总数差 −0.74%…+0.35%；W01/W02 都恰好 23,033 条）
  ⇒ **同源代码重编译，不是同一二进制**。
- 数据段 **99.4–99.9% 相同**，差异只在两处：`va 0xffffffffa300a000–0xae68` 的一小片指针/尺寸表
  （`0xffffffffa3015000`/`0x16000`/`0x18000` + `0x40`，且在各图间整体位移 8 B），以及 R 段尾部追加。
- 差异的**语义**（全是配置开关）：① 索引 0 用 `drivers/dma.c`，索引 1–6 用 `drivers/gdma.c`+`extintr-v2.c`；
  ② 索引 4/5（**gb20x/gb20y**）`init.c` 断言点 15–16 → **27–28**；③ 只有 Windows 索引 1–6 有
  `softmmu_swap` 断言（Linux 版没有 `softmmu_core/softmmu_swap`，改带 `sched/heartbeat.c`）；
  ④ 行列号不同（sbi.c 56 vs 52、objectpool 122 vs 106、port.c 1165 vs 1162）。

#### 8.7.4 权威负面结论：**两张包里都没有 ACR/FMC 镜像**

- 清单里没有 ACR/FMC 条目。`ACR` 只出现在 HDMI **Audio Clock Regeneration**（`hdmiProgramFrlAcrWar_GA102`）
  与 RM regkey（`RmUseAutoAcr`/`RMAcrExecuteOnSec2`…）；`FMC` 只出现在错误码名 `FLCN_ERR_FMC_BOOT_CHECK_FAIL`。
- **Windows 包可判死**：两个数据块都是明文且无 ELF magic——
  `rm.bindata.bin` 32,768 B（熵 1.742，近全零）、`rm.data.bin` 1,703,936 B（以 `NVDUMPCONFIGSIG` 开头，
  是 register dump config），都没有 ACR/FMC/falcon/ucode。
- 只有 Linux 的 `rm.bindata.bin`（64,512,000 B，熵 **8.0000**，无 magic）无法静态判定，
  但对照 Windows 侧更可能不是引擎固件容器。
- ⇒ **与 `§8.4` 完全一致**：FMC 不是"包里的某张图"，而是那个**独立的、加密的 212 KB bindata**。
  两条独立路线得出同一结论，这条现在可以当定论。

#### 8.7.5 分层判定

| 层 | 张数 | 特征 | 置信度 |
|---|---|---|---|
| **内核**（libos） | 7 | X 段 `0xffffffff92fff000`、RW `0xffffffffa3000000`、`entry = X_vaddr+0x1000`、`sret` 6–7、`wfi`=1、csr 289–379、**无 PT_TLS**、含 `KernelElfMap`/`findAperture`、`mret`=0 | **0.97** |
| **应用** | 5 | X 段 `0x01000000`、entry 在 text 内、**有 PT_TLS**（仅这 5 张）、`ecall` 1–7（rm 268/321）、无 `.c` 断言表 | **0.85** |
| **stage-0 加载器** | 1 段 | `.fwimage` `0x0–0x6e000`（450,560 B，非 ELF），入口在偏移 0，含 `kernel_<fam>.elf` 名字数组 @`0x3b38` + 7 个"返回家族文件名"的小函数 | 0.8 |

`init.elf` 里能直接读到它在拉起别人：`"rm.elf"`、`"vgpu"`、`"mnoc"`、
`"Partition spawned as RM Partition"`、`"Failed to receive GspFwTaskMappings"`。

#### 8.7.6 对既有假设的两处修正

1. 所谓 "BSS 124–155 KB" 实际是**文件里有内容的 RW PT_LOAD**（`filesz == memsz`），是 rodata/data，
   **真 BSS = 0**。
2. "已确认 libos 的 `filesz = 61440`"是 **Windows 版**；Linux 版是 53248/57344。

### 8.8 更正记录（每次改判的原因与触发证据）

| # | 曾经的结论 | 改判为 | 触发证据 |
|---|---|---|---|
| 1 | `0x82380c` 是 GB 专属选择器 | 通用常量 | AD107 同值 |
| 2 | 7 张镜像"不是明文代码（字符串+编码代码）" | **是明文** | `auipc`+`addi` 精确命中段内断言串（127 处） |
| 3 | "FMC 代码是明文，Q2 可开工" | **FMC 是密文** | 从 MIT bindata 提取真实 FMC，熵 7.999、零字符串 |
| 4 | 那 7 张含 libos 串的镜像"就是 FMC" | **是每家族一份的 libos 内核**（非 FMC） | `.fwimage` 清单给出真实文件名 |
| 5 | `<unknown>` 源于 `nvriscv` 自定义指令集 | **不存在自定义指令集**，是 objdump 缺 `--mattr=+c` | 12 张镜像 `e_flags = EF_RISCV_RVC`；加 `--mattr` 后 100% 解码 |
| 6 | `wprShadow[]` 的"BSS" | RW PT_LOAD（rodata/data），**真 BSS = 0** | `filesz == memsz` |
| 7 | 30 对 auipc 里仅 30% 落段内 | **100%** | 漏了立即数 `<<12` 且只查了 RX 段 |

**教训总纲**：本项目的多数错误来自**工具配置与统计口径**，而非固件本身。
凡"扫不到/比例异常"的结论，先自检工具，再下判断。

### 8.9 GB206 → 家族的查表逻辑（已解出结构，`rm.elf`）

在 `rm.elf` 全量反汇编（4,505,054 条指令，零 `<unknown>`）里流式扫描，找到 **25 处**对
设备号表区域（`0x1acc900`–`0x1acd200`）的引用，集中在 `0x110e2xx`–`0x112exxx`。

**表结构**：定长 `0x14` 字节记录 = `{ u32 num_valid_ids; u32 deviceIds[4]; }`，连续排列：

| 记录地址 | num | deviceIds |
|---|---|---|
| `0x1acc960` | 1 | `0x0360, 0x0364, 0x037c, 0x03fc` |
| **`0x1acc974`** | **4** | **`0x2d00, 0x2d04, 0x2d1c, 0x2d9c`** ← 本机 **RTX 5060 Ti = `0x2d04`** |

**查表代码**（全部正常解码，含边界检查）：

```asm
0x110ef20:  slli  a5, a3, 0x20
0x110ef24:  srli  a3, a5, 0x1e        ; a3 = (idx & 3) << 2   —— 索引按 4 字节缩放
0x110ef28:  auipc a5, 0x9be
0x110ef2c:  addi  a5, a5, -0x5b4      ; a5 = 0x1acc974（该家族的记录基址）
0x110ef30:  add   a5, a5, a3
0x110ef32:  lw    s1, 0x4(a5)         ; s1 = record->deviceIds[idx]   ★
0x110ef34:  ld    a5, 0x148(a6)
0x110ef38:  ...
0x110ef42:  jalr  a5                  ; 调用 HAL
...
0x110eef2/0x110ef30 之前统一有：  li a5, 0x3 ; bltu a5, a3 -> 错误分支   —— 索引上界检查
```

**判读**：
1. 设备号 → 家族的映射是**按记录表 + 有界索引**做的（`idx ≤ 3` 检查后才访问），不是线性搜索、也没有无界解引用。
2. `0x2d04` 明确落在 `num_valid_ids = 4` 的那条记录里；同组 `0x2d00/0x2d1c/0x2d9c` 属同一家族。
3. **尚未做**：把"这条记录 ↔ `kernel_gb20x.elf`"这一环闭合（需要找到选择 kernel 文件名的上层函数，
   即 `.fwimage` 里 stage-0 加载器那 7 个返回家族名的小函数，或 `rm.elf` 调用它们的路径）。
   目前是"结构已明、命名未连"——**高置信但非闭环**。

### 8.10 收尾：这份分析能支撑的结论

1. **RTX 50 系在当前形态下不可解锁**，原因不是"没找到入口"，而是**入口的构造材料不存在**：
   40 系能做出 V67 payload，前提是 **NVIDIA 用非机密测试密钥 #37 加密了 debug booter，而 debug 与 prod
   的明文代码相同**（`§8.5`）；50 系的对应阶段是 FMC，其 debug 副本**不含 key #37 标记**，
   载荷与 prod 有 **99.5%** 字节不同 ⇒ 同一条"解 debug 得 prod"通路不成立。
2. **没有任何已公开的免验签路径**（`kfspGspFmcIsEnforced`/`ksec2GspFmcIsEnforced` 恒 TRUE；
   `DISABLE_GSPFMC` 在 silicon 上硬拒；debug 只切换签名密钥）。
3. **Q1（公钥信任锚）实务结论"不能"**：各族密钥不同、debug≠prod，攻击者仍需 NVIDIA 私钥。
4. **Q2（FMC 边界校验）静态路径被加密堵死**；能看到的每一层（identity/pagestate/softmmu/ipi）都有校验。
5. **本机 override 熔丝未关死**（`0x8203f0 = 0`），门在结构上还开着——但开门的钥匙（L3 代码执行）拿不到。
   这一条决定了：若将来 NVIDIA 泄露/降级了 FMC 交付形态（例如某代恢复明文），门会立刻重新可及。

### 8.11 外部研究对照 + 未来重新评估的触发条件

#### 8.11.1 同领域公开项目（`[社区]`，外部内容，仅作对照与线索）

| 项目 | 覆盖 | 与本项目的关系 |
|---|---|---|
| [Zagitta/gpu-unlock](https://github.com/Zagitta/gpu-unlock) | Ampere 张量速率解锁（含 *How Ampere was unlocked*） | 方法论源头：payload 容器格式、kmod 时序 |
| [JustAResearcher/gpu-unlock-ada](https://github.com/JustAResearcher/gpu-unlock-ada) | Ada AD102/AD103 | 40 系直接前身 |
| [nlzy/turing-unlock](https://github.com/nlzy/turing-unlock) | Turing | 最早一代 |
| TOTORONG/AD103_win_unlocker | AD102 payload 与 booter 分析 | Windows 侧实现 |
| [Consensus-Protocol/cmp170hx](https://github.com/Consensus-Protocol/cmp170hx) | CMP 170HX（GA100）全链路 wiki + [MRMCD 2026 演讲](https://talks.mrmcd.net/2026/talk/ZDRJLV/) | **最完整的一手技术档案**：booter IMEM 函数图、PLM 语义、签名缓冲溢出、key #37 说明 |
| [phiraml/gpu-unlock-blackwell](https://github.com/phiraml/gpu-unlock-blackwell) | **GB20x 移植研究（与本题同题）** | 见 `§8.5.4`；其"下一步 = 拿 GB20x debug booter"的方向需按 `bPartitionedFmc` 修正 |

`[社区]` 新闻侧同向：2026-10 有报道称 50 系的 tensor 限制"做了硬件级修复"
（[17173 转载](https://news.17173.com/content/10272026/180129132.shtml)），与本项目"固件交付形态已变"的判断一致。

#### 8.11.2 唯一还没被否掉的技术方向：**恢复 `csecret`**

`[社区]` CMP 170HX 文档把三条路线列为"均未成功、均需电压毛刺硬件"：

| csecret | 能力 | 若恢复意味着什么 |
|---|---|---|
| `secret(6)` | 解密 ECB 固件块 | **可直接解出明文固件 + booter 代码**（该文档称约 121.7 KB） |
| `secret(2)` | 伪造内容 MAC | 可伪造 CFG1 内存解锁 / PCIe 速率解锁所需的 MAC |
| `secret(0)` | debug 旁路 | 可用带 `SKIP_VBIOS_SIG` 的 HULK 证书 |

本项目判断：**这是 50 系当前唯一没被证否的方向**，但需故障注入（电压毛刺）设备与专用卡，
属实验室级别；且 50 系的 FMC 密钥是否由 `csecret(6)` 派生，仍 `[未确认]`。

#### 8.11.3 未来值得重新评估的触发条件（出现任意一条即可重开本题）

1. **有人公开恢复出 `csecret`**（尤其 `secret(6)`）→ 立刻回到 `§8.4` 试解 FMC 密文载荷；
2. **某个族的 FMC debug 副本出现 key #37 尾标记** → 说明测试密钥方案也扩到了 FMC，`§8.5.3` 结论失效；
3. **驱动里新增 GB20x `BooterLoadUcode` HAL 变体**（现在落到 NULL 桩 fallback）→ 说明 NVIDIA 为 Blackwell
   重新引入独立 booter，40 系那套方法论可能复活；
4. **任何族的 FMC 交付形态退回"明文 + 签名"** → 静态挖 gadget 立刻可行；
5. **有人证明 FSP 不校验公钥归属**（推翻 `§8.4.3` 的结构性旁证）→ Q1 结论失效，回到自签路径；
6. **FSP/ROM 内部验签逻辑被公开**（固件 dump + 反汇编）→ 可把 `§8.4.3` 的旁证升级为逐字证据。

#### 8.11.4 本项目已有的可复用资产（换卡/换代时直接可用）

- **只读冷值采样链**：`nv-uefi-unlocker` 的 `ssdiag` + UEFI 采样器 + `docs/cold-values.md` 的 GB206 节；
- **固件分析管线**：`gb206-fw/tools/nvrx.py`（正确的 `--mattr` 调用、覆盖率统计、镜像提取）；
- **镜像身份映射**：`.fwimage` 清单结构（magic `0x81b26a705c10e14d` @`0x6d000`）+ 12 张图 ↔ 真实文件名；
- **FMC 外围材料**：`gb206-fw/gb20b-fmc/`（image + hash + sig + pkey），可直接用于将来的实验设计；
- **分析纪律**：读回是唯一判据、STOP 后不重试、异常即断电、跨族移植=重抽重审。

### 8.12 其余纪律

1. **Q1（公钥信任锚）仍是第一位的判据**：若公钥不被熔丝约束，则主机自签 FMC 即成立，其余分析都不必要；
   目前的结构性旁证指向"被约束"（`§8.4.3`），故转入 Q2。
2. **匹配 ASIC**：7 张内核镜像已确认为**每芯片家族一份**（`§8.7.3`），GB206 对应 `kernel_gb20x.elf`
   （Linux L04 / Windows W04）；任何跨族套用都要"重抽重审"。
3. **任何写操作（发 COT / 写 mailbox / 改熔丝）换专用研究卡**，主力 5060 Ti 不做；
   本项目宪法：读回是唯一判据、STOP 后不重试、异常即断电。
4. 合规：只在自有硬件研究；不分发 NVIDIA 固件/密钥；不发布可武器化工具。

## 9. 参考

- 本项目实测：`nv-uefi-unlocker/docs/evidence/m1-gb206-5060ti/report.md`、`docs/cold-values.md`（GB206 节）
- 一手文档：<https://docs.kernel.org/gpu/nova/core/fsp.html>、<https://docs.kernel.org/gpu/nova/core/falcon.html>
- 一手源码（MIT）`open-gpu-kernel-modules@57130a27`：
  - `kernel/gpu/fsp/arch/hopper/kern_fsp_gh100.c`（COT 组包/发送、EMEM、FRTS、状态机）
  - `kernel/gpu/fsp/kern_fsp.c`（MCTP/NVDM 组包、收发、regkey 覆盖）
  - `inc/kernel/gpu/fsp/kern_fsp_cot_payload.h`（COT 11 字段）
  - `kernel/gpu/gsp/kernel_gsp_booter.c:4962-4976`（bPartitionedFmc → booter 消失）
  - `kernel/gpu/gsp/arch/hopper/kernel_gsp_gh100.c`（BOOT_PARAMS、三条分支、PLM 注释）
  - `kernel/gpu/gsp/arch/blackwell/kernel_gsp_gb100.c`（debug 熔丝、GSP reset PLM）
  - `kernel/gpu/sec2/arch/blackwell/kernel_sec2_gb20b.c`（FWSEC 消费 COT、debug dump）
  - `src/common/inc/swref/published/blackwell/gb100/dev_fuse_zb.h`（0x74C）
