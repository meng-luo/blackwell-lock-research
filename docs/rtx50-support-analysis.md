# RTX 50 系（Blackwell / GB2xx）解锁可行性分析

> **范围**：`gpu-unlock`（Linux kmod，主线）、`nv-uefi-unlocker`（UEFI EFI 应用）、
> `rtx30-gpu-unlock-backup`（旧版备份）+ 公开一手资料（open-gpu-kernel-modules 源码、
> kernel.org nova-core 文档、社区实测报告）。
> **目的**：回答"50 系能不能支持、代价是什么、第一步做什么"。
> **证据等级**：［源码］= NVIDIA open-gpu-kernel-modules；［文档］= kernel.org / 上游 patch；
> ［规格书］= NVIDIA 白皮书；［实测］= 社区真机数据；［推测］= 推断；［未确认］= 公开资料查不到。

---

## 0. 结论

| 问题 | 答案 | 证据等级 |
|---|---|---|
| 现在支持吗？ | 不支持，且是**主动排除**（EFI 路由 `0x2bxx+ = out of scope`，kmod `cards[]` 无 GB 条目） | ［源码］本仓 |
| 缺的是"适配工作"吗？ | **不是**。缺的是攻击面：整套解锁依赖"已签名 SEC2 Booter 被重入"，GB20x 没有这段固件 | ［源码］+［文档］ |
| 别人做出来了吗？ | 没有。公开侧已有专门项目做了同样的可行性判断：**"Public Blackwell payload / debug booter: does not exist"、"Step 1 is the blocker"** | ［实测］phiraml/gpu-unlock-blackwell |
| 定性结论 | **不可行（无可用入口）**，等价于"需要一次全新的漏洞研究"，不是"待适配" | — |
| 唯一还有意义的动作 | 先确认"到底要解什么"——速率编码目前三个口径互相矛盾，连目标值都未定论 | ［实测］ |

一句话：**50 系的问题不是"项目没做"，而是这一代把"签名固件替我们写寄存器"这条路整个拿掉了；而在投入研究前，连"降了多少、按什么编码"都还没有共识。**

---

## 1. 这套解锁的充要条件（六条）

钳制寄存器被 PLM 硬件门锁在 heavy-secure（L3），主机写被静默丢弃，唯一出路是**让已签名固件在 L3 里替我们写**。一代芯片要能解锁，必须凑齐：

| # | 条件 | 谁提供 | 对应代码 |
|---|---|---|---|
| a | 一段**能被主机点火、且带无界签名 DMA 拷贝**的 HS Booter（SEC2 Falcon） | 驱动 BINDATA `kgspGetBinArchiveBooterLoadUcode_<CHIP>` | `recipes.h:13-21`、`extract_boot_assets.py:15-28` |
| b | 针对**那段 booter 二进制**的 gadget 链（写入口 / canary / 0x18 帧几何 / marker / 出口） | 社区逆向逐族手挖 | `recipes.c:25-174`、`payload.h:42-46` |
| c | **FWSEC-FRTS** 在 GSP 上以 HS 建 WPR2，提供 WprMeta 通道 | VBIOS ucode 表 | `vbios_610.c`、`prep_610.c` |
| d | 钳制寄存器组存在、且由 PLM 门控 | 冷值标定 | `registers.h:73-98` |
| e | 熔丝总开关未烧（`OPT_FEATURE_FUSES_OVERRIDE_DISABLE=0`）、签名槽可用 | 硅片出厂态 | `registers.h:57-58` |
| f | 驱动侧接受"pre-OS 已改过的卡"（Turing 必须 GSP 模式） | 驱动行为 | `enable-turing-unlock.ps1` |

**a/b/c 是"零"，d/e/f 是"有但不可用"。** 这个区分决定整个判断。

---

## 2. Blackwell 逐条判定（含 2026 年社区实测）

| # | GB2xx 状态 | 依据 |
|---|---|---|
| a | ❌ **不存在** | Hopper+ 的 `kgspBootstrap_GH100` 三选一：FSP → SEC2(FWSEC) → 主机直写 RISC-V BCR。GB202 走 **FSP**（`kern_fsp_gb202.c`），且 **FSP 在 silicon 上强制**（`kfspGspFmcIsEnforced_GH100()` 恒 TRUE，COT 不可关）。不存在 `kernel_sec2_gb202.c`；`BooterLoadUcode` 的 per-chip 变体只有 TU102/TU116/GA100/GA102/AD102，其余是返回 NULL 的 stub ［源码］ |
| b | ❌ 无对象 | 没有 a 就没有 b。GA102 载荷在 AD102 上直接 HALT 是先例；`payload.h:42-46` 明文："payload 由 Booter 选择，绝不由 family 选择……另一个 Booter 用不了" |
| c | ❌ **GSP 侧不存在** | 内核文档："There is no SEC2 involvement, no Booter ucode, and no FWSEC-FRTS stage." FRTS 区改由 COT 消息参数指定（GB100 另有 ZB 寄存器编程 FRTS 位置）。WprMeta 结构还在，但语义变成"给 FMC/ACR 的尺寸+地址输入"，经 `GSP_FMC_BOOT_PARAMS` 交给 FMC，不再进 Booter 邮箱 ［源码］［文档］ |
| d | ⚠️ **存在，但形同虚设** | GB203M 冷态实测：`FEAT_OVR_PLM 0x823804 = 0xfffffb8f`（关；Ada 是 `0xffffff8f`）、`SS0/SS1 0x82381c/0x823820` 有值但 enable 位无效、`FEAT_READOUT_1 0x823818 = 0x00c36180`。**写 SS0=0x88888888 / SS1=0x8 / PLM=0xffffffff 全部读回不变 = 主机写被丢弃**，与 30/40 系行为一致 ［实测］ |
| e | ⚠️ 熔丝是**数据源**，不只是开关 | 速率值疑似直接从熔丝来：`FUSE_SS_FMLA32 0x008207d8 = 3`（按 `ctrl2080gr.h` = **1/8** 编码）。而直改熔丝会让卡**拒绝 POST**（可恢复，Panchovix 实测） ［实测］［推测］ |
| f | ❓ 无数据 | 没有任何 GB 硅证据，README 收益表不能外推 |

**结论：a/b/c 为零 → 当前形态不可行；d 存在但被 PLM 锁死且数值来自熔丝；e 提供了"即使拿到任意写也未必有用"的第二道墙。**

---

## 3. 为什么"没有 SEC2 Booter"是致命的（两处表述先纠正）

⚠️ **纠正 1：不要说"Blackwell 没有 SEC2"。** GB20B（B200 级）上 SEC2 仍在，跑 **FWSEC** 并作为 COT 消息的消费者（`ksec2SendBootCommands_GB20B`，等 FWSEC 写 0xFF 到 `NV_PMC_ZB_SCRATCH_RESET_PLUS_2`）。准确说法是：**没有"SEC2 Booter 装 GSP-RM"这一段**，SEC2 的职责从"执行主机递来的 Booter"变成"跑 FWSEC 处理消息"。

原方案的四段式依赖：

```
① 主机递签名 Booter 给 SEC2 → ② BROM 验签后在 HS 运行
→ ③ 其签名 DMA 拷贝无界（长度取 WprMeta+0x50，DMEM 0x0800+0xF800=0x10000 越栈顶）
→ ④ ROP 复用其自身指令写 PLM
```

Blackwell 把 ① 拿掉、把 ③ 的载体换成"主机给的三个地址 + RISC-V BROM 按 manifest 里的 PKC 参数自行载入"。于是：

- **主机交付的不再是可执行固件，而是被 SHA-384 + RSA-3K 绑定的 FMC 头**；验签发生在 FSP / RISC-V BootROM 里；
- `_kgspBootstrapGspFmc_GH100()` 那条"主机写 BCR 给地址"的路径在**零售卡上不会被采用**（FSP 强制），而且 FMC **通过 PLM 屏蔽 `RISCV_BCR_CTRL` 的读** ［源码］；
- 因此拿不到 L3 内的可控执行 → `FEAT_OVR_PLM` 永远开不了 → SS0/SS1 永远空写；
- 这也解释了为什么 `0x23xx`（Hopper）在 EFI 路由里是**故意留空**的（`loader/src/main.rs:164-167`）：同一堵墙，GB 只是更晚出现。

---

## 4. 不只是本项目：公开渠道目前也没有方案

| 来源 | 结论 | 价值 |
|---|---|---|
| `phiraml/gpu-unlock-blackwell`（2026-10） | 状态表：熔丝存在=已测量；**"Public Blackwell payload: does not exist"、"Public Blackwell debug booter: does not exist"**；"Step 5（pre-driver kmod）已写好可复用，**Step 1 是阻塞点**" | 与本项目结论同构：卡在"没有可解密的 booter 明文" |
| `JustAResearcher/gpu-unlock-ada` issue #12（17 评论，closed/not planned） | GB202 固件目录里有 `bootloader-*.bin`(200,812B) / `fmc-*.bin`(ELF32)，**没有 `booter_load`**；610.43.03 的 bindata 里也没有任何 Blackwell booter。维护者：*"same registers are there, but host writes are dropped, the rate comes from fuses, and there's no published SEC2 booter"*；ElXreno：**"The unlock for GB20x will be an FSP/FMC bug, not a register move."** | 一手硅片/镜像证据 |
| key #37 复核 | 按 AES-128-ECB（KAT `AES_ECB(key,0*16)=717d1494…`）扫常见构造，**无命中**；cmp170hx 亦记"debug #37 从未被证实、密钥从未公开" | 逆向前置条件不成立 |

**注意**：本项目自己的 `ssdiag` 反而落后于公开认知——它仍把 `blackwell-gb2` 标为 `FEAT_NONE`（`tools/ssdiag/main.rs:743-745`），而社区已在 GB203M 上读全了 FEAT 块。这是个可以直接补的小缺口。

---

## 5. 连"要解的是什么"都还没定论（这是最容易被忽略的一条）

同一张 5090，三种口径互相矛盾 ［规格书］［实测］：

| 口径 | 数值 | 含义 |
|---|---|---|
| NVIDIA 白皮书（Table 3） | FP16→FP16 dense **419** / FP16→FP32 dense **209.5** | 209.5/419 = **0.500**（正好半速）；对比 RTX PRO 6000：三项全是 503.8（**专业卡无分档**） |
| 第三方同一 boot 实测 | FP16-acc 334.68 → **FP32-acc 226.14**（**0.676**）、BF16-acc 222.29（0.664）；另一组 324.6 → 217.5（≈0.67） | 与规格书 0.5 不符 |
| RM 控制接口 | `GR_GET_SM_ISSUE_RATE_MODIFIER` 返回 `fmla32=3`（GB202 与 GB203M 一致） | 按定义 3 = **1/8** |

再加上 `FEAT_READOUT_1 = 0x00c36180` **按 Ada 的 9×3bit 打包解不出合理值**——说明 GB 上的字段打包方式变了。

**后果**：即使明天有人拿到 L3 任意写，也还不知道该往 SS0/SS1 写什么、READOUT 该读回多少才算成功。**"成功判据"本身是缺失的**，而项目的宪法是"读回是唯一判据"。

---

## 6. 真要走这条路：三个候选面 + 两道硬约束

候选攻击面（都属"全新漏洞研究"，不是移植）：

1. **FMC 的加载/验签面**：唯一"主机仍提供固件"的环节（`GSP_FMC_BOOT_PARAMS` + BCR 三段地址 + manifest 里的 PKC 参数）；但验签在 BROM 里，主机拿不到可写 IMEM/DMEM。
2. **FSP 消息面**：COT（0x14）/ PRC（0x13）是新的 MCTP/NVDM 解析面；PRC 的 knob 例子是 vGPU/ECC/CC/NVLINK，**没有任何算力相关 knob**；与频率有关的只有 `CLOCK_BOOST` RPC（boost 档次，不是算力档）。
3. **调试/降级路径**：`kgspIsDebugModeEnabled_GB100()` 读 `NV_FUSE_ZB_OPT_SECURE_GSP_DEBUG_DIS`，debug 时取 `GspRmFmcGfwDebugSigned`——**存在 DebugSigned 资产**，但无公开材料表明它用公开测试密钥加密（见 §4 的反证）。

两道硬约束：

- **约束 A（入口）**：验签链是 FSP → FMC → GSP-RM，任何"主机提供 blob"的点都要过 RSA-3K/SHA-384；
- **约束 B（出口）**：数值疑似来自熔丝（`FUSE_SS_FMLA32=3`），而直改熔丝 → **拒绝 POST**。所以原语必须"只动速率、不触发验签失败与 POST 拒绝"，窗口极窄。

---

## 7. 如果真到了"移植"那一步：最小移植面（量化）

| 项 | 数量/内容 |
|---|---|
| **必改文件** | gpu-unlock **8 个**（`recipes.c/.h`、`registers.h`、`unlock_610.c`、`firmware_610.c/.h`、`Makefile`、`extract_boot_assets.py`）+ 2 条件（`vbios_610.c`、`prep_610.c`）；nv-uefi-unlocker **11 个**（`main.rs`、`tx.rs`、`tx_booter.rs`、`tx_fwsec.rs`、`sample.rs`、`assets/{manifest,payload,main}.rs`、`make-usbroot.ps1`、`.sh`）+ 2 诊断（`ssdiag/main.rs`、`diag-unlock.py`） |
| **每族必新增数据对象（10 类，缺一跑不通）** | booter bundle、8 个 booter 几何常量、GSP boot + desc、`.fwsignature_<fam>`(4096B)、FWSEC 描述符几何、payload(19–40 dword) + fill/canary/完成判据、特权写表 + host 写表、FEAT 三元组、WprMeta heap 规则、layout 输入源 |
| **纯体力活** | `cards[]` 逐 SKU、`MODULE_FIRMWARE`、`GU_SHARED_BUNDLES/BOOTERS=3` 扩容、`-Family` 双份（ps1+sh）、die→family 映射三处同步、manifest pin、ELF 段改名 |
| **必须有全新外部输入、工程补不齐的** | ① 该族**签名 Booter 的可解密镜像** ② 反汇编出的 gadget 偏移 ③ 溢出栈几何标定 ④ FWSEC/boot desc 版本 ⑤ 该族驱动版本钉链 |
| **族相关代码密度（主战场）** | `recipes.c` 156 处 / `tx.rs` 67 / `tx_fwsec.rs` 45 / `tx_booter.rs` 42 |

**关键事实：仓库里没有任何 gadget 挖掘工具**（`gadget|fwmap|envydis|disassembl` 在两个仓的 `*.py` 命中为 0）。`generate_v67.py` 的"生成"= 用 fill 字铺满 64 KB + 覆写 19 个 dword + 对 pin 校 SHA-256；payload 真正来源是外部补丁函数 `_kgspCmp90FillV67Signature`。**仓库只覆盖链条末端的"物化 + 点火读回"，不覆盖"挖漏洞"这一段。**

现有三族实现互不通用，也说明没有可套的模板：
- GA102 = 单写 + 自循环，无 marker；
- AD10x = 四写 + marker `0x67b00001`；
- TU102 = 两写 + ACR mutex 释放 + 不穿 FLR（还要 PLM 回锁）。

参照成本：Turing 这一代（**同体系内、有社区先例**）在 EFI 侧用了 **13 次实机点火**才闭环（`docs/evidence/m3-tu106/attempt1..13`）。

---

## 8. 现在能做的低成本动作（修订版 M1'）

原计划是"用 ssdiag 标定 FEAT 地址"，但 §2/§5 表明社区已有 GB203M 冷值。所以这一步的意义从"打开未知"降级为"**校准与补缺**"，仍值得做，因为项目自己的工具还停在 `FEAT_NONE`：

1. **补 `ssdiag` 的 GB 行表**：把 `0x823800–0x823830`、`0x8207d8`（`FUSE_SS_FMLA32`）、`0x8241c0/0x824140`、`0x8203f0`、`0x1fa824/28`、`0x840100/0x110100`、`0x9a0148` 加进 `family_of()` 的 `blackwell-gb2` 分支（现在是空表）。
2. **在真卡上做只读对照**：验证 `FEAT_OVR_PLM = 0xfffffb8f` 这个"异于 Ada"的值是否可复现，并尝试**重推 `FEAT_READOUT_1` 的字段打包**（这是目前唯一真正未解的寄存器语义）。
3. **量速率编码**：同一 boot 上跑 FP16-acc / FP32-acc 微基准，把"规格 0.5 / 实测 0.67 / RM 3"三个口径在同一台机器上对齐——这一步决定"有没有必要继续"。
4. **明确不做的**：不加载 `gpu_unlock`（`cards[]` 无 GB，本来也不会动作）；不尝试熔丝写（→ 拒 POST）；不指望 vBIOS 改（签名）。

---

## 9. 建议（按性价比）

1. **定性接受"50 系不可解锁"**，把研究精力留在 20/30/40 系（README 已逐卡实测 +65%~100% 峰值、真实负载 +25~55%）。
2. **只做 §8 的只读校准**（1 天），产出两样东西：GB 冷值表入 `cold-values.md` 的 GB 节、`FEAT_READOUT_1` 编码假设。这两样是任何后续研究（包括别人做的）的前置。
3. **若要做研究，先做"能否拿到可反汇编固件"的判定**（debug 资产 + key #37 复核）。拿不到就停——这一步是 §6 三个候选面的共同前置。
4. **不要相信"加 ID 就能跑"**的工程直觉：本项目自己的 `recipes.c:65-68` 就写着 GA100 在无 payload 时"借用"GA102 的 V67 body（并注明这只是占位），而跨族载荷在硅上直接 HALT。

---

## 10. 本机实证（GB206 / RTX 5060 Ti，2026-10-29）

用户本机实测补充，详见 [gb206-readonly-evidence.md](gb206-readonly-evidence.md)：

| 项 | 结果 | 对结论的影响 |
|---|---|---|
| 身份 | `10de:2D04`，RTX 5060 Ti，驱动 621.01，VBIOS `98.06.4e.xx`，`nvidia-smi` 自报 **Product Architecture: Blackwell** | 确认落在 GB2xx 段 |
| `gsp_ga10x.bin` ELF 段 | **12 个族签名段，含 `.fwsignature_gb20x`**（另有 gb20y / cc_gb20x / gb10x / gb10y / gh100 / ad10x / ga10x …） | **签名资产不是瓶颈**——进一步坐实"缺的是 booter" |
| `ucodes_*.bin` | 只有 `ucodes_ga10x.bin` / `ucodes_tu10x.bin`，**没有 `ucodes_gb20x.bin`** | GB 共用 ga10x 微码归档；与"无自有 SEC2 booter 套件"方向一致 |
| `nvlddmkm.sys` 符号扫描 | `BooterLoadUcode`/`FWSEC`/`kfsp` 等 **0 命中** | 零售二进制符号已剥离，此方法**无效**（不是反证） |
| `ssdiag` 未提权运行 | `OpenSCManager failed: win32 5`，服务零残留 | 无权限路径安全失败，符合预期 |

**代码侧已落地**（`tools/ssdiag/main.rs`）：
- 新增 `FEAT_GB2XX`（Ada 孔径、实测用于 GB203M）与 `GB_ROWS`/`GB_SWEEP`（`FUSE_SS_FMLA32 0x8207d8` 邻域）；
- `family_of()` 的 `blackwell-gb1/gb2` 不再返回空表，VERDICT 会给出"GB2xx 编码未确立"的明确说明；
- **写路径对该族硬拒**：`--reapply` 在 GB 上无条件 REFUSED，理由是"无可读回验证的选择器编码"。

### 10.1 已完成：GB206 冷值采样（UEFI 只读路径）

`pmxdrv.sys` 在本机 `MAP_PHYS` 被拒（EPERM），于是改走项目自己的 **UEFI 只读构建**
（`cargo efi`，`tx` 关闭 → 二进制内无任何写原语），U 盘启动采样后链回 Windows。
日志归档：`nv-uefi-unlocker/docs/evidence/m1-gb206-5060ti/`（`loader.log` 8818 B + `report.md`）。

| 项 | 实测值 | 意义 |
|---|---|---|
| `PMC_BOOT_0` | `0x1b6000a1` | die = **0x1B6 = GB206**（首个 GB 硅身份确认） |
| `FEAT_OVR_PLM 0x823804` | `0xfffffb8f` | 读 L0–L3 / **写仅 L3** / 源使能 `0xfffb` → **门同形**；与社区 GB203M 逐位一致 |
| `FEAT_READOUT_1 0x823818` | `0x00c36180` | **钳制存在**；按 Ada 9×3bit 解为 `[0,0,6,0,6,6,0,6,0]`（Ada 钳制是 #2/#5/#7=2）→ **打包未定** |
| `SS0/SS1 0x82381c/20` | `0x25337061` / `0x00031005` | 与 Ada 冷值族完全不同，enable 位未置 |
| `FUSE_SS_FMLA32 0x8207d8` | **`0x3`** | `ctrl2080gr.h`：3 = **1/8**；同区间 0x7e0/0x7e4/0x7ec 亦 = 3 |
| `FUSE_OPT_FEAT_OVR_DISABLE 0x8203f0` | **`0x0`** | **熔丝总开关未烧 → override 域未被关死** |
| `SEC2/GSP_CPUCTL` | `0xbadf4100` ×2 | `0x41xx` = `privErrTargetLocked`（两引擎对 PL0 锁定） |
| `BSI_SCRATCH15` / `GFW_SCRATCH` | `0x0` / `0x0` | **无 BSI handoff、GFW 未跑**（AD107 为 `0x202001bf` / `0x3ff`） |
| `0x82380c` | `0x00888888` | **与 AD107 同值** → 通用常量，**不是**选择器（一个已排除的误判） |

**这轮采样对结论的修正**：
1. "钳制到底在不在"——**关闭**：在（READOUT ≠ 0，熔丝 4 字 = 3）。
2. "是不是被熔丝一刀切死"——**否**：`0x8203f0 = 0`，override 域结构上还在。
3. 但 **"写 `0x88888888` 即解锁" 在 GB 上不成立**：SS0/SS1 冷值与 READOUT 打包都变了，目标值和成功判据都缺。
4. 入口仍为零（CPUCTL 目标锁定 + BSI/GFW 归零），**§0 的定性结论不变**。

## 11. 证据索引

**本仓（可点开复核）**
- 结论性表述：`gpu-unlock/README.md:29`、`:118-119`；`nv-uefi-unlocker/README.md:352`
- 路由与排除：`nv-uefi-unlocker/loader/src/main.rs:171-187`
- 载荷不可跨族：`gpu-unlock/kernel/gpu_unlock/payload.h:42-46`；payload 表 `recipes.c:25-174`
- 资产来源与命名：`gpu-unlock/firmware/extract_boot_assets.py:15-28`、`recipes.h:6-21`
- 寄存器与判据：`gpu-unlock/kernel/gpu_unlock/registers.h:73-98`
- 族分叉 5 处：`unlock_610.c`（`turing_layout`:442、`booter->launch`:1035、`fwsec_version`:807、`feat_*`、`payload->completion`:1084）
- 15 步链条与族差异：`nv-uefi-unlocker/docs/chain-walkthrough.md`、`docs/reading-notes.md:47-89`
- 冷值范式：`nv-uefi-unlocker/docs/cold-values.md`；`ssdiag` 的 `FEAT_NONE`：`tools/ssdiag/main.rs:743-745`

**外部（一手优先）**
- <https://docs.kernel.org/gpu/nova/core/fsp.html>（FSP/COT/PRC，Ampere vs Hopper/Blackwell 对比）
- <https://docs.kernel.org/gpu/nova/core/falcon.html>（HS/LS/NS、BROM 信任根）
- open-gpu-kernel-modules `@57130a2`：`kernel/gpu/gsp/arch/hopper/kernel_gsp_gh100.c`、`kernel/gpu/fsp/arch/blackwell/kern_fsp_gb202.c`、`kernel/gpu/sec2/arch/blackwell/kernel_sec2_gb20b.c`
- <https://github.com/phiraml/gpu-unlock-blackwell>（同题可行性项目，状态表）
- <https://github.com/JustAResearcher/gpu-unlock-ada/issues/12>（GB202 固件目录、RM 读数、社区结论）
- RTX Blackwell 白皮书 Table 3 / RTX Blackwell PRO Table 4（FP16→FP32 分档数据）
