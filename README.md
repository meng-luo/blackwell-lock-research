# Blackwell Lock Research

A **read-only research archive** on NVIDIA GeForce RTX 50 series (Blackwell, `GB20x`): why this generation
cannot be unlocked the way 30/40 series were — and exactly where that boundary sits.

一个面向 RTX 50 系（Blackwell，`GB20x`）的**只读研究档案**：为什么这一代无法像 30/40 系那样通过固件层面的
手段解开机型限制，以及这条分界线**具体**落在哪里。

> **This is not an unlock tool and contains no executable attack.** / **这不是解锁工具，也不含任何可执行攻击。**
> Everything here is based on read-only register sampling of the author's own hardware, NVIDIA's MIT-licensed
> driver source, and static analysis of locally installed firmware packages.
> **No write of any kind, no GPU modification, no VBIOS flash, no fuse touched.**
>
> 全部工作基于：自有硬件的只读寄存器采样、NVIDIA 以 MIT 许可公开的驱动源码、以及本地固件包的静态分析。
> **没有任何一次写操作、没有改过显卡、没有刷过 VBIOS、没有碰熔丝。**

---

## TL;DR

> **EN** — The dividing line is not a fuse and not a PLM; it is the **delivery form of the firmware**.
> On 30/40 series the debug booter image ships encrypted with a **non-secret numbered test key (#37)**, and debug
> vs. production images contain **identical cleartext code** — so decrypting the debug copy yields the production
> code, from which ROP gadgets can be mined. That is how every public 30/40-series payload was built.
> On 50 series this stage moved into the **FMC**, whose debug copy carries **no such test-key marker**, differs from
> production in **99.5 %** of its bytes, and is verified with **RSA-3K / ECDSA P-384** instead of a Falcon AES-MAC.
> The same route does not exist on the new architecture.
>
> Measured on the author's card: **`FUSE_OPT_FEAT_OVR_DISABLE = 0`** — the override domain is *not* fused off,
> so the door is structurally still open; what is missing is the key to it (code execution inside the GPU's
> security domain).
>
> **中文** — 分界线不在熔丝，也不在 PLM，而在**固件交付形态**。
> 30/40 系能做出解锁 payload，前提是 NVIDIA 交付的 **debug booter 镜像用的是非机密测试密钥（编号 #37）**，
> 而 debug 与 production 的**明文代码完全相同**——解 debug 副本即得 prod 代码，再从中挖 ROP gadget。
> 50 系把这个阶段并入 **FMC**，其 debug 副本**不含该测试密钥标记**，载荷与 prod 有 **99.5%** 字节不同，
> 验签也改为 **RSA-3K / ECDSA P-384**。同一条通路在新架构上不成立。
>
> 本机实测：**`FUSE_OPT_FEAT_OVR_DISABLE = 0`**——override 域并没有被熔丝关死，门在结构上还开着；
> 但开门的钥匙（在 GPU 安全域内取得代码执行）拿不到。

### Generation boundary, measured / 代际分界（实测）

| | 30/40 series | 50 series |
|---|---|---|
| Secure-boot stage | **Booter ucode** on SEC2 | **FMC** (partitioned, ACR inside) |
| Host loads the booter? | yes | no (`bPartitionedFmc`) |
| Artifact location | `g_bindata_kgspGetBinArchiveBooterLoadUcode_*.c` | `g_bindata_kgspGetBinArchiveGspRmFmcGfwProdSigned_*.c` |
| Ciphertext range | `[0x100,0x8700)` = 34,304 B | `[0x48,…)` ≈ 212 KB (almost the whole payload) |
| **test-key #37 trailing marker** | **present** (GA102 @ `0x89c0`) | **absent** |
| debug vs prod | same cleartext, different key | **99.5 % of bytes differ** |
| Verification | Falcon AES-MAC / RSA | **RSA-3K / ECDSA P-384** |

Per-family keys are *not* shared: GB20B/GH100 use RSA-3K (384 B sig/key), GB100/GB202 use ECDSA P-384
(96 B sig / 97 B key, with GB100 and GB202 sharing one key). Debug ≠ production key.
A chip that did not know which key to expect could not enforce any of this — which is why the
"FSP blindly trusts the host-supplied public key" hypothesis is structurally implausible.

各族密钥并不通用：GB20B/GH100 用 RSA-3K（384 B），GB100/GB202 用 ECDSA P-384（96/97 B，且两者公钥相同），
debug ≠ prod。芯片若不知道"该用哪把钥"，这套分级根本无从执行——所以"FSP 无条件相信主机送来的公钥"在结构上难以成立。

---

## Documents / 文档

| Document | Contents |
|---|---|
| [`docs/gb206-fsp-attack-surface.md`](docs/gb206-fsp-attack-surface.md) | **Main document** (Chinese). FSP/FMC attack surface map: host-controllable inputs, validation & fallback matrix, read-only observability, ranked hypotheses, the generation boundary, **8 documented self-corrections**, and re-evaluation triggers |
| [`docs/rtx50-support-analysis.md`](docs/rtx50-support-analysis.md) | Early feasibility analysis: three-generation boot-chain comparison, per-family requirements, measured cold values |
| [`docs/gb206-readonly-evidence.md`](docs/gb206-readonly-evidence.md) | On-card read-only evidence: identity, `gsp_ga10x.bin` structure, driver-cleanup defect, post-reboot self-check |
| [`docs/evidence/`](docs/evidence/) | Sampling logs (`ssdiag-*.log`) |
| [`analysis/reports/acr-image-hunt.md`](analysis/reports/acr-image-hunt.md) | Embedded image manifest in `.fwimage`, real identity of all 12 images, GB206 attribution, proof that ACR/FMC is in neither package |
| [`analysis/reports/nvriscv-decode.md`](analysis/reports/nvriscv-decode.md) | Root cause of the decode problem (missing `--mattr=+c` plus two further artifacts), verdicts on four hypotheses, MPU window CSRs |
| [`analysis/tools/nvrx.py`](analysis/tools/nvrx.py) | Firmware image extraction / disassembly / coverage statistics |
| [`analysis/tools/extract-run.py`](analysis/tools/extract-run.py) | Selective firmware extraction from an NVIDIA `.run` (makeself + zstd) |

> The documents themselves are written in Chinese; this README is the English entry point.
> 文档正文为中文，本 README 提供英文入口。

---

## Reproduction notes / 复现要点

When disassembling the RISC-V components, **three pitfalls** make the code look like it uses a custom ISA
(this repository hit all three):

```bash
llvm-objdump -d --triple=riscv64 --mattr=+m,+a,+c,+zicsr,+zifencei -M no-aliases <file>
```

1. `--triple=riscv64` defaults to **bare RV64I**; the C extension is off, and objdump **does not read `e_flags`**
   (these images are `EF_RISCV_RVC`).
2. `.text` must start at `e_entry`; starting at the segment base decodes from `7f 45 4c 46` (the ELF magic) and
   never resynchronises.
3. Segment tails often contain rodata (source paths + assertion strings); counting them as code drags coverage down.

Acceptance criterion: **zero `<unknown>` in the code region**, and 100 % of branch targets on instruction
boundaries.

反汇编 RISC-V 组件时，**三个坑**会让人误以为指令集里有自定义扩展（本仓库全踩过）：
默认特征集是裸 RV64I 且 objdump 不读 `e_flags`；`.text` 必须从 `e_entry` 起；段尾 rodata 不能当代码扫。

`nvrx.py` wraps the correct invocation / 已封装上述调用与统计:

```bash
python analysis/tools/nvrx.py info    <image.elf>
python analysis/tools/nvrx.py analyze <image.elf>
python analysis/tools/nvrx.py batch   <dir>
```

---

## Compliance / 合规

This repository **deliberately does not contain** / 本仓库**刻意不含**：

- NVIDIA proprietary firmware (`gsp_*.bin`, `ucodes_*.bin`, `.fwimage` embedded images, FMC payloads)
- driver installers (`.run`) or their unpacked intermediates
- any key material, signatures, or public-key binaries
- full firmware disassembly dumps
- weaponisable tooling (payload generators, ROP chains, code that writes protected registers)

Firmware and key redistribution is restricted by NVIDIA's licence; publishing exploitation tooling would not
serve this project's purpose, which is **to establish the feasibility boundary**, not to provide an unlock.

固件与密钥的再分发受 NVIDIA 许可限制；利用工具的发布不符合本研究的目的（**判断可行性边界**，而非提供解锁手段）。

Related work (the 30/40-series implementations) is public third-party code; this project only cites its
conclusions for comparison and does not reproduce it.

---

## Why there are 8 corrections on record / 为什么有 8 条更正记录

This research reversed itself several times ("the images are not plaintext" → "they are" → "the FMC is
encrypted"; "custom instruction set" → "actually a tool-flag mistake"; ...). Every reversal, with the evidence
that triggered it, is kept in `§8.8` of the main document — so that later readers are not misled by a superseded
conclusion buried mid-document.

Rule of thumb recorded there: **most mistakes in this project came from tool configuration and statistics
discipline, not from the firmware itself.** If a scan finds nothing, check the tool before drawing a conclusion.

研究过程中多次自我改判，全部连同触发证据记录在 `§8.8`。教训总纲：**本项目多数错误来自工具配置与统计口径，
而不是固件本身——凡"扫不到/比例异常"，先自检工具再下判断。**

---

## What would overturn this conclusion / 什么情况下结论会被推翻

See `§8.11.3` for the full list. Summary / 摘要：

1. Someone publicly recovers a `csecret` (especially `secret(6)`, which decrypts ECB firmware blocks)
2. A per-family FMC debug copy shows the key #37 trailing marker
3. A driver adds a GB20x `BooterLoadUcode` HAL variant (today it falls into a NULL-stub fallback)
4. Any family's FMC reverts to "plaintext + signature"
5. Someone proves the FSP does not validate public-key provenance
6. The FSP/ROM verification logic becomes public (firmware dump + disassembly)

---

## Primary sources / 一手来源

- NVIDIA `open-gpu-kernel-modules` (**MIT**): `kernel/gpu/fsp/*`, `kernel/gpu/gsp/*`, `kernel/gpu/sec2/*`,
  `generated/g_bindata_*`, `common/inc/swref/*`
- kernel.org nova-core docs: <https://docs.kernel.org/gpu/nova/core/fsp.html>, `.../falcon.html`
- Community, conclusions cited only: `Zagitta/gpu-unlock`, `JustAResearcher/gpu-unlock-ada`, `nlzy/turing-unlock`,
  `Consensus-Protocol/cmp170hx` (CMP 170HX full-chain wiki), `phiraml/gpu-unlock-blackwell` (GB20x port study)

## License

- **Scripts** (`analysis/tools/`): [MIT](LICENSE)
- **Documents and reports** (`docs/`, `analysis/reports/*.md`): [CC BY 4.0](NOTICE)
- NVIDIA source snippets quoted here keep their own license (MIT)
- This repository contains no NVIDIA firmware, driver package, key material, or firmware-derived dump

Scope, third-party inventory and attribution format: see [NOTICE](NOTICE).
