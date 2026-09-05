# SlotWarner

SlotWarner 是一个面向 Solidity 可升级合约的**位级（bit-level）存储冲突分析工具**。它不仅比较两个合约是否使用了同一个 storage slot，还进一步检查变量在槽位中的实际 bit 区间、Logic 合约中的可达写入/外部输入影响，以及这些影响在 `DELEGATECALL` 执行语义下是否会投影到 Proxy 合约的持久化存储区域。

除了 Proxy–Logic 存储冲突检测，SlotWarner 还提供**单合约预警分析（single-contract early warning）**：在尚未给出第二个合约时，工具可以分析哪些状态变量会受到 public/external 参数或 EVM 环境输入的影响，为后续升级或代理部署提前标记需要关注的 storage 区域。

> `WARNING` 不等于“已经存在漏洞”；它表示该单合约存在值得关注的外部可影响持久状态。真正的存储冲突结论需要 Proxy–Logic 两个存储上下文。

## 功能概览

- Solidity 源码级 storage layout 重建
- packed storage 的 slot / offset / bit-width 分析
- Proxy–Logic bit-level 物理重叠检测
- Logic 侧 public/external 输入与状态写入传播
- `DELEGATECALL` 存储上下文下的跨合约投影
- mapping namespace seed 等动态存储场景的辅助分析
- 单合约提前预警
- 原始多级 Solidity 工程与 flattened Solidity 文件均可使用

---

## 1. 安装

### 环境要求

推荐：

- Python 3.10 或更高版本（推荐 Python 3.11）
- Windows / Linux / macOS
- 首次分析某个 Solidity 编译器版本时需要网络连接，以便 `py-solc-x` 下载对应的 `solc`

进入 SlotWarner 目录后创建独立 Python 环境：

### Windows PowerShell

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -e .
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -e .
```

安装后检查命令是否可用：

```bash
slotwarner --help
slotwarner --version
```

---

## 2. 测试安装是否成功

发布包内置两个最小 Solidity 示例：

- `examples/single/SingleWarning.sol`：测试单合约预警分析
- `examples/flattened/StorageCollisionFlat.sol`：测试 flattened Proxy–Logic 存储冲突检测

直接运行：

```bash
slotwarner selftest
```

首次运行时 SlotWarner 会自动安装示例所需的 Solidity 编译器。正常情况下最终应看到类似：

```text
warning_prediction   = WARNING
collision_prediction = POSITIVE
passed               = true
```

测试结果位于：

```text
results/selftest/
```

如果机器已经预装了需要的 `solc`，并且你不希望 SlotWarner联网安装编译器，可以使用：

```bash
slotwarner selftest --no-install-solc
```

---

## 3. 单合约预警分析

当你只有一个 Solidity 合约时，不需要等待 Proxy/Logic 配对完成。SlotWarner 可以先执行 early-warning analysis。

### 3.1 一个文件、一个合约

```bash
slotwarner warning MyContract.sol --out results/my-warning
```

如果文件中只有一个 concrete contract，SlotWarner 会自动选择它。

输出：

```text
results/my-warning/warning_result.json
```

主要结果有三种：

- `WARNING`：发现 public/external 输入或受支持 EVM 环境数据可以影响持久 storage；这是提前预警，不等同于已确认漏洞。
- `NO_WARNING`：在当前支持的静态分析范围内未识别出此类外部影响。
- `ABSTAIN`：当前证据不足，SlotWarner 无法可靠完成分析，例如源码无法编译、依赖缺失或目标合约无法唯一确定。

示例：

```bash
slotwarner warning examples/single/SingleWarning.sol --contract SingleWarning --out results/example-warning
```

### 3.2 一个 flattened 文件中有多个合约

如果一个 `.sol` 中同时包含多个 `contract`，请明确指定目标：

```bash
slotwarner warning Flattened.sol --contract MyLogic --out results/my-logic-warning
```

SlotWarner 会以 `MyLogic` 为目标构建其继承/调用分析上下文，而不是把整个 flattened 文件误认为一个合约。

### 3.3 多文件、多级目录

对于原始 Solidity 项目，可以直接传入 source root：

```bash
slotwarner warning ./contracts --out results/project-warning
```

SlotWarner 会递归查找：

```text
contracts/
├── proxy/
│   └── Proxy.sol
├── logic/
│   ├── LogicV1.sol
│   └── LogicV2.sol
└── libraries/
    └── Math.sol
```

原始目录结构应尽量保留，因为 Solidity `import`、继承与 library 依赖通常依赖这些相对路径。

目录批量模式会生成：

```text
warning_results.jsonl
warning_summary.json
```

如果某个 flattened 文件包含多个 concrete contracts，建议单独对该文件运行并使用 `--contract` 指定目标。

---

## 4. 存储冲突漏洞检测

本地使用时，给 SlotWarner 一对 Proxy 与 Logic 源码即可进行 storage-collision analysis。

### 4.1 Proxy 和 Logic 分别位于两个文件

如果每个文件只有一个 concrete contract：

```bash
slotwarner collision Proxy.sol Logic.sol --out results/collision --clean
```

如果文件中有多个合约，建议明确指定：

```bash
slotwarner collision contracts/proxy/MyProxy.sol contracts/logic/MyLogic.sol --proxy-contract MyProxy --logic-contract MyLogic --out results/collision --clean
```

多级目录不需要扁平化；直接传入目标文件即可。SlotWarner 会保留其所在 source tree，以便恢复相对 `import` 和依赖。

### 4.2 Proxy 和 Logic 已被扁平化到同一个文件

这是常见的 explorer/benchmark 输入形式。只需要传一次文件，并指定两个目标合约名：

```bash
slotwarner collision Flattened.sol --proxy-contract ProxyContract --logic-contract LogicContract --out results/collision --clean
```

使用发布包内置示例：

```bash
slotwarner collision examples/flattened/StorageCollisionFlat.sol --proxy-contract DemoProxy --logic-contract DemoLogic --out results/example-collision --clean
```

该示例故意让 `DemoProxy.admin` 与 `DemoLogic.initialized/operator` 在 slot 0 中发生物理重叠，因此预期结果为：

```text
POSITIVE
```

### 4.3 结果文件

主结论：

```text
collision_summary.json
```

同时保留可审计的中间结果：

```text
proxy_layout.json
logic_layout.json
geometry_summary.json
bit_overlap_records.jsonl
same_slot_non_overlap_records.jsonl
namespace_seed_alias_records.jsonl

detection/
├── single_contract_results.jsonl
├── upgradeable_all_bit_effects.jsonl
├── upgradeable_aligned_effects.jsonl
├── upgradeable_collision_findings.jsonl
├── upgradeable_pair_summary.jsonl
└── compile_failures.jsonl
```

最终 `prediction`：

- `POSITIVE`：发现至少一个可执行的 bit-level storage-conflict candidate。
- `NEGATIVE`：分析成功，但在当前支持范围内没有保留的 operational storage-conflict candidate。
- `ABSTAIN`：无法可靠完成该 pair 的正式判断。

---

## 5. `ABSTAIN` 是什么意思？

`ABSTAIN` 可以理解为：**SlotWarner 拒绝猜测。**

它既不是 `NEGATIVE`，也不应该被自动算成 `FN`。常见原因包括：

- Solidity 源码或依赖不完整；
- 缺少兼容的 `solc`；
- 编译失败；
- storage layout 无法可靠恢复；
- flattened 文件中无法唯一确定目标 contract；
- 某些动态/assembly 行为超出当前静态分析能力；
- 在链上 benchmark 场景中，Proxy–Logic 历史关系证据不足。

在科研评测中，`ABSTAIN` 应与 TP/FP/TN/FN 分开，并同时报告 coverage。例如 100 个 case 中分析了 91 个、9 个 ABSTAIN，则 coverage 为 91%。

在实际使用中，不要把 ABSTAIN 理解成“这个合约安全”。建议检查输出中的 `reason` / `detail`，补齐源码、import、编译器或目标合约信息后重新分析。

---

## 6. 常用命令速查

```bash
# 查看帮助
slotwarner --help

# 验证安装
slotwarner selftest

# 单文件预警
slotwarner warning MyContract.sol

# flattened 文件指定目标合约进行预警
slotwarner warning Flattened.sol --contract MyContract

# 整个多级源码目录的预警扫描
slotwarner warning ./contracts

# 两个独立 Solidity 文件进行存储冲突检测
slotwarner collision Proxy.sol Logic.sol --clean

# 一个 flattened 文件中的 Proxy/Logic
slotwarner collision Flattened.sol --proxy-contract ProxyContract --logic-contract LogicContract --clean
```

---

## 7. 分析边界

SlotWarner 是静态分析工具。它尽量保留“不确定”而不是把分析失败强行解释为安全或漏洞。因此，在以下场景中可能出现 `ABSTAIN` 或 coverage 降低：

- 源码未公开或无法完整恢复；
- npm/外部 Solidity package 依赖缺失；
- 大量 raw assembly / 非标准动态 dispatch；
- 无法恢复的 compiler/toolchain 环境；
- 复杂动态 storage namespace 无法被精确投影。

对于重要合约，建议将 SlotWarner 的结果与人工审计、升级前 storage-layout diff、测试网执行以及其他安全工具结合使用。

---

## Citation

如果 SlotWarner 对你的研究有帮助，请引用对应的 SlotWarner 论文。论文发表信息确定后，可在此处补充正式 BibTeX。
