# SlotWarner

SlotWarner is a **bit-level storage-collision analyzer for Solidity upgradeable contracts**. Instead of treating two variables as conflicting merely because they share a storage slot, SlotWarner reconstructs their actual bit intervals, analyzes reachable writes and external influence on the Logic side, and projects those effects back to the Proxy storage context under `DELEGATECALL` semantics.

SlotWarner also provides **single-contract early-warning analysis**. Even when only one contract is available, the tool can identify persistent storage regions influenced by public/external inputs or supported EVM environment sources. This helps developers review potentially sensitive storage before a contract is deployed behind a proxy or used in an upgrade path.

> `WARNING` does not mean that a storage-collision vulnerability has already been confirmed. It indicates externally influenced persistent state that deserves attention. A concrete storage-collision decision requires two storage contexts, typically a Proxy and a Logic contract.

## Highlights

- Source-level Solidity storage-layout reconstruction
- Slot / offset / bit-width analysis for packed storage
- Bit-precise Proxy–Logic physical-overlap detection
- Public/external input and reachable-write propagation on the Logic side
- Cross-contract projection under `DELEGATECALL` storage semantics
- Auxiliary handling for mapping namespace seeds and dynamic storage patterns
- Single-contract early warning
- Support for both multi-directory Solidity projects and flattened Solidity files

---

## 1. Installation

### Requirements

Recommended environment:

- Python 3.10+ (Python 3.11 recommended)
- Windows, Linux, or macOS
- Network access the first time a required Solidity compiler version must be installed by `py-solc-x`

Create an isolated environment in the SlotWarner directory.

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

Verify that the command is available:

```bash
slotwarner --help
slotwarner --version
```

---

## 2. Verify the Installation

Two minimal Solidity examples are bundled with the release:

- `examples/single/SingleWarning.sol` — single-contract early-warning analysis
- `examples/flattened/StorageCollisionFlat.sol` — storage-collision detection from a flattened Proxy/Logic source

Run:

```bash
slotwarner selftest
```

On the first run, SlotWarner automatically installs the compatible Solidity compiler required by the examples. A successful run should end with results similar to:

```text
warning_prediction   = WARNING
collision_prediction = POSITIVE
passed               = true
```

Outputs are written to:

```text
results/selftest/
```

If the required `solc` versions are already installed and network access should be disabled:

```bash
slotwarner selftest --no-install-solc
```

---

## 3. Single-Contract Early Warning

A Proxy/Logic pair is not required for early-warning analysis. SlotWarner can first inspect a single Solidity contract and identify storage influenced by external inputs.

### 3.1 One file, one contract

```bash
slotwarner warning MyContract.sol --out results/my-warning
```

If the file contains exactly one concrete contract, SlotWarner selects it automatically.

Main output:

```text
results/my-warning/warning_result.json
```

Possible results:

- `WARNING` — persistent storage influenced by public/external input or supported EVM environment data was identified. This is an early warning, not by itself a confirmed storage-collision vulnerability.
- `NO_WARNING` — no such externally influenced persistent storage was identified within the supported analysis scope.
- `ABSTAIN` — SlotWarner does not have enough reliable evidence to make a result, for example because compilation failed, a dependency is missing, or the target contract cannot be resolved uniquely.

Example:

```bash
slotwarner warning examples/single/SingleWarning.sol --contract SingleWarning --out results/example-warning
```

### 3.2 Multiple contracts in one flattened file

When a `.sol` file contains multiple contract declarations, specify the target contract explicitly:

```bash
slotwarner warning Flattened.sol --contract MyLogic --out results/my-logic-warning
```

SlotWarner builds the analysis around `MyLogic`; it does not treat the entire flattened file as one deployed contract.

### 3.3 Multi-file, multi-directory projects

A Solidity source root can be provided directly:

```bash
slotwarner warning ./contracts --out results/project-warning
```

For example:

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

Keeping the original directory structure is recommended because Solidity imports, inheritance, and libraries frequently depend on relative source paths.

Batch output:

```text
warning_results.jsonl
warning_summary.json
```

If a flattened file contains several concrete contracts, analyze that file separately and use `--contract` to select the intended target.

---

## 4. Storage-Collision Detection

For local source analysis, provide a Proxy/Logic source pair to SlotWarner.

### 4.1 Proxy and Logic in separate files

If each source file contains a single concrete contract:

```bash
slotwarner collision Proxy.sol Logic.sol --out results/collision --clean
```

If either file contains multiple contracts, specify the targets:

```bash
slotwarner collision contracts/proxy/MyProxy.sol contracts/logic/MyLogic.sol --proxy-contract MyProxy --logic-contract MyLogic --out results/collision --clean
```

There is no need to flatten a multi-directory project. Pass the target files in their original source tree so relative imports can be resolved.

### 4.2 Proxy and Logic in the same flattened file

Pass the file once and specify both contract names:

```bash
slotwarner collision Flattened.sol --proxy-contract ProxyContract --logic-contract LogicContract --out results/collision --clean
```

Bundled example:

```bash
slotwarner collision examples/flattened/StorageCollisionFlat.sol --proxy-contract DemoProxy --logic-contract DemoLogic --out results/example-collision --clean
```

The example intentionally overlaps `DemoProxy.admin` with `DemoLogic.initialized/operator` in slot 0, so the expected result is:

```text
POSITIVE
```

### 4.3 Outputs

Main decision:

```text
collision_summary.json
```

Auditable intermediate artifacts are retained as well:

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

Final `prediction` values:

- `POSITIVE` — at least one operational bit-level storage-conflict candidate was identified.
- `NEGATIVE` — analysis completed, but no operational storage-conflict candidate was retained within the supported scope.
- `ABSTAIN` — the pair could not be analyzed reliably enough for a formal decision.

---

## 5. What Does `ABSTAIN` Mean?

`ABSTAIN` means that **SlotWarner refuses to guess**.

It is not the same as `NEGATIVE`, and it should not automatically be counted as an `FN`. Typical causes include:

- missing or incomplete Solidity source/dependencies;
- no compatible `solc` available;
- compilation failure;
- storage-layout reconstruction failure;
- ambiguous target contract in a flattened source;
- dynamic or assembly-heavy behavior outside the current static-analysis scope;
- insufficient historical Proxy–Logic relation evidence in on-chain benchmark scenarios.

In evaluation, ABSTAIN cases should be reported separately from TP/FP/TN/FN together with coverage. For example, if 91 out of 100 cases are analyzed and 9 are ABSTAIN, coverage is 91%.

In practical use, never interpret ABSTAIN as “safe”. Inspect `reason` and `detail`, restore missing source/import/compiler information where possible, and run the analysis again.

---

## 6. Command Cheat Sheet

```bash
# Help
slotwarner --help

# Verify installation
slotwarner selftest

# Early warning for one Solidity file
slotwarner warning MyContract.sol

# Select one contract from a flattened file
slotwarner warning Flattened.sol --contract MyContract

# Recursively scan a multi-directory Solidity source root
slotwarner warning ./contracts

# Storage-collision analysis with two source files
slotwarner collision Proxy.sol Logic.sol --clean

# Proxy and Logic in one flattened source
slotwarner collision Flattened.sol --proxy-contract ProxyContract --logic-contract LogicContract --clean
```

---

## 7. Analysis Scope and Limitations

SlotWarner is a static analyzer. It prefers an explicit uncertain result over silently treating an analysis failure as safe or vulnerable. `ABSTAIN` or reduced coverage can occur when:

- verified/complete source is unavailable;
- npm or other Solidity package dependencies are missing;
- code relies heavily on raw assembly or non-standard dynamic dispatch;
- the original compiler environment cannot be recovered;
- complex dynamic storage namespaces cannot be projected precisely.

For high-value contracts, SlotWarner should be combined with manual review, upgrade-time storage-layout checks, testing, and other security-analysis tools.

---

## Citation

If SlotWarner is useful in your research, please cite the corresponding SlotWarner paper. The final BibTeX entry can be added here once the publication metadata is available.
