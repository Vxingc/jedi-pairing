# M-HIBE Experiment Review and Reproduction Guide
# M-HIBE 实验审阅与复现指南

This document is the entry point for reviewers of the M-HIBE range-query experiments in this directory. It describes the code as it exists in this checkout. The programs are research prototypes, not production services.

本文是本目录 M-HIBE 范围查询实验的审阅与复现入口。内容以当前代码为准；这些程序是研究原型，不是生产服务。

## 1. Scope and Entry Points / 范围与入口

| Purpose / 用途 | Current entry point / 当前入口 | Dimensions / 维数 |
| --- | --- | --- |
| Proposed scheme: query-independent offline M-HIBE empty-region material, online delegation, geometric completeness check, and optional ZK authenticity / 主方案：查询无关离线 M-HIBE 空区域材料、在线委托、几何完整性检查及可选 ZK 真实性 | `cmd_bench_2d_perbit.go` through `cmd_bench_6d_perbit.go` | 2D--6D |
| Native ZK-accumulator baseline: membership for correctness plus non-membership for full query completeness / 原生 ZK 累加器对比：成员证明正确性加非成员证明查询完整性 | `acc_chun_2d.go`, `acc_chun_3d.go` | 2D, 3D only |
| Historical iterations / 历史迭代版本 | `history/` | Do not use as the primary reproduction target / 不作为主复现实验入口 |

The source names in the original request, `cmd_bench_xd_perbit.go` and `acc_chun_xd.go`, denote these dimension-specific file families. They are not files in a `cmd/` subdirectory.

原请求中的 `cmd_bench_xd_perbit.go` 与 `acc_chun_xd.go` 指的是上述按维数展开的文件族，而不是 `cmd/` 子目录下的实际文件。

**Current labeling caveat.** Every current `cmd_bench_*d_perbit.go` file has copied console labels that say `4D`, including the 2D, 3D, 5D, and 6D files. This is a reporting-label defect, not evidence that those files run a 4D configuration. Identify a run by the executed filename and the number of printed `dimN` bounds. This guide documents the issue but does not alter the experimental source.

**当前标签注意事项。** 当前所有 `cmd_bench_*d_perbit.go` 文件都保留了写成 `4D` 的复制控制台标签，其中包括 2D、3D、5D 和 6D 文件。这是报告标签缺陷，不代表这些文件实际运行 4D 配置。请以所执行的文件名和打印出的 `dimN` 边界数量识别运行维数。本文档记录该问题，但不修改实验源代码。

All experiment files deliberately start with `//go:build ignore`. Run an explicitly named source file, for example `go run ./cmd_bench_2d_perbit.go`; do not run `go run .` in this directory.

所有实验文件都刻意带有 `//go:build ignore`。必须显式运行单个源文件，例如 `go run ./cmd_bench_2d_perbit.go`；不要在本目录执行 `go run .`。

## 2. Protocol Summary / 协议概要

The proposed program has two distinct components.

1. **M-HIBE component (Engine A).** It builds a database-wide prefix-occupancy index and database-wide empty parent regions before a query arrives. For a query, it intersects and crops those global regions, chooses a cover, delegates query-scoped keys, and checks that selected empty regions cover every empty query point but no returned point.
2. **ZK-accumulator component (Engine B).** When ZK is enabled, it commits to database data and proves membership of the returned set. The code reports its time separately from the M-HIBE geometric check.

主方案包含两个相互区分的部分。

1. **M-HIBE 部分（Engine A）。** 查询到来前，程序建立数据库范围的前缀占用索引和全局空父区域。查询到来后，程序相交并裁剪这些全局区域、选择覆盖、委托查询范围密钥，并检查选中的空区域覆盖所有查询内空点且不覆盖返回点。
2. **ZK 累加器部分（Engine B）。** 启用 ZK 时，程序对数据库数据作承诺，并对返回集合生成成员证明。代码将它与 M-HIBE 的几何完整性检查分别计时。

The native accumulator baseline takes a different route: it directly enumerates every absent coordinate in the query box, then proves that this empty set is disjoint from the database. It is a useful baseline, but its empty-point enumeration is not equivalent to the proposed scheme's query-independent offline construction.

原生累加器基线采用不同路径：它直接枚举查询盒中每一个不存在的坐标，再证明该空集合与数据库不相交。它是有价值的对比基线，但其空点枚举不等同于主方案的查询无关离线构造。

## 3. Data Model and Default Query / 数据模型与默认查询

Input is a pipe-delimited TPC-H `lineitem` table. The table is not included in this checkout. Supply a compatible `lineitem_120K.tbl` (or another compatible subset) through `-data`.

输入是以竖线分隔的 TPC-H `lineitem` 表。本仓库当前未包含该 `.tbl` 文件。请通过 `-data` 提供兼容的 `lineitem_120K.tbl` 或其他兼容子集。

The proposed-program coordinate order is fixed in the current files:

| Dimension / 维度 | TPC-H field / TPC-H 字段 | Default width / 默认位宽 |
| --- | --- | --- |
| 0 | `l_shipdate`, encoded as days since 1992-01-01 | 12 |
| 1 | `l_discount * 100`, rounded | 4 |
| 2 | `l_quantity`, converted to integer | 6 |
| 3 | `l_tax * 100`, rounded | 4 |
| 4 | `l_linenumber` | 4 |
| 5 | `floor(l_extendedprice / 1000)` | 4 |

For 2D--6D, the program uses the first 2--6 rows of this table. The default base query is ship date `1994-01-01` through `1994-12-31`, encoded discount `5` through `7`, and, from 3D onward, quantity `0` through `23`. Dimensions 3 and above are anchored around an observed matching record; `-extra-width` controls their half-width. Always record the printed query bounds, which are the authoritative values after parsing and clamping.

对于 2D--6D，程序依次采用表中的前 2--6 个维度。默认基础查询为船运日期 `1994-01-01` 至 `1994-12-31`、编码折扣 `5` 至 `7`，并从 3D 开始加入数量 `0` 至 `23`。第 3 维及以上围绕一个已匹配记录锚定；`-extra-width` 控制其半宽。请始终记录程序打印出的查询边界，它才是解析和截断后的权威值。

The accumulator baselines use a fixed 12-bit encoding per dimension, while the proposed program uses the widths shown above. When comparing them, use the same raw data, row limit, and explicit coordinate bounds, and report this encoding difference.

累加器基线每一维使用固定的 12 位编码，而主方案使用上表位宽。做比较时应使用相同原始数据、行数上限和显式坐标边界，并报告这一编码差异。

## 4. Prerequisites / 环境前置条件

The checked-in `go.mod` requires Go 1.24 or newer and contains an author-local replacement:

```text
replace github.com/accumulators-agg/bp => /home/xing/bp
```

Consequently, a fresh checkout is not self-contained. The reviewer must obtain the `github.com/accumulators-agg/bp` source used for the experiment and point Go at its local copy. Linux or WSL2 on x86-64 is the supported reproduction environment in practice. Native Windows has not been validated; the current static archives and replacement path are Unix-oriented.

因此，刚克隆的仓库不是自包含的。审阅者必须取得实验所使用的 `github.com/accumulators-agg/bp` 源码，并将 Go 指向该本地副本。实际建议在 x86-64 Linux 或 WSL2 上复现。原生 Windows 尚未验证；当前静态库和替换路径均面向 Unix。

Install a C/C++17 toolchain, `make`, Git, and Go with CGo enabled. The Go bindings link static `pairing.a` archives and `-lstdc++`; therefore `g++` and the matching native build environment are required.

请安装 C/C++17 工具链、`make`、Git，并使用启用 CGo 的 Go。Go 绑定会链接静态 `pairing.a` 和 `-lstdc++`，因此需要 `g++` 以及匹配的原生构建环境。

### Workspace-local dependency override / 工作区本地依赖覆盖

From the repository root, create an uncommitted Go workspace override. This leaves the checked-in `go.mod` unchanged.

在仓库根目录创建一个不提交的 Go workspace 覆盖配置。该做法不修改已提交的 `go.mod`。

```bash
git clone https://github.com/accumulators-agg/bp.git "$HOME/src/bp"
go work init .
go work edit -replace github.com/accumulators-agg/bp="$HOME/src/bp"
go mod download
go env GOWORK
```

If the public repository does not match the authors' dependency revision, request the exact `bp` checkout used for the experiment and use that path instead. Record its commit ID alongside the M-HIBE repository commit.

若公开仓库与作者实验依赖的版本不匹配，请索取作者使用的精确 `bp` 工作副本并替换上述路径。应同时记录其提交号和 M-HIBE 仓库提交号。

The repository already contains `pairing.a` files under the Go binding packages. If a target-system or linker mismatch occurs, rebuild the archive at the repository root and copy it into the binding directories before retrying:

仓库在 Go 绑定包下已包含 `pairing.a`。若出现目标系统或链接器不匹配，请在仓库根目录重新构建静态库，再复制到绑定目录后重试：

```bash
make
for package_dir in lang/go/bls12381 lang/go/cryptutils lang/go/internal lang/go/lqibe lang/go/wkdibe; do
  cp pairing.a "$package_dir/pairing.a"
done
```

## 5. Quick Start / 快速开始

Run from `lang/go/mhibe`, not from the repository root. This is important because the proposed programs load accumulator material from `./pkvk-17`.

必须在 `lang/go/mhibe` 目录运行，而非仓库根目录。主方案从 `./pkvk-17` 加载累加器材料，因此当前工作目录很重要。

```bash
cd /path/to/jedi-pairing/lang/go/mhibe
DATA=/absolute/path/to/lineitem_120K.tbl

# 2D smoke test: M-HIBE path only; ZK/SRS loading is skipped.
go run ./cmd_bench_2d_perbit.go \
  -data "$DATA" -limit 100 -mhibe-workers 1 -skip-zk
```

The smoke test confirms parsing, M-HIBE setup, query-independent initialization, online cover generation, delegation, and geometric completeness. It is not a full end-to-end ZK result.

上述冒烟测试验证数据解析、M-HIBE 初始化、查询无关离线构造、在线覆盖生成、委托和几何完整性。它不是包含 ZK 的端到端结果。

For a full 2D protocol run, omit `-skip-zk`. Start with a small row limit and increase it only after recording memory and elapsed time.

要运行完整 2D 协议，请去掉 `-skip-zk`。先使用较小的行数上限；记录内存与耗时后再逐步增大。

```bash
go run ./cmd_bench_2d_perbit.go \
  -data "$DATA" -limit 1200 -mhibe-workers 4 \
  2>&1 | tee mhibe_2d_1200.log
```

For 3D, use the corresponding source file. Begin with a small input; its database-wide encoded domain is substantially larger than 2D.

对于 3D，使用相应源文件。应从小输入开始；它的数据库范围编码域明显大于 2D。

```bash
go run ./cmd_bench_3d_perbit.go \
  -data "$DATA" -limit 1200 -mhibe-workers 4 \
  2>&1 | tee mhibe_3d_1200.log
```

The same pattern applies to 4D--6D by changing the filename. These are stress experiments, not a promise that all full-data runs will fit in memory.

将文件名替换为 4D--6D 即可使用相同模式。这些是压力实验，并不保证所有全数据运行都能放入内存。

## 6. Baseline Commands / 对比基线命令

Use an identical input file, `-limit`, and explicit query parameters when comparing a dimension supported by both programs. The following 2D pair avoids the `-poneglyph-q6` shortcut and therefore shares the default inclusive raw bounds.

比较两个程序均支持的维度时，请使用相同输入文件、`-limit` 和显式查询参数。下面的 2D 命令对不使用 `-poneglyph-q6` 快捷参数，因此共享默认的闭区间原始边界。

```bash
# Proposed M-HIBE + ZK program
go run ./cmd_bench_2d_perbit.go \
  -data "$DATA" -limit 1200 -mhibe-workers 1 \
  -date-min 1994-01-01 -date-max 1994-12-31 \
  -discount-min 5 -discount-max 7 \
  2>&1 | tee proposed_2d.log

# Native accumulator baseline; use real witness generation for a security-comparable run.
go run ./acc_chun_2d.go \
  -data "$DATA" -keys ./pkvk-17 -limit 1200 -proof-mode real \
  -date-min 1994-01-01 -date-max 1994-12-31 \
  -discount-min 5 -discount-max 7 \
  2>&1 | tee accumulator_2d_real.log
```

Repeat with `cmd_bench_3d_perbit.go` and `acc_chun_3d.go`, adding `-quantity-min 0 -quantity-max 23` to both commands.

将文件替换为 `cmd_bench_3d_perbit.go` 和 `acc_chun_3d.go` 后即可进行 3D 对比；同时为两条命令添加 `-quantity-min 0 -quantity-max 23`。

Important: `acc_chun_*` defaults to `-proof-mode trapdoor`, whereas the proposed program's Engine B calls the ordinary accumulator `Commit` path. Do not present trapdoor-baseline timings as security-equivalent to the proposed full ZK run. Use `-proof-mode real` for the comparable setting, or label trapdoor results clearly as a compatibility/lower-cost configuration.

重要提示：`acc_chun_*` 默认采用 `-proof-mode trapdoor`，而主方案的 Engine B 调用普通累加器 `Commit` 路径。不得将 trapdoor 基线计时表述为与主方案完整 ZK 运行具有相同安全语义。可比设置应使用 `-proof-mode real`；若使用 trapdoor，必须明确标注其为兼容/低成本配置。

Do not use `-poneglyph-q6` blindly for cross-program comparisons. In the current M-HIBE files it selects inclusive discount `[5, 7]`; in the accumulator baseline it selects the strict SQL-style discount predicate and encodes it as `[6, 6]`. Specify bounds explicitly instead.

跨程序比较时不要直接使用 `-poneglyph-q6`。当前 M-HIBE 文件会选择包含端点的折扣 `[5, 7]`；累加器基线则实现严格 SQL 风格条件，并编码为 `[6, 6]`。比较时应显式指定边界。

## 7. Parameters That Change Interpretation / 会改变结果含义的参数

| Flag / 参数 | Meaning / 含义 | Review rule / 审阅规则 |
| --- | --- | --- |
| `-skip-zk` | Skip accumulator SRS load, proving, and verification / 跳过累加器 SRS、证明和验证 | Use only for smoke tests or M-HIBE profiling; not a full protocol result / 仅用于冒烟或 M-HIBE 剖析，不是完整协议结果 |
| `-upload-keys` | Materialize one WKD-IBE key per database row / 为每条数据库记录物化一个 WKD-IBE 密钥 | Optional record-level access-control stress work; report separately from the empty-region protocol / 可选的记录级访问控制压力项，应与空区域协议成本分开报告 |
| `-mhibe-workers` | Parallelism used by M-HIBE proving and client verification / M-HIBE 证明和客户端验证并行度 | Fix and report it with CPU details / 固定该值并连同 CPU 信息报告 |
| `-dim-bits` | Per-dimension encoded domain widths / 各维编码域位宽 | Changes the domain and offline work; record exact values / 改变编码域及离线工作量，必须记录 |
| `-expand-parent-dims` | Dimensions permitted to expand as parent prefixes / 允许作为父前缀展开的维度 | Algorithm/configuration change; record it / 属于算法配置变化，必须记录 |
| `-max-global-regions` | Abort guard for global empty-region generation / 全局空区域生成的中止保护阈值 | An abort is a scaling observation, not a successful run / 中止是扩展性现象，不是成功结果 |
| `-max-parent-dim` | Caps recursive parent depth / 限制父节点递归深度 | Changes completeness semantics; never present it as an exact full-depth run / 改变完整性语义，不得表述为精确全深度运行 |
| `-extra-width` | Half-width of dimensions 3+ around an exemplar / 第 3 维以上围绕样本点的半宽 | Changes the query; print and retain final bounds / 改变查询，应保存最终打印边界 |

## 8. What to Record / 应记录的内容

For each run, retain the complete console log and the following metadata:

- Git commit of this repository and of the external `bp` dependency.
- OS, CPU model/core count, RAM, compiler, Go version, and `CGO_ENABLED` value.
- Data file provenance and checksum, actual rows loaded, `-limit`, all flags, and printed query bounds.
- For the proposed scheme: offline index build, global-region enumeration, global parent-key generation, Engine A extraction/delegation, geometric completeness verification, ZK commitment/proving/verification, and key-material sizes.
- For the baseline: data load/direct partition, empty-set enumeration, commitment, Proof A, Proof B, verification, proof size, and proof mode.
- Whether `-upload-keys`, `-skip-zk`, any cap, or any non-default bit width was used.

每次运行都应保存完整控制台日志和以下元数据：

- 本仓库以及外部 `bp` 依赖的 Git 提交号。
- 操作系统、CPU 型号/核数、内存、编译器、Go 版本和 `CGO_ENABLED` 值。
- 数据文件来源和校验和、实际加载行数、`-limit`、所有参数和打印出的查询边界。
- 主方案：离线索引构建、全局区域枚举、全局父密钥生成、Engine A 提取/委托、几何完整性验证、ZK 承诺/证明/验证和密钥材料大小。
- 基线：数据加载/直接划分、空集合枚举、承诺、证明 A、证明 B、验证、证明大小和证明模式。
- 是否使用 `-upload-keys`、`-skip-zk`、任何上限或非默认位宽。

The proposed program's final report accounts for setup as cryptographic setup plus query-independent offline initialization plus ZK commitment; server proving as Engine A plus the ZK prover; and client verification as geometric checking plus the ZK verifier. Optional upload-key materialization is printed separately. Keep these categories separate when constructing tables.

主方案最终报告将设置时间计为密码学设置、查询无关离线初始化和 ZK 承诺之和；服务器证明时间计为 Engine A 和 ZK 证明器之和；客户端验证时间计为几何检查和 ZK 验证器之和。可选的上传密钥物化会单独打印。整理表格时应保持这些类别分离。

## 9. Expected Limits and Honest Reporting / 已知限制与如实报告

The database-wide prefix-combination representation grows quickly with dimension. In this prototype, 2D is the practical starting point, 3D may be expensive, and 4D or above can take a long time or exhaust memory. More workers reduce some constants but can also increase peak memory because index shards and key material coexist.

数据库范围前缀组合表示会随维数快速增长。在当前原型中，2D 是实际可用的起点，3D 可能昂贵，4D 及以上可能耗时很长或耗尽内存。增加工作线程可降低部分常数，但也可能因索引分片与密钥材料同时驻留而提高峰值内存。

Treat an out-of-memory event, a region-cap abort, or a multi-hour run as a result about the current representation's scalability. Do not hide it by lowering `-max-parent-dim` and then claim the same completeness protocol. Report any capped or partial run explicitly.

内存溢出、区域上限中止或多小时运行都是当前表示法扩展性的结果。不得通过降低 `-max-parent-dim` 隐藏问题后仍声称实现了相同的完整性协议。所有受限或部分运行都必须明确报告。

## 10. Troubleshooting / 常见问题排查

| Symptom / 现象 | Cause and action / 原因与处理 |
| --- | --- |
| `replacement directory /home/xing/bp does not exist` | Configure the workspace-local `go.work` replacement in Section 4 / 按第 4 节配置本地 `go.work` 替换 |
| `build constraints exclude all Go files` | You used package mode; run the named `.go` file directly / 使用了包模式；请直接运行指定 `.go` 文件 |
| Cannot find `pkvk-17` files | Run proposed files from `lang/go/mhibe`; for the baseline, pass an absolute `-keys` path if needed / 主方案须从 `lang/go/mhibe` 运行；基线可按需传绝对 `-keys` 路径 |
| CGo or linker error involving `pairing.a` | Use a matching Linux/WSL toolchain and rebuild/copy the archive as in Section 4 / 使用匹配的 Linux/WSL 工具链，并按第 4 节重建/复制静态库 |
| `max-global-regions` panic | The guard stopped an oversized complete-domain construction. Lower the dataset size for diagnosis, record the failure, or redesign the representation; do not label it a completed exact run / 该保护阻止了过大的全域构造。可降低数据规模进行诊断、记录失败或重构表示；不得标注为已完成的精确运行 |
| High memory or no progress in 4D+ | Reduce the input for a diagnostic run and capture peak memory. The current code materializes substantial global index/key state / 先缩小输入作诊断并记录峰值内存；当前代码会物化大量全局索引/密钥状态 |

## 11. Review Checklist / 审阅检查表

- Does the run use the current `*_perbit.go` entry point rather than an unlabelled historical variant?
- Is the M-HIBE offline stage demonstrably query independent and over the configured full encoded domain?
- Are raw data, row limit, query bounds, proof mode, and bit widths identical or explicitly reconciled for each comparison?
- Are protocol costs separated from optional upload work and from experimental audits?
- Are `-skip-zk`, caps, partial runs, or trapdoor mode clearly marked?
- Do all reported success claims include the printed geometric completeness result and, when enabled, successful ZK verification?

- 运行是否使用当前 `*_perbit.go` 入口，而非未标注的历史变体？
- M-HIBE 离线阶段是否确实查询无关，并覆盖所配置的完整编码域？
- 每组比较的原始数据、行数上限、查询边界、证明模式和位宽是否一致，或已明确说明差异？
- 协议成本是否与可选上传工作、实验审计分开？
- 是否清楚标注 `-skip-zk`、上限、部分运行或 trapdoor 模式？
- 所有成功结论是否同时包含打印出的几何完整性结果，以及在启用时成功的 ZK 验证？
