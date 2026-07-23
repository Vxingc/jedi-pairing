# M-HIBE 当前方案：实验口径、声明修订与实施路线

> 本文是方案整理的第三部分。核心构造见 `mhibe_scheme_current.md`；验证、安全、复杂度与代码族见 `mhibe_scheme_current_review.md`。

## 11. 实验映射与计时

### 11.1 TPC-H 字段

| 维数 | 字段 |
|---|---|
| 2D | shipdate、discount*100 |
| 3D | 2D + quantity |
| 4D | 3D + tax*100 |
| 5D | 4D + line number |
| 10D | 再加 extendedprice/1000、commit date、receipt date、partkey mod 4096、suppkey mod 4096 |

当前数据文件有 120,515 行。多数文件的 `-poneglyph-q6` 会把 `limit=0` 改为前 120,000 行，论文应区分“120K 前缀”和“120,515 全文件”。

10D 默认只读 5000 行，额外五维围绕第一个满足前三维的样本取 `extra-width=0` 单点范围，因此它不是一般宽 10D 查询。

### 11.2 正确计时分类

**Offline/setup**：

- WKD-IBE 公共参数；
- 全库 occupancy index；
- 全域空父区域和父键；
- owner 的 `digest_D`；
- 已有 SRS 的磁盘加载应单列，不能称为可信设置生成。

**Online server**：

- 查询扫描和 `A/X` 构造；
- `digest_X` 或补集 witness；
- 空区域查询、裁剪与子证书派生；
- accumulator prover。

**Client protocol**：

- 谓词检查；
- 结果承诺与实际记录绑定；
- 每个空证书验证；
- 几何覆盖；
- accumulator verifier。

**Experimental audit**：

- trusted owner 的全域覆盖审计；
- 全父键或全子键 crypto self-check；
- 其他不属于部署协议的 exhaustive 检查。

当前 `zkCommitMs` 混合查询无关 `Commit(DB)` 与查询相关 `Commit(X)`，并整体计入 setup；数据读取、查询扫描和 `I/X` 构造通常不计时。这会低估 online prover。旧 CSV 的跨方案数字不能直接作为当前公平比较。

### 11.3 当前 smoke run

2026-07-20 运行：

```text
cmd_bench_2d_offline_serial.go
-limit 1000 -skip-zk -verify-offline-global=false
```

当前输出：

```text
loaded rows:                 1000
matching rows/coordinates:     48 / 48
global empty parents:         3161
query empty regions:           180
real query coordinates:         48
empty query coordinates:      1047
query volume:                 1095
max empty-cover overlap:         2
sampled same-pattern checks:     64
```

`48 + 1047 = 1095` 通过，说明 2D query-independent 流程在该输入上自洽。该运行跳过 ZK、关闭全域审计，且小数据产生了大量全域父键，不能作为论文性能结果。

## 12. PPT 声明修订

| 当前表述 | 问题 | 建议表述 |
|---|---|---|
| 存储从指数级降为多项式 | 对固定维数的 `n,b` 多项式不等于对维数 `d` 多项式 | 避免完整宇宙枚举；固定低维为数据/前缀相关稀疏表示，维数增长仍受限 |
| M-HIBE 实现零知识 | 空 pattern 和 key/signature 有明确 leakage，当前无模拟证明 | M-HIBE 提供查询局部空能力；整体隐私由 leakage 定义和 ZK accumulator 共同论证 |
| 服务器发送空证明签名 | 这是 PPT/PoPETs 的目标形式，当前代码未调用 Sign/Verify | 论文采用 HIBS；当前代码只是 key-reveal 原型，签名尚待接入 |
| 返回数据正确完整 | 当前只哈希坐标，几何层只处理唯一坐标 | 当前验证坐标真实性与空间支持集完备性；完整行和重复记录待完成 |
| 支持任意维 | 参数化到 10D 不等于完整高维实验可完成 | 语义参数化到 d 维；工程可行性集中于 2D/3D，4D 以上是边界实验 |
| 证明常数大小 | 只有 accumulator 子证明近似常数 | 总 VO 随 answer 和空证书数增长 |
| 链上验证 | 当前无合约、pairing gas 或链上实验 | 区块链是版本摘要锚和可选结算层，链上路径尚待实现 |

## 13. 必须解决的问题

### P0：安全声明成立前

1. **逐个验证所有空证书**：不能只做几何，也不能只抽样 64 个；
2. **停止向客户端发送 `NonDelegableQualifyKey` 输出**：改用 HIBS 或普通 `QualifyKey`；
3. **可信锚定 `digest_D`**：由 owner 签名或写入版本化公开账本；
4. **绑定完整 statement**：transcript 包含 epoch、query、answer commitment、patterns 和参数标识；
5. **绑定记录与 `C_I`**：客户端从实际记录重算编码并检查 degree 等于记录数；
6. **认证完整记录**：哈希唯一主键、查询坐标和需要认证的 payload；
7. **解决重复坐标 multiplicity**；
8. **严格 pattern validator**：拒绝 `*1` 等非前缀形状；
9. **角色隔离**：实现 owner/server/verifier、VO 序列化和恶意输入测试。

### P1：可信实验与低维可用性

1. 修正 timing accounting；
2. 抽共享包，消除 benchmark 语义漂移；
3. 为 global parent 建索引，消除当前 `O(SG)`；
4. 先去重坐标，再建 occupancy；
5. 联合真实位宽和维度顺序优化；
6. 流式 candidate、分批构造和父键持久化；
7. index worker 与 crypto worker 分开；
8. 增加 omission、forgery、malformed pattern 和 replay tests；
9. 移除 `go.mod` 对 `/home/xing/bp` 的绝对本地 replace。

### P2：系统扩展

- 动态更新、epoch 切换和能力撤销；
- HIBS 批量验证或聚合；
- 区块链合约、BLS12-381 支持和 gas 评估；
- 访问模式隐私；
- 高维持久化稀疏索引或替代证明系统；
- formal soundness、history independence 和 leakage-based ZK 证明。

## 14. 推荐实现顺序

1. 从 2D offline serial 抽共享协议库；
2. 实现 owner/server/verifier 和序列化 VO；
3. 修复 owner digest、完整记录编码、transcript 和结果承诺绑定；
4. 接入 `wkdibe.Sign/Verify`，用 HIBS 替代 key reveal；
5. 增加 omission、fake row、fake pattern、wrong key、replay 测试；
6. 明确唯一坐标假设或 multiplicity 机制；
7. 完成公平计时的 2D 全协议 benchmark；
8. 推广到 3D full-audit parallel；
9. 再做变长位宽、顺序、去重和批处理；
10. 4D 在 memory profile 和 bounded batches 可复现后再作为系统结果。

## 15. 材料溯源

### 15.1 PDF

| 材料 | 关键作用 | 关键页 |
|---|---|---|
| `popets-2016-0045.pdf` | 一维 HIBE/HIBS、交互/非交互、安全与 ZK | pp. 4-11，尤其 p. 8 |
| `An_Approach_to_Function_as_M_HIBE.pdf` | d 维 identity 展平为 WKD wildcard pattern | pp. 1-2 |
| `mhibeconstruction.pdf` | WKD 构造、KeyGen/Encrypt/Decrypt、history independence | pp. 2-6，尤其 p. 5 |
| `proof_of_completeness.pdf` | 二维父补充与 `O(nl^2)` 分析 | pp. 1-5；p. 6 仅简述 d 维 |
| `Verifiable_Multi_Dimensional_Range_Queries_over_Outsourced_Datasets_in_Zero_Knowledge.pdf` | 朴素二维失败与补充父区域动机 | pp. 4-6 |
| `Taking Authenticated Range Queries to Arbitrary Dimensions.pdf` | 每维一维结果 + set algebra 的相关工作 | pp. 1-8 |

`Taking Authenticated Range Queries...` 追求各项成本对维数线性，但不提供当前 M-HIBE 构造，也不是当前零知识声明的直接依据。

### 15.2 当前 PPT

| 幻灯片 | 可保留内容 | 需要修订内容 |
|---|---|---|
| 2-3 | 双层方案和按数据分布聚合空块 | 严格区分真实性与完备性 |
| 5 | owner/server/client/chain 模型 | 区块链当前只是目标部署；补 epoch 和可信摘要 |
| 10 | accumulator 用于真实性，不用于逐空点完备性 | 常数证明只指 accumulator 子证明 |
| 11 | 一维 HIBE 空节点思路 | 非交互版本应表述为 HIBS |
| 12 | 多维规范覆盖笛卡尔积 | 它只编码矩形，不解决全域空密钥数量 |
| 13 | 固定顺序宏观扫描 + 微观填充 | 删除对维数多项式和当前已实现签名的过强表述 |
| 14 | TPC-H 与三维字段 | 旧时间不能继续作为当前可复现实验结果 |

### 15.3 当前验证结果

2026-07-20 已核验：

```text
go test ./lang/go/mhibe   PASS
go test ./lang/go/wkdibe  PASS
```

前一命令只运行 4-bit toy tests，不编译带 `//go:build ignore` 的主 benchmark。2D offline serial、3D offline parallel、4D memopt、4D varbits 和 10D offline parallel 已能独立编译；这不替代协议级恶意输入测试。

## 16. 一句话论文定位

> 我们提出一种面向静态、低维离散范围查询的双层可验证构造：零知识多项式累加器认证返回结果，WKD-IBE 实例化的固定顺序多维空域能力覆盖证明查询支持集完备性。该方法避免枚举完整坐标宇宙，并把空域证明限制在查询局部；其当前实现对 2D/3D 有效，但离线前缀组合和查询格点枚举仍限制高维扩展性。
