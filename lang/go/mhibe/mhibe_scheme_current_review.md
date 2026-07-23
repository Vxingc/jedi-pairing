# M-HIBE 当前方案：验证、安全、复杂度与实现核对

> 本文是 `mhibe_scheme_current.md` 的配套下篇。上篇整理方案来源、数据模型、编码、查询无关空域构造与证明生成；本文集中给出 verifier、安全边界、复杂度、代码族、实验口径和实施路线。

## 6. 验证算法

验证者应执行：

1. 从可信发布渠道取得版本化的 `(epoch, digest_D, MPK, public parameters)`；
2. 检查证明的 epoch、dataset ID 和查询请求一致；
3. 对每条返回记录检查范围谓词；
4. 从实际收到的完整记录重新计算累加器输入，检查结果承诺和 degree；
5. 验证零知识累加器证明；
6. 对每个空 pattern 做严格语法、位宽和范围检查；
7. 逐个验证 HIBS 空证书，或验证安全重随机化的查询子键；
8. 检查空 pattern 全部位于查询框内且不覆盖返回坐标；
9. 检查查询框中每个未返回坐标至少被一个空 pattern 覆盖；
10. 所有检查通过才接受。

几何条件是：

```text
support(answer) intersect empty_union = empty
support(answer) union empty_union = query_box
```

空 pattern 之间可以重叠。当前实跑的最大重叠次数为 2，因此代码输出是 cover，不是严格 partition，也不是最小 cover。

当前 3D 以上 verifier 显式枚举查询内格点。这是实验正确性审计，不是与查询体积无关的 succinct verification。

## 7. 完备性论证

### 7.1 前提

完备性结论依赖以下前提：

- owner 诚实，离线父区域只覆盖真实空点；
- 全局父区域并集覆盖 `U \ support(D)`；
- 服务器不能伪造未授权 WKD-IBE/HIBS 能力；
- verifier 强制验证每个空证书；
- 空证书绑定 epoch、query、answer commitment 和 pattern；
- `digest_D` 由 owner 认证，而不是由查询进程现场自证；
- 结果承诺与实际收到的完整记录绑定。

### 7.2 固定顺序覆盖的归纳思路

按固定维度顺序归纳：

1. 在第一维，空点要么落入完全空的前缀子树，直接由该前缀加后续通配符覆盖；要么落入有数据的第一维前缀并继续下降。
2. 假设前 `j-1` 维父前缀已固定。若目标点第 `j` 维落入父节点下的空隙，则空隙规范覆盖包含它；否则沿有占用的第 `j` 维前缀下降。
3. 到最后一维时，所有非真实点均落入某个空隙规范节点，而真实点不落入任何空隙。

在完整索引、完整递归且 `max-parent-dim=NumDims` 时：

$$
\bigcup_{P\in\mathcal G}R(P)=U\setminus\operatorname{support}(D),
$$

且每个 `R(P)` 与真实坐标集合不相交。

### 7.3 查询遗漏的反证

若服务器遗漏真实查询坐标 `x`，几何覆盖要求 `x` 被某个空 pattern `C` 覆盖。有效证书又表示 `C` 从 owner 签发的全局空父区域派生。但 owner 不会为包含真实坐标 `x` 的区域签发空能力，矛盾。

所以遗漏要通过验证，服务器必须伪造空证书、破坏结果承诺、利用错误离线索引，或利用 verifier 未检查的输入。

### 7.4 重复坐标缺口

若同一坐标有两条记录而服务器只返回一条，`support(answer)` 仍包含该坐标，空覆盖不会覆盖它，而 accumulator subset proof 只证明返回项属于数据库，不证明该坐标的所有记录均返回。

因此当前代码严格支持的是**唯一坐标支持集完备性**。记录级完备性需要至少一种补充：

1. 假设查询坐标本身唯一；
2. owner 认证每坐标 multiplicity，客户端检查返回数量；
3. 把唯一记录 ID 纳入可证明查询语义；
4. 证明补集中不存在满足查询谓词的记录。

TPC-H benchmark 已出现 `matching rows` 多于 `unique spatial points`，所以论文不能忽略这一点。

## 8. 隐私、非交互性与新鲜性

### 8.1 可保守主张

- 不需要发送查询外相邻边界记录；
- 查询子 pattern 被裁剪到查询框内；
- ZK accumulator 隐藏补集 witness 和结果多项式随机性；
- 若空覆盖是 query 与完整 answer 的确定性函数，其几何结构不超出允许 leakage。

### 8.2 当前不能直接主张

- M-HIBE secret key 本身不是标准 ZK proof；
- 当前没有 formal leakage function 或 simulator；
- pattern 数量、形状、答案数量、证明长度和时间均可能泄露信息；
- 发送派生 key 会产生可转移能力；
- 全零 transcript 不能防跨查询、跨数据版本重放。

### 8.3 非交互的准确表述

客户端先发送查询，服务器随后一次返回 answer 与 VO，客户端不再发送随机挑战。这是“查询后的单消息非交互验证”。

推荐的空证书是 HIBS signature：服务器用查询子键签名 `transcript || pattern`，客户端公开验证。它与 PoPETs 2016 第 8 页一致。当前代码尚未接入 `wkdibe.Sign/Verify`。

### 8.4 新鲜性

区块链只有在证明绑定链上版本时才提供新鲜性。transcript 至少应包含：

```text
chain id || contract id || dataset id || epoch/block height || digest_D
```

“使用区块链”本身不会自动阻止旧证明重放。

## 9. 复杂度

### 9.1 记号

- `n`：记录数；`n_s`：唯一坐标数；
- `d`：维数；`b_i`：第 `i` 维位宽；`L=sum b_i`；
- `G`：全局空父区域数；`S`：查询空子区域数；
- `C`：候选 pattern 数；`V=|Q|`：查询格点体积；
- `w=64`：当前 bitset 字宽。

### 9.2 离线索引

当前显式前缀组合索引的主项为：

$$
T_{index}=\Theta\left(
n_s\sum_{k=1}^{d-1}\prod_{j=1}^{k}(b_j+1)
\right).
$$

统一位宽 `b` 时为 `Theta(n_s(b+1)^(d-1))`。它避免枚举 `2^(sum b_i)` 个全域点，但仍随维数指数增长。

安全表述应是：

> 构造避免完整坐标宇宙枚举，并在固定低维下形成数据/前缀相关的稀疏表示；维数增长仍是主要扩展性限制。

不能表述为“将任意维数的指数复杂度降成多项式”。

### 9.3 密钥与证明大小

父区域和父键生成至少为 `O(G)+G*T_KeyGen`。当前压缩序列化、启用 signature support 时：

$$
|PP|=337+48L\ bytes,
\qquad
|SK_P|=193+52f_P\ bytes,
$$

其中 `f_P` 是自由槽数。程序打印的 key material 不含 pattern 字符串、Go map、`big.Int` 和运行时对象。

当前 accumulator 子证明约为：

```text
ZK membership proof: 928 B
ZK degree proof:     296 B
合计:               1224 B
```

打印值未包含约 96 B 的 `C_I`，也未包含 M-HIBE patterns 和证书。总 VO 为：

$$
|VO|=|A|+O(SL)+\sum_i|cert_i|+O(1)_{accumulator},
$$

所以只有 accumulator 子证明近似常数，总证明不是常数大小。

### 9.4 在线与 verifier

当前实现扫描全部 `G` 个全局区域求交；每个查询 pattern 再扫描全局区域找父节点，最坏 `O(SG)`；candidate bitset 内存约 `O(CV/w)`；几何验证约 `O(V + sum_i |R(C_i)|)`。

因此全局索引和查询体积都会成为瓶颈。

### 9.5 高维结论

- 2D 是当前最完整的协议实现；
- 3D 可运行，但完整全域 offline 已昂贵；
- 4D 全域 materialization 可能数小时或 OOM；
- 5D/10D 完整 materialization 在当前表示法下通常不可完成；
- 并行降低常数，不改变指数主项；
- `max-parent-dim<NumDims` 改变完备性，不能与完整协议混报；
- `max-global-regions` 超限会 panic，不是近似正确结果。

已有优化包括 `cmd_bench_4d_varbits.go` 的 `{12,4,6,4}` 位宽、`cmd_bench_4d_order_opt.go` 的顺序实验，以及 `cmd_bench_4d_memopt.go` 的压缩前缀 ID、occupancy bitmap、逐 shard 释放和显式 GC。

内存实验仍未做坐标去重、流式候选、分批落盘和 query-touched 父键加载，因而没有改变增长阶。

## 10. 代码族

### 10.1 最接近目标协议

| 用途 | 文件 | 说明 |
|---|---|---|
| 2D offline serial | `cmd_bench_2d_offline_serial.go` | 查询前完成全域父区域与全部父键 |
| 2D full audit | `cmd_bench_2d_full_audit.go` | 区分协议验证与完整 crypto audit |
| 2D full parallel audit | `cmd_bench_2d_offline_full_crypto_parallel.go` | 查询无关 offline、并行、全 key audit |
| 3D offline | `cmd_bench_3d_full_audit.go` | 完整域 `X -> Y -> Z` |
| 3D offline parallel | `cmd_bench_3d_full_audit_parallel.go` | 当前 3D 主参考 |
| 4D full-domain | `cmd_bench_4d_full_audit{,_parallel}.go` | 逻辑完整，扩展性压力大 |
| 4D memory experiment | `cmd_bench_4d_memopt.go` | 当前未提交实验，不是稳定基线 |

### 10.2 其他文件

普通 `cmd_bench_{2d,3d,4d,5d,10d}.go` 及多种 parallel 文件主要是 query-touched 性能原型，不能报告为完整查询无关 setup。

`cmd_bench.go` 和 `cmd_bench_2_exact_cover.go` 是旧 Multi/Hexa-Sweep 或 exact-cover；`acc_chun_*.go` 是独立 accumulator 基线；4-bit toy tests 不覆盖当前 12-bit 主程序。所有主 benchmark 都带 `//go:build ignore`，常规 `go test` 不会编译它们。

`lang/go/mhibe` 当前是一组复制演化的独立 `main`，不是共享协议包。论文定稿前应抽出 encoding、canonical cover、offline index、empty certificate、proof、verifier 和 benchmark 模块。
