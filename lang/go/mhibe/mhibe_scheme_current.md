# 基于 WKD-IBE 空域能力覆盖与零知识累加器的可验证多维范围查询

> 当前方案整理与代码核对稿，2026-07-20。
>
> 本文以当前工作区源码和实际命令输出为事实依据，以 `20260313-张昊星-研究汇报.pptx` 为当前研究叙事，以六份 PDF 为方案来源。`PROJECT_CONTEXT.md` 仅作为历史线索。本文不会把历史 benchmark、PPT 设想或文件名当作已经实现的事实。

## 0. 结论先行

当前方案最准确的名称是：

**基于 WKD-IBE 的多维空域能力覆盖 + 零知识多项式累加器结果成员证明**。

它由两个相互独立的证明层组成：

1. **结果真实性层**：用零知识多项式累加器证明返回元素属于数据拥有者承诺的数据集。
2. **空间完备性层**：用数据拥有者离线签发的 WKD-IBE 空区域父能力，派生查询范围内的空区域证书，使“返回坐标集合”和“经认证的空区域并集”覆盖整个查询框。

当前代码已经较完整地验证了低维、静态数据、诚实执行路径下的空域构造和几何覆盖；2D offline 系列还实现了真正查询无关的父区域与父密钥初始化。当前代码尚不能支持以下论文级强声明：

- 尚未实现端到端的数据加密、密文检索或访问控制；
- 尚未把数据拥有者、服务器、客户端和区块链拆成真实独立角色；
- 3D 以上主基准通常没有执行协议必需的空区域证书有效性验证；
- 当前几何层证明的是**唯一坐标支持集的完备性**，不是含重复坐标记录的多重集完备性；
- 当前累加器只哈希坐标，没有认证完整行内容，也没有把证明绑定到可信数据摘要、查询和返回记录；
- 当前高维索引仍随维数指数增长，不能声称已经消除了维数灾难；
- 区块链和智能合约仍是部署设想，不是当前 Go 原型的一部分。

因此，论文应把 2D 查询无关 offline 实现和 3D full-audit parallel 实现作为协议主线，把普通 query-touched 文件作为性能原型，把 4D 以上作为可扩展性与内存压力实验。

## 1. 方案演进

### 1.1 一维起点：HIBE 空节点证明

Ghosh、Ohrimenko 和 Tamassia 的一维方案把离散键域表示为完全二叉树。数据拥有者为数据库全域中的空区间生成 HIBE/HIBS 能力。查询后，服务器针对查询区间中未被结果占据的规范节点派生证明。

其核心安全直觉是：

- 空父节点的密钥可以派生空子节点的密钥；
- 含真实数据的区域没有被签发空区域祖先密钥；
- 因而服务器不能为被遗漏的真实数据位置伪造空区域证明。

原论文的交互版本由客户端加密随机挑战、服务器解密；非交互版本不是简单“去掉挑战”，而是使用 HIBS：服务器用相应空节点密钥签名节点 ID，客户端公开验证。

### 1.2 从 HIBE 到 M-HIBE：用 WKD-IBE 展平多维层级

早期 `An_Approach_to_Function_as_M_HIBE.pdf` 和 `mhibeconstruction.pdf` 的关键观察是：WKD-IBE 的属性槽允许通配符，因而可以把每一维的 HIBE 前缀放进独立槽段，再把所有槽段拼成一个 WKD-IBE pattern。

当前代码遵循这一思路，但它并没有实现一种新的底层 M-HIBE 密码原语。这里的 “M-HIBE” 是以下三部分的组合：

```text
WKD-IBE 通配符委派
    + 多维二进制规范覆盖
    + 数据相关的空域父区域构造
```

### 1.3 朴素二维推广为什么失败

朴素做法对每个二维空矩形直接生成密钥。其数量依赖整个坐标宇宙，而不是实际数据量，无法用于大域。

早期二维草稿还发现了一个更细的障碍：仅按全库相邻点形成的空矩形，不一定包含查询答案诱导出的空矩形，因此服务器可能无法从离线密钥派生查询所需证明。解决办法是为所有被真实数据触达的前缀父节点补充下一维空隙证书。

### 1.4 当前接受的构造：固定维度顺序的父区域补充

当前方案固定一个维度顺序，例如：

```text
shipdate -> discount -> quantity -> tax -> ...
```

它不再枚举所有维度排列，也不再把多轮 sweep 的结果取并集。算法按固定顺序递归：

1. 若第一维某前缀子树没有数据，直接认证该前缀与所有后续维度组成的整块区域；
2. 若该第一维前缀有数据，认证第二维中的所有空隙；
3. 仅对有数据的第二维前缀继续下降，认证第三维空隙；
4. 依此类推直到最后一维。

这正是 PPT 第 13 页所称的“宏观扫描 + 微观填充”，也是当前 `*_full_audit*.go` 的协议主线。

### 1.5 当前双引擎结构

PPT 的整体结构可以保留，但需要更准确地表述：

```text
数据拥有者离线阶段
  |- 发布/锚定数据集摘要和公共参数
  `- 生成全域空父区域及其可委派 WKD-IBE 父密钥

服务器查询阶段
  |- 返回满足查询的记录 A
  |- 从全局空父区域裁剪并派生查询空区域证书 E_Q
  `- 为 A 生成零知识累加器成员证明

验证阶段
  |- 检查所有返回记录满足查询谓词
  |- 验证返回记录的累加器证明
  |- 验证每个空区域证书
  `- 检查 support(A) 与 union(E_Q) 覆盖查询框且不相交
```

区块链可以承载数据版本、公共参数和数据摘要，也可以触发结算，但它不是密码学构造成立的必要条件。

## 2. 问题与安全定义

### 2.1 数据模型

令第 `i` 维离散域为：

$$
U_i = [0, 2^{b_i}-1],
\qquad
U = U_1 \times \cdots \times U_d.
$$

数据库版本 `e` 是记录多重集：

$$
D_e = \{r_1,\ldots,r_n\},
$$

每条记录有查询坐标 `x(r) in U` 和业务载荷 `payload(r)`。查询为轴对齐框：

$$
Q=[\ell_1,u_1]\times\cdots\times[\ell_d,u_d].
$$

真实答案多重集为：

$$
A^*(Q,D_e)=\{r\in D_e:x(r)\in Q\}.
$$

当前几何代码把记录投影为唯一坐标支持集：

$$
\operatorname{supp}(A)=\{x(r):r\in A\}.
$$

这一区分必须保留。若两条记录坐标相同，`supp(A)` 无法表达二者的数量。

### 2.2 参与方

- **数据拥有者 DO**：可信；生成数据版本、公共参数、数据摘要和全局空区域父能力。
- **数据库服务器 SP**：不可信；保存外包数据和空父能力，回答查询并生成证明。
- **查询用户/验证者 V**：可公开验证；可以是普通客户端，也可以是链下验证服务。
- **区块链/合约 BC**：可选的公开锚和结算层。当前代码尚未实现这一角色。

### 2.3 应分别定义的性质

1. **谓词正确性**：每条返回记录都满足 `x(r) in Q`。这可由验证者直接检查。
2. **结果真实性**：每条返回记录都属于数据拥有者在版本 `e` 承诺的数据库，且被认证字段未被修改。
3. **空间支持完备性**：`supp(A)=supp(A*)`。
4. **记录级完备性**：`A=A*`，按多重集计数。当前代码尚未证明这一性质。
5. **查询局部隐私**：验证过程不泄露查询框外记录；允许泄露应被明确写成 leakage function，例如查询、答案、答案数量、数据版本和由查询与答案确定的空覆盖结构。
6. **新鲜性**：证明必须绑定数据版本/epoch，旧版本证明不能重放到新版本。

论文若继续采用“零知识”一词，应给出上述 leakage function 和模拟定义。单纯发送 M-HIBE 密钥或空 pattern 不是标准意义上的零知识证明。

### 2.4 当前可证明范围

当前实现最接近以下受限命题：

> 在静态数据库、唯一坐标集合语义、可信离线初始化、有效空证书和可信数据库摘要的假设下，验证通过意味着服务器没有遗漏查询框中的任何唯一坐标。

其中“有效空证书”和“可信数据库摘要”在当前主基准中尚未完整落实，因而现阶段仍是协议原型而不是完整安全实现。

## 3. 基础编码

### 3.1 一维规范覆盖

任意离散区间 `[a,b]` 可以唯一分解为若干互不重叠的最大 dyadic 区间。每个 dyadic 区间对应完全二叉树上的一个二进制前缀。记一维规范覆盖为：

$$
\mathsf{CC}_i([a,b])=\{p_{i,1},\ldots,p_{i,t_i}\}.
$$

多维查询框的规范覆盖是各维覆盖的笛卡尔积：

$$
\mathsf{CC}(Q)=
\mathsf{CC}_1([\ell_1,u_1])\times\cdots\times
\mathsf{CC}_d([\ell_d,u_d]).
$$

代码入口为各 benchmark 中的 `getCanonicalCover`、`MapToIDs` 和 `cartesianProduct`。

### 3.2 多维 pattern

若第 `i` 维前缀为 `p_i`，则该维补齐为 `P_i=p_i *^(b_i-|p_i|)`。完整 pattern 为：

$$
P=P_1\parallel\cdots\parallel P_d,
\qquad L=\sum_i b_i.
$$

它代表各维前缀区间笛卡尔积形成的矩形 `R(P)`。若父 pattern 的每个固定位都与子 pattern 对应位相同，记为 `P_parent contains P_child`。WKD-IBE 允许从父键派生子键，但不能改变已经固定的位。

### 3.3 pattern 到 WKD-IBE 属性

当前主基准对每个固定比特做槽位域分离哈希：

$$
a_{i,j}=H_{\mathbb Z_p}(
\texttt{"mhibe"}\parallel i\parallel j\parallel bit).
$$

- 固定 `0/1` 位写入 `wkdibe.AttributeList`；
- `*` 位完全不写入 map，表示以后可继续填充的自由槽；
- map 中显式的 `nil` 是隐藏且不可再填的槽，不等价于 `*`。

当前 toy `integration_test.go` 仍只哈希字符 `0/1`，与主 benchmark 的域分离编码不一致，不能作为当前编码的回归测试。

目标实现还必须增加 `ValidatePattern`，强制每一维只能是“固定前缀 + 全部星号”。当前解析只检查总长度和字符，恶意的 `*1` 形式会破坏 `patternToBounds` 的连续区间语义。

## 4. 查询无关的固定顺序空域构造

### 4.1 占用索引

对每个下一维 `j` 和前面各维的前缀组合 `pi=(p_1,...,p_(j-1))`，建立：

$$
\mathsf{Occ}_j[\pi]
=\{x_j:\exists x\in\operatorname{supp}(D_e),
p_k\preceq x_k,\ 1\le k<j\}.
$$

2D 中它等价于 `XPrefix -> occupied Y values`；3D 中还增加 `(XPrefix,YPrefix) -> occupied Z values`；通用 ND 代码把它存为分层 map。

这个索引必须在查询到达前根据全库构建。普通 4D/5D/10D 文件把查询传入索引构造，只建立 query-touched index，不能称为完整离线初始化。

### 4.2 父区域生成

逻辑上可以写成如下固定顺序递归：

```text
BuildEmpty(parentPrefixes, dim):
    occupied = coordinates in dimension dim under parentPrefixes
    gaps = canonical cover(domain(dim) - occupied)

    for gap in gaps:
        emit parentPrefixes || gap || wildcards_for_remaining_dims

    if dim is last dimension:
        return

    for each occupied prefix node p in dimension dim:
        BuildEmpty(parentPrefixes || p, dim + 1)
```

实现可以剪枝：若某个父区域完全没有数据，直接输出该父区域加后续全通配符，不再下降。生成后执行精确去重、删除已被更粗父 pattern 包含的冗余子 pattern，并为每个保留父 pattern 生成可委派 WKD-IBE 父键。

### 4.3 二维实例

固定顺序 `X -> Y` 时：

1. 对 X 树中的空前缀 `p_x`，生成 `p_x || *`；
2. 对包含数据的 X 前缀 `p_x`，查看该前缀下出现过的所有 Y 值；
3. 对 Y 的空隙规范覆盖 `e_y`，生成 `p_x || e_y`；
4. 仅对包含数据的 X 子前缀继续递归。

这对应早期证明中的两类承诺 `Commit(*|bot)` 与 `Commit(x|*)`。

### 4.4 三维及更高维

3D 按 `X -> Y -> Z` 生成 `p_x || e_y || *`，以及在占用 `(p_x,p_y)` 父节点下的 `p_x || p_y || e_z`。ND 文件把这一规则递归推广到后续维度。

早期 `proof_of_completeness.pdf` 第 6 页只用一句话提出 `d>=2` 推广，没有给出归纳证明；当前代码提供了构造性证据，但论文仍需补正式归纳证明。

### 4.5 离线材料

数据拥有者输出：

$$
\mathcal G_e=\{(P,SK_P):R(P)\cap\operatorname{supp}(D_e)=\varnothing\}.
$$

其中每个 `SK_P` 必须是可安全继续委派的父键。服务器不应得到 MSK。当前 2D offline 和 3D/4D full-audit 文件在同一进程中持有 MSK，以模拟数据拥有者生成父键；这不是实际部署的权限模型。

## 5. 查询与证明生成

### 5.1 查询答案与查询裁剪

服务器计算 `A={r in D_e: x(r) in Q}`。客户端可以直接检查每条返回记录满足范围谓词。当前 benchmark 在同一进程中扫描全库并同时构造 `A` 和补集 `X`，因此没有测试恶意服务器输入。

对每个全局空父区域 `R(P)`：

1. 计算 `R(P) intersect Q`；
2. 若交集为空则忽略；
3. 对非空交集逐维重新做规范覆盖；
4. 产生仍被 `P` 包含且完全位于 `Q` 内的查询子 pattern。

所有子 pattern 可以继续去重、删除被包含项。3D 以上实验还按查询内实际空格点建立 candidate bitset，用贪心最大新增覆盖选择较小子集，再删除冗余候选。该贪心不保证最少 key 数，也不优化真实序列化字节数。

### 5.2 派生查询空区域证书

对每个查询子 pattern `C`，找到全局父 pattern `P` 满足 `P contains C`，然后派生：

$$
SK_C\leftarrow\mathsf{Qualify}(SK_P,C).
$$

当前代码用 `NonDelegableQualifyKey`。WKD-IBE API 明确说明该输出没有重随机化，不应交给另一个实体，否则可能泄露父键信息。若证明对象把子键从服务器发送给客户端，必须改用普通 `QualifyKey`，或者改为不发送密钥的签名/持有证明。

### 5.3 两种非交互证书形式

**形式 K：发送查询子键。** 服务器发送 `(C,SK_C)`。验证者自行选随机消息，在属性 `C` 下加密并用 `SK_C` 解密。它与当前 2D audit 接近，但证书可转移、泄露能力，而且必须使用安全重随机化的子键。它不是标准零知识证明。

**形式 S：HIBS 签名，推荐论文主协议。** 服务器保留 `SK_C`，用它对绑定整个查询的消息签名：

$$
\sigma_C\leftarrow\mathsf{Sign}(SK_C,\tau\parallel C).
$$

验证者用 MPK、pattern `C` 和 transcript `tau` 公开验证。该形式与 `popets-2016-0045.pdf` 第 8 页的非交互转换一致，也避免把派生密钥交给客户端。

当前 `wkdibe` 包已有 `Sign/Verify`，主 benchmark 也以 `supportSignatures=true` 初始化，但 `lang/go/mhibe` 没有使用这些接口。因此形式 S 是下一步实现，不是当前已完成功能。

### 5.4 结果真实性证明

当前累加器层将数据库编码为域元素多重集 `D_F`，将返回结果编码为 `I`，其余元素为 `X`。它构造 `digest_D=Commit(D_F)`、`digest_X=Commit(X)`、结果多项式 `f_I(z)=product_(a in I)(z-a)` 及 Pedersen 承诺 `C_I`，随后生成 `ZKMemProof` 和 `ZKDegCheckProof`。

这一层当前最多证明被承诺的 `I` 是数据库多项式的因子/子多重集，并隐藏结果多项式；它不证明空域，也不自动证明返回元素满足查询谓词。

论文目标实现应把每个记录编码为：

$$
H_F(\mathsf{canonicalSerialize}(
epoch,primaryKey,indexedCoordinates,authenticatedPayload)).
$$

当前代码只哈希 `FormatPointToBinary(point)`，因而只能认证坐标，不能认证完整行载荷。

### 5.5 完整证明对象与 transcript

建议最终证明对象为：

$$
\mathsf{VO}=(e,Q,A,C_A,
\{(C_i,\sigma_i)\}_{i=1}^{s},
\pi_{mem},\pi_{deg}).
$$

若暂时采用形式 K，则把 `sigma_i` 换为安全重随机化的 `SK_(C_i)`。

外部 transcript 至少绑定：

```text
protocol version
dataset identifier and epoch
owner-authenticated digest_D
M-HIBE/WKD-IBE public parameters identifier
query bounds
canonical hash of returned records
C_I
ordered hash of all empty patterns
all other public statement fields
```

当前主程序给累加器传入全零 `[32]byte` transcript，没有绑定数据版本、查询、答案或空覆盖，必须修复。

