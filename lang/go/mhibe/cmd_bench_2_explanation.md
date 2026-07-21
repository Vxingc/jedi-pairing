# `cmd_bench_2.go` 解释文档

## 1. 文件定位

`cmd_bench_2.go` 是一个独立 benchmark 脚本，用来把两层机制拼起来评估：

- `Engine A`：三维查询空间切分 + 基于 WKD-IBE 的真实空区域 pattern key 编码
- `Engine B`：ZK-Accumulator 证明命中结果真实性


## 2. 三维查询如何变成 36 个 WKD-IBE 槽位

固定常量：

- `NumDims = 3`
- `BitLength = 12`

所以每个点都被编码成 36 位二进制串：

- 第 0 维占 12 位
- 第 1 维占 12 位
- 第 2 维占 12 位

程序把 TPC-H 记录映射成三维点：

- 第 0 维：发货日期相对 `1992-01-01` 的天数
- 第 1 维：`discount * 100`
- 第 2 维：`quantity`

然后用 `FormatPointToBinary` 把它转成 36 位字符串。

这 36 位不是只拿来做几何切分，它们同时也是 WKD-IBE 的 36 个 attribute slot 的索引来源，也就是：

- 第 `i` 位固定为 `0` 或 `1`：对应第 `i` 个 slot 被设置成某个具体 attribute
- 第 `i` 位为 `*`：对应第 `i` 个 slot 保持 free

这就是从“二维 JEDI pattern”推广到“三维 bit-flattened pattern”的核心做法。

## 3. 查询空间切分逻辑

### 3.1 `getCanonicalCover` / `MapToIDs`

每一维的查询区间先被拆成规范二叉覆盖，然后做笛卡尔积，得到三维查询框的规范前缀块。

### 3.2 `FormatToWildcardPattern`

把每个维度上的前缀补足到 12 位，未指定的位写成 `*`。得到的 36 位模式串就是后面空区域 key 的逻辑 pattern。

### 3.3 `SubtractPointOrdered` / `SubtractPointsOrdered`

这部分负责从查询框中逐点“减去”真实命中点，得到纯空区域模式。

关键点：

- `SubtractPointOrdered` 会沿给定 `bitOrder` 追踪目标点
- 每次遇到 `*`，都把“反向分支”保存成一个新的空区域模式
- `SubtractPointsOrdered` 把这个过程对整库点重复执行

因此输出的空区域 pattern 是一个“带自由位的 36 位模式”，不是单点集合。

## 4. 真实 WKD-IBE 编码

这一版新增了真正的 pattern-key materialization。

### 4.1 `DerivedPatternKey`

每个真实 completeness key 都用一个结构表示：

- `Pattern`：36 位 `0/1/*` 模式串
- `Attrs`：对应的 `wkdibe.AttributeList`
- `Key`：真实的 `wkdibe.SecretKey`

### 4.2 `attributeValueForBit`

函数会把：

- 槽位编号 `slot`
- 该位取值 `0` 或 `1`

哈希到 `Zp`，作为 WKD-IBE 的 attribute 值。

也就是说，这里不是直接把整数 `0/1` 塞进 attribute，而是做了一个 slot-aware 编码：

- 同一个 bit 值出现在不同 slot，得到的 attribute 不同
- `slot + bit` 共同决定 attribute

### 4.3 `patternToAttributeList`

这个函数把一个模式串转成 WKD-IBE 的 attribute list：

- 位是 `0` 或 `1`：加入 attribute map
- 位是 `*`：不加入 map，保持 free

### 4.4 `derivePatternKeyFromRoot`

程序先生成一个根 key：

- `rootKey := wkdibe.KeyGen(params, masterKey, empty attrs)`

它对应“所有 slot 都是 free”。

然后对某个 pattern：

- 先用 `patternToAttributeList` 得到固定槽位集合
- 再调用 `wkdibe.QualifyKey(params, rootKey, attrs)`

得到该 pattern 的 delegable key。

这一步对应“从根模式限定到查询框 canonical-cover pattern”。

### 4.5 `derivePatternKeyFromParent`

对某个更细的空区域 pattern：

- 先检查它是否被某个 canonical-cover parent pattern 包含
- 再用 `wkdibe.NonDelegableQualifyKey(params, parent.Key, childAttrs)`

把 parent key 继续限定到 child pattern。
- parent pattern 提供更粗的授权范围
- child pattern 通过继续填具体 slot 收缩权限

### 4.6 六轮 sweep 之后如何提取候选空块

代码会先把 6 轮 sweep 生成的空区域 pattern 全部合并到 `combinedEmptyPatterns`，然后做两步后处理：

1. 去重
2. 按包含关系取极大 pattern

具体做法见：

- `dedupePatterns`
- `selectMaximalPatterns`

这里“最大”不是指体积最优或数量最少，而是指：

- 如果某个 pattern 被另一个 pattern 完全包含
- 那么只保留外层那个 pattern

于是最终保留下来的 `maximalEmptyPatterns` 是一组 inclusion-maximal empty blocks，作为后续 cover 优化的候选集。

这组候选块可能：

- 比单轮切分更大
- 彼此重叠
- 数量不一定更少

这正是六轮 sweep 的真实作用：提供更多候选空块，再由后处理选出其中的极大块。

### 4.7 如何从候选空块得到更小的 key cover

只取极大块还不够，因为：

- 极大块之间可能重叠
- 候选数可能反而比单轮更多

所以当前代码在 `maximalEmptyPatterns` 之上又做了一层 cover 优化：

1. 先把查询补集中的每个空点编号
2. 为每个候选块构造它覆盖哪些空点的 bitset
3. 用贪心 set cover 反复选择“当前能覆盖最多未覆盖空点”的候选块
4. 再做一轮冗余删除：如果去掉某个已选块后，其覆盖点仍然都被别的已选块覆盖，就把它删掉

这一步对应代码中的：

- `buildCoverCandidates`
- `greedySetCover`

最终发给客户端并 materialize 成 WKD-IBE key 的，不是 `maximalEmptyPatterns`，而是 `selectedCoverPatterns`。

## 5. 客户端如何验证完备性

这一层现在是“两段式验证”。

### 5.1 几何完备性验证：`verifyEmptyRegionPatterns`

这一步仍然是严格、全量的空间检查。客户端拿到的是 `selectedCoverPatterns`，它们来自极大候选块上的 cover 压缩，因此允许 pattern 之间重叠。它逐点保证：

1. 每个空区域 pattern 都在查询框内
2. 空区域 pattern 不覆盖真实命中点
3. 查询框内每个空点至少被一个 selected cover pattern 覆盖
4. 查询框内的真实点不会被任何 selected cover pattern 覆盖

然后再检查：

- `coveredEmptyPoints + realSpatialVolume == totalQueryVolume`

其中：

- `realSpatialVolume` 是命中点按空间坐标去重后的数量
- `coveredEmptyPoints` 是空区域覆盖的空点数量

### 5.2 密码学一致性验证：`verifyDerivedPatternKeys`

实际做法是：

- 对若干个生成出来的 `DerivedPatternKey`
- 用它自己的 `Attrs` 加密一个随机 `Encryptable`
- 再用它自己的 `Key` 解密
- 检查解密结果是否恢复原消息

这一步验证的是：

- pattern 到 attribute list 的编码是对的
- parent 到 child 的 `QualifyKey` / `NonDelegableQualifyKey` 链是对的
- materialized completeness key 确实是一个可用的 WKD-IBE key

为了控制客户端开销，当前默认只抽样最多 `64` 个 key 做这一步。

因此当前客户端检查分工是：

- 几何层：全量严格验证这些 selected cover blocks 的并集覆盖了整个查询补集
- 密码学层：抽样验证 key 编码和 delegation 链路

## 6. `main` 的实际流程

### 6.1 初始化

程序初始化：

- `mcl.InitFromString("bls12-381")`
- `wkdibe.Setup(36, true)`
- `bpacc.BpAcc`

这里的 `36` 就是三维平铺后的总 slot 数。

### 6.2 读取数据并分桶

扫描 `lineitem_120K.tbl`，构造：

- `dbData`：三维点
- `dbFr`：整库映射到累加器域元素
- `I`：命中查询的记录
- `X`：未命中查询的记录
- `queryUniquePoints`：命中查询的唯一空间点

### 6.3 底层承诺

生成：

- `digest_DB`
- `digest_X`

用于 Engine B 的真实性证明。

### 6.4 Engine A：Hexa-Sweep

1. 把查询框转成 `initialPatterns`
2. 运行 6 种维度排列的切分
3. 记录每种排列下的空区域数量
4. 把 6 轮总数合并到 `combinedEmptyPatterns`
5. 把 6 轮结果全部合并
6. 从合并结果中提取 `maximalEmptyPatterns`
7. 再从 `maximalEmptyPatterns` 中求 `selectedCoverPatterns`

### 6.5 Engine A：真实 WKD-IBE key materialization

1. 生成 `rootKey`
2. 先把每个 canonical-cover pattern materialize 成 parent key
3. 再把 `selectedCoverPatterns` 中的每个 cover block 从 parent key 继续限定成 leaf key
4. 统计：
   - materialized completeness key 数量
   - delegation 用时
   - marshalled key material 总大小

### 6.6 客户端完整性检查

客户端先做：

- 全量几何补集验证

再做：

- 抽样 pattern-key 的 same-pattern encrypt/decrypt 检查

两者都通过，才算 Engine A 成功。

### 6.7 Engine B：真实性证明

1. 把 `I` 组织成多项式 `I_poly`
2. 生成 Pedersen 承诺 `C_I`
3. 生成：
   - `ZKMemProof`
   - `ZKDegCheckProof`
4. 客户端验证两份证明

它负责的是“命中结果集合是真实的”。

## 7. 语义边界

- 几何层负责证明空区域 partition 的完备性
- WKD-IBE 层负责把空区域 pattern 真实落到 secret key
- ZK-Accumulator 层负责证明返回结果真实性

## 8. 一句话总结

`cmd_bench_2.go` 现在实现的是：

- 用三维 bit-pattern 表示查询补集
- 先做六轮 sweep 得到大量候选空块
- 再按包含关系抽取六轮合并后的极大候选块
- 再对这些候选块做近似最小 key cover
- 把最终 cover 中的块真实编码成 WKD-IBE key
- 用 `QualifyKey` / `NonDelegableQualifyKey` 表达 delegation 思路
- 再把空间完备性与结果真实性分别交给几何检查和 ZK-Accumulator 去验证