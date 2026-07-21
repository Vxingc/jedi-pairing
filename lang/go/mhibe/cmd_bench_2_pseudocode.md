# `cmd_bench_2.go` 伪代码

## 1. 常量与类型

```text
constants:
    NumDims = 3
    BitLength = 12
    MaxKeyPatternDecryptChecks = 64

type Point:
    Coords[3]

type RangeQuery:
    Bounds[3][2]

type DerivedPatternKey:
    Pattern
    Attrs
    Key

type CoverCandidate:
    Pattern
    CoverageBitset
```

## 2. 查询框转成三维 bit-pattern

```text
function getCanonicalCover(min, max, nodeMin, nodeMax, prefix):
    if min <= nodeMin and nodeMax <= max:
        return [prefix]

    if nodeMax < min or nodeMin > max:
        return []

    mid = nodeMin + (nodeMax - nodeMin) / 2
    left  = getCanonicalCover(min, max, nodeMin, mid, prefix + "0")
    right = getCanonicalCover(min, max, mid + 1, nodeMax, prefix + "1")
    return left + right
```

```text
function cartesianProduct(dimCovers):
    result = dimCovers[0]

    for each nextCoverList in dimCovers[1:]:
        temp = []
        for each left in result:
            for each right in nextCoverList:
                temp.append(left + "||" + right)
        result = temp

    return result
```

```text
function MapToIDs(query):
    dimCovers = []

    for dim in [0, 1, 2]:
        minVal = query.Bounds[dim][0]
        maxVal = query.Bounds[dim][1]
        maxDomain = 2^BitLength - 1
        dimCovers.append(
            getCanonicalCover(minVal, maxVal, 0, maxDomain, "")
        )

    return cartesianProduct(dimCovers)
```

```text
function FormatToWildcardPattern(prefix):
    dims = split(prefix, "||")
    pattern = ""

    for dim in [0, 1, 2]:
        pattern += dims[dim]
        pattern += "*" repeated (BitLength - len(dims[dim]))

    return pattern
```

## 3. 点编码与空间减法

```text
function FormatPointToBinary(point):
    bits = ""
    for dim in [0, 1, 2]:
        bits += point.Coords[dim] encoded as 12-bit binary
    return bits
```

```text
function matches(pattern, pointBits):
    for i in 0 .. len(pattern)-1:
        if pattern[i] != "*" and pattern[i] != pointBits[i]:
            return false
    return true
```

```text
function generateBitOrderCustom(dimOrder, bitLen):
    order = []
    for each dim in dimOrder:
        for bitIndex from dim * bitLen to (dim + 1) * bitLen - 1:
            order.append(bitIndex)
    return order
```

```text
function SubtractPointOrdered(pattern, pointBits, bitOrder):
    if not matches(pattern, pointBits):
        return [pattern]

    emptyPatterns = []
    current = mutable copy of pattern

    for each bitIndex in bitOrder:
        if current[bitIndex] == "*":
            targetBit = pointBits[bitIndex]

            emptyBranch = copy(current)
            emptyBranch[bitIndex] = opposite(targetBit)
            emptyPatterns.append(emptyBranch)

            current[bitIndex] = targetBit

    return emptyPatterns
```

```text
function SubtractPointsOrdered(initialPatterns, dataPoints, bitOrder):
    currentPatterns = initialPatterns

    for each point in dataPoints:
        pointBits = FormatPointToBinary(point)
        nextPatterns = []

        for each pattern in currentPatterns:
            nextPatterns += SubtractPointOrdered(pattern, pointBits, bitOrder)

        currentPatterns = nextPatterns

    return currentPatterns
```

## 4. 把三维 pattern 编码成 WKD-IBE attributes

```text
function attributeValueForBit(slot, bit):
    payload = encode("mhibe", slot / BitLength, slot % BitLength, bit)
    return HashToZp(payload)
```

```text
function patternToAttributeList(pattern):
    attrs = {}

    for slot in 0 .. len(pattern)-1:
        if pattern[slot] == "*":
            continue

        if pattern[slot] is neither "0" nor "1":
            error "invalid pattern character"

        attrs[slot] = attributeValueForBit(slot, pattern[slot])

    return attrs
```

```text
function patternContainsPattern(parent, child):
    for i in 0 .. len(parent)-1:
        if parent[i] == "*":
            continue
        if parent[i] != child[i]:
            return false
    return true
```

```text
function dedupePatterns(patterns):
    seen = set()
    unique = []

    for each pattern in patterns:
        if pattern not in seen:
            seen.add(pattern)
            unique.append(pattern)

    return unique
```

```text
function selectMaximalPatterns(patterns):
    unique = dedupePatterns(patterns)
    sort unique by descending number of "*" entries

    maximal = []

    for each candidate in unique:
        dominated = false

        for each chosen in maximal:
            if patternContainsPattern(chosen, candidate):
                dominated = true
                break

        if not dominated:
            maximal.append(candidate)

    return maximal
```

## 5. 从极大候选块求近似最小 key cover

```text
function buildEmptyPointIndex(query, realPoints):
    indexByPoint = {}
    nextIndex = 0

    for each point in query bounds:
        if point in realPoints:
            continue
        indexByPoint[point] = nextIndex
        nextIndex += 1

    return (indexByPoint, nextIndex)
```

```text
function buildCoverCandidates(patterns, query, realPoints):
    (indexByPoint, emptyPointCount) = buildEmptyPointIndex(query, realPoints)
    candidates = []

    for each pattern in patterns:
        bounds = patternToBounds(pattern)
        assert bounds are inside query

        coverage = zero bitset sized for emptyPointCount

        for each point in bounds:
            assert point not in realPoints
            pointIndex = indexByPoint[point]
            coverage.set(pointIndex)

        if coverage is not empty:
            candidates.append(
                CoverCandidate(
                    Pattern = pattern,
                    CoverageBitset = coverage
                )
            )

    return (candidates, emptyPointCount)
```

```text
function greedySetCover(candidates, emptyPointCount):
    uncovered = full bitset of size emptyPointCount
    selected = []

    while uncovered is not empty:
        best = candidate whose coverage intersects uncovered the most
        assert best exists

        selected.append(best)
        uncovered = uncovered - best.coverage

    # redundancy pruning
    coverCount[emptyPoint] = number of selected sets covering that point

    repeat until no change:
        for each selected candidate:
            if every point it covers also has coverCount >= 2:
                remove candidate
                decrement coverCount on its covered points

    return selected
```

注意：这一层是贪心近似 set cover，不是严格全局最优。

## 6. 真实 delegation 链

```text
function derivePatternKeyFromRoot(params, rootKey, pattern):
    attrs = patternToAttributeList(pattern)
    key = QualifyKey(params, rootKey, attrs)

    return DerivedPatternKey(
        Pattern = pattern,
        Attrs = attrs,
        Key = key
    )
```

```text
function derivePatternKeyFromParent(params, parentKey, childPattern):
    assert patternContainsPattern(parentKey.Pattern, childPattern)

    childAttrs = patternToAttributeList(childPattern)
    key = NonDelegableQualifyKey(params, parentKey.Key, childAttrs)

    return DerivedPatternKey(
        Pattern = childPattern,
        Attrs = childAttrs,
        Key = key
    )
```

```text
function deriveInitialPatternKeys(params, rootKey, initialPatterns):
    results = []
    for each pattern in initialPatterns:
        results.append(derivePatternKeyFromRoot(params, rootKey, pattern))
    return results
```

```text
function deriveEmptyPatternKeys(params, initialKeys, emptyPatterns):
    results = []

    for each emptyPattern in emptyPatterns:
        find parentKey in initialKeys such that
            patternContainsPattern(parentKey.Pattern, emptyPattern)

        if no such parentKey:
            error "missing canonical-cover parent"

        results.append(
            derivePatternKeyFromParent(params, parentKey, emptyPattern)
        )

    return results
```

## 7. 几何完备性验证

```text
function calculateVolume(pattern):
    return 2 ^ (number of "*" in pattern)
```

```text
function patternToBounds(pattern):
    for each dimension:
        interpret "0" as fixed 0
        interpret "1" as fixed 1
        interpret "*" as [0,1]
    return bounds
```

```text
function verifyEmptyRegionPatterns(query, emptyPatterns, realPoints):
    coverage = map spatialPoint -> hitCount
    maxOverlap = 0

    for each pattern in emptyPatterns:
        bounds = patternToBounds(pattern)
        assert bounds are inside query

        for each point in bounds:
            assert point not in realPoints
            coverage[point] += 1
            maxOverlap = max(maxOverlap, coverage[point])

    coveredEmptyPoints = 0

    for each point in query bounds:
        if point in realPoints:
            assert coverage[point] == 0
        else:
            assert coverage[point] >= 1
            coveredEmptyPoints += 1

    assert coveredEmptyPoints >= size(coverage)
    return (coveredEmptyPoints, maxOverlap)
```

这里允许不同 cover block 重叠，所以验证条件是“每个空点至少被覆盖一次”，不是“恰好一次”。

## 8. 抽样密码学一致性验证

```text
function verifyDerivedPatternKeys(params, derivedKeys):
    checks = min(len(derivedKeys), MaxKeyPatternDecryptChecks)

    for probe in 0 .. checks-1:
        idx = probe * len(derivedKeys) / checks
        item = derivedKeys[idx]

        message = RandomEncryptable()
        ciphertext = Encrypt(message, params, item.Attrs)
        decrypted = Decrypt(ciphertext, item.Key)

        assert decrypted == message

    return checks
```

注意：这里验证的是“同一个 pattern 的 ciphertext 能否被对应 key 解开”，不是把 key 当成“任意具体点的前缀 key”来测。

## 9. 主流程

```text
function main():
    print "Starting benchmark"

    initialize curve
    (params, masterKey) = wkdibe.Setup(36, true)
    acc = load accumulator keys

    query = {
        date     in [1994-01-01, 1994-12-31],
        discount in [5, 7],
        quantity in [0, 23]
    }

    dbData = []
    dbFr = []
    I = []
    X = []
    queryUniquePoints = empty set

    for each line in TPC-H file:
        point = parse three-dimensional point
        dbData.append(point)

        fr = SeedToFr(FormatPointToBinary(point))
        dbFr.append(fr)

        if point in query:
            I.append(fr)
            queryUniquePoints.add(point.Coords)
        else:
            X.append(fr)

    digest_DB = CommitFakeG1(dbFr)
    digest_X  = CommitFakeG1(X)

    # Engine A: Hexa-Sweep extraction
    initialPrefixes = MapToIDs(query)
    initialPatterns = map each prefix to wildcard pattern

    permutations = all 6 orderings of dimensions
    combinedEmptyPatterns = []

    for each permutation:
        order = generateBitOrderCustom(permutation, BitLength)
        patterns = SubtractPointsOrdered(initialPatterns, dbData, order)
        combinedEmptyPatterns += patterns

    maximalEmptyPatterns = selectMaximalPatterns(combinedEmptyPatterns)
    (coverCandidates, emptyPointCount) = buildCoverCandidates(
        maximalEmptyPatterns,
        query,
        queryUniquePoints
    )
    selectedCover = greedySetCover(coverCandidates, emptyPointCount)
    selectedCoverPatterns = extract pattern field from each selected candidate

    # Engine A: real WKD-IBE materialization
    rootKey = KeyGen(params, masterKey, emptyAttrs)

    initialKeys = deriveInitialPatternKeys(params, rootKey, initialPatterns)
    verificationEmptyKeys = deriveEmptyPatternKeys(
        params,
        initialKeys,
        selectedCoverPatterns
    )

    totalKeyBytes = sum Marshal(true) size of each verification key

    # Client completeness check
    totalQueryVolume = sum calculateVolume(pattern) for pattern in initialPatterns

    (coveredEmptyPoints, maxOverlap) = verifyEmptyRegionPatterns(
        query,
        selectedCoverPatterns,
        queryUniquePoints
    )

    sampledKeyChecks = verifyDerivedPatternKeys(params, verificationEmptyKeys)
    realSpatialVolume = size(queryUniquePoints)

    assert coveredEmptyPoints + realSpatialVolume == totalQueryVolume

    # Engine B: authenticity proof
    I_poly = PolyTree(I)
    C_I = Pedersen commit of I_poly

    zkMemProof = ZKMemProver(C_I, digest_X, transcript)
    zkDegProof = ZKDegCheckProver(C_I, I_poly, hash(zkMemProof))

    ok1 = ZKMemVerifier(zkMemProof, digest_DB, C_I.Com, transcript)
    ok2 = ZKDegCheckVerifier(C_I.Com, zkDegProof, hash(zkMemProof))

    print final timing report
```

## 10. 主线摘要

```latex
先把三维查询框切成规范前缀块
再用六种维度顺序提取空区域 pattern
把六轮结果去重并按包含关系取极大空块
再对这些极大空块做贪心近似 minimum key cover
把最终 selected cover 真实 materialize 成 WKD-IBE completeness keys
客户端对这些 selected cover 的并集做全量几何验证
再对抽样 completeness keys 做 same-pattern encrypt/decrypt 验证
最后对命中结果集合做 ZK-Accumulator 真实性证明
```
