# `acc.go` 伪代码

## 1. 一维区间规范覆盖

```text
function getCanonicalCover(min, max, nodeMin, nodeMax, prefix):
    if min <= nodeMin and nodeMax <= max:
        return [prefix]

    if nodeMax < min or nodeMin > max:
        return []

    mid = nodeMin + (nodeMax - nodeMin) / 2

    leftCover  = getCanonicalCover(min, max, nodeMin, mid, prefix + "0")
    rightCover = getCanonicalCover(min, max, mid + 1, nodeMax, prefix + "1")

    return leftCover + rightCover
```

## 2. 多维范围查询映射成前缀 ID

```text
function MapToIDs(query):
    dimCovers = []

    for dim in [0 .. NumDims-1]:
        minVal = query.Bounds[dim][0]
        maxVal = query.Bounds[dim][1]
        maxDomain = 2^BitLength - 1

        cover = getCanonicalCover(minVal, maxVal, 0, maxDomain, "")
        dimCovers.append(cover)

    return cartesianProduct(dimCovers)
```

```text
function cartesianProduct(dimCovers):
    if dimCovers is empty:
        return []

    result = dimCovers[0]

    for i from 1 to len(dimCovers)-1:
        temp = []
        for prefixA in result:
            for prefixB in dimCovers[i]:
                temp.append(prefixA + "||" + prefixB)
        result = temp

    return result
```

## 3. 前缀与点的编码

```text
function FormatToWildcardPattern(prefix):
    dims = split(prefix, "||")
    output = ""

    for each dimPrefix in dims:
        output += dimPrefix
        while length(dimPrefix) < BitLength:
            output += "*"
            dimPrefix += "*"

    return output
```

```text
function FormatPointToBinary(point):
    output = ""

    for dim in [0 .. NumDims-1]:
        output += toFixedLengthBinary(point.Coords[dim], BitLength)

    return output
```

```text
function matches(pattern, pointBits):
    for i in [0 .. len(pattern)-1]:
        if pattern[i] != "*" and pattern[i] != pointBits[i]:
            return false
    return true
```

## 4. 按位顺序做“空间减点”

```text
function generateBitOrder(primaryDim, numDims, bitLen):
    order = []

    for i in bits of primaryDim:
        order.append(i)

    for each otherDim != primaryDim:
        for i in bits of otherDim:
            order.append(i)

    return order
```

```text
function SubtractPointOrdered(pattern, pointBits, bitOrder):
    if not matches(pattern, pointBits):
        return [pattern]

    emptyRegions = []
    current = copy(pattern)

    for bitIndex in bitOrder:
        if current[bitIndex] == "*":
            targetBit = pointBits[bitIndex]

            emptyBranch = copy(current)
            emptyBranch[bitIndex] = opposite(targetBit)
            emptyRegions.append(emptyBranch)

            current[bitIndex] = targetBit

    return emptyRegions
```

```text
function SubtractPointsOrdered(initialPatterns, dataPoints, bitOrder):
    currentPatterns = initialPatterns

    for point in dataPoints:
        pointBits = FormatPointToBinary(point)
        nextPatterns = []

        for pattern in currentPatterns:
            pieces = SubtractPointOrdered(pattern, pointBits, bitOrder)
            nextPatterns.extend(pieces)

        currentPatterns = nextPatterns

    return currentPatterns
```

## 5. 日期编码与点是否命中查询

```text
function ParseDate(dateStr):
    baseDate = "1992-01-01"
    targetDate = parse(dateStr)
    if parse failed:
        return 0
    return daysBetween(baseDate, targetDate)
```

```text
function IsPointInQuery(point, query):
    for dim in [0 .. NumDims-1]:
        if point.Coords[dim] < query.Bounds[dim][0]:
            return false
        if point.Coords[dim] > query.Bounds[dim][1]:
            return false
    return true
```

## 6. 主流程

```text
function main():
    print "start pure zk-accumulator benchmark"

    initialize curve bls12-381
    initialize accumulator acc
    acc.loadKeys("./pkvk-17")

    query = {
        date     in [1994-01-01, 1994-12-31],
        discount in [5, 7],
        quantity in [0, 23]
    }

    dbData = []
    dbFr = []
    I = []
    X = []

    open "/home/xing/poneglyphdb/src/data/lineitem_120K.tbl"

    for each line in file:
        parse quantity from cols[4]
        parse discount from cols[6], then multiply by 100
        parse date from cols[10]

        point = Point(dateDays, discountScaled, quantity)
        dbData.append(point)

        fr = SeedToFr(FormatPointToBinary(point))
        dbFr.append(fr)

        if IsPointInQuery(point, query):
            I.append(fr)
        else:
            X.append(fr)

    digest_DB = Commit(dbFr)
    digest_X  = Commit(X)

    initialPrefixes = MapToIDs(query)
    initialPatterns = []
    for prefix in initialPrefixes:
        initialPatterns.append(FormatToWildcardPattern(prefix))

    orderX = generateBitOrder(primaryDim = 0)
    orderY = generateBitOrder(primaryDim = 1)

    emptyPatternsX = SubtractPointsOrdered(initialPatterns, dbData, orderX)
    emptyPatternsY = SubtractPointsOrdered(initialPatterns, dbData, orderY)

    combinedEmptyPatterns = emptyPatternsX + emptyPatternsY

    # Proof A: membership for hit set I
    I_poly = PolyTree(I)
    C_I = PedersenCommit(I_poly)
    zkMemProof = ZKMemProver(C_I, digest_X)
    zkDegProof = ZKDegCheckProver(C_I, I_poly, hash(zkMemProof))

    memOK1 = ZKMemVerifier(zkMemProof, digest_DB, C_I)
    memOK2 = ZKDegCheckVerifier(C_I, zkDegProof, hash(zkMemProof))

    # Proof B: non-membership for empty regions
    emptySet = []
    for pattern in combinedEmptyPatterns:
        emptySet.append(SeedToFr(pattern))

    (A, B) = ProveBatchNonMemFake(dbFr, emptySet)

    emptyPoly = PolyTree(emptySet)
    CEmpty = PedersenCommit(emptyPoly)
    zkNonMemProof = ZKNonMemProver(digest_DB, CEmpty, A, B)
    zkDegNonMemProof = ZKDegCheckProver(CEmpty, emptyPoly, hash(zkNonMemProof))

    nonMemOK1 = ZKNonMemVerifier(zkNonMemProof, digest_DB, CEmpty)
    nonMemOK2 = ZKDegCheckVerifier(CEmpty, zkDegNonMemProof, hash(zkNonMemProof))

    print extraction time
    print membership proof time, verify time, proof size, result
    print non-membership proof time, verify time, proof size, result
    print overall result = (memOK1 and memOK2 and nonMemOK1 and nonMemOK2)
```

## 7. 一句话主线

```text
把三维范围查询切成前缀块
再从这些块里扣掉真实数据点
把剩余空块和命中结果都编码成累加器元素
最后分别做成员证明与非成员证明
```
