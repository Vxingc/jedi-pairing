//go:build ignore
// +build ignore

package main

import (
	"bufio"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	// 零知识累加器依赖
	"github.com/accumulators-agg/bp/bpacc"
	"github.com/accumulators-agg/go-poly/fft"
	"github.com/alinush/go-mcl"
)

// ==========================================
// 1. M-HIBE 核心逻辑 (3维空间, 12-bit)
// ==========================================
const (
	NumDims   = 3
	BitLength = 12
)

type Point struct{ Coords [NumDims]int64 }
type RangeQuery struct{ Bounds [NumDims][2]int64 }

func getCanonicalCover(min, max, nodeMin, nodeMax int64, prefix string) []string {
	if min <= nodeMin && nodeMax <= max {
		return []string{prefix}
	}
	if nodeMax < min || nodeMin > max {
		return nil
	}
	mid := nodeMin + (nodeMax-nodeMin)/2
	leftCover := getCanonicalCover(min, max, nodeMin, mid, prefix+"0")
	rightCover := getCanonicalCover(min, max, mid+1, nodeMax, prefix+"1")
	return append(leftCover, rightCover...)
}

func cartesianProduct(dimCovers [][]string) []string {
	if len(dimCovers) == 0 {
		return nil
	}
	result := dimCovers[0]
	for i := 1; i < len(dimCovers); i++ {
		var temp []string
		for _, res := range result {
			for _, cover := range dimCovers[i] {
				temp = append(temp, res+"||"+cover)
			}
		}
		result = temp
	}
	return result
}

func MapToIDs(query RangeQuery) []string {
	var dimCovers [][]string
	for i := 0; i < NumDims; i++ {
		minVal, maxVal := query.Bounds[i][0], query.Bounds[i][1]
		maxDomain := int64(math.Pow(2, BitLength)) - 1
		dimCovers = append(dimCovers, getCanonicalCover(minVal, maxVal, 0, maxDomain, ""))
	}
	return cartesianProduct(dimCovers)
}

func FormatToWildcardPattern(prefix string, numDims int, bitLen int) string {
	dims := strings.Split(prefix, "||")
	var b strings.Builder
	for d := 0; d < numDims; d++ {
		b.WriteString(dims[d])
		for i := len(dims[d]); i < bitLen; i++ {
			b.WriteByte('*')
		}
	}
	return b.String()
}

func FormatPointToBinary(p Point) string {
	var b strings.Builder
	for i := 0; i < NumDims; i++ {
		b.WriteString(fmt.Sprintf("%0*b", BitLength, p.Coords[i]))
	}
	return b.String()
}

func matches(pattern, pointBin string) bool {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] != '*' && pattern[i] != pointBin[i] {
			return false
		}
	}
	return true
}

// 提取命中查询框的数据判断函数
func IsPointInQuery(p Point, q RangeQuery) bool {
	for i := 0; i < NumDims; i++ {
		if p.Coords[i] < q.Bounds[i][0] || p.Coords[i] > q.Bounds[i][1] {
			return false
		}
	}
	return true
}

// ==========================================
// 支持自定义主维度的分裂算法
// ==========================================

func generateBitOrder(primaryDim int, numDims int, bitLen int) []int {
	var order []int
	for i := primaryDim * bitLen; i < (primaryDim+1)*bitLen; i++ {
		order = append(order, i)
	}
	for d := 0; d < numDims; d++ {
		if d == primaryDim {
			continue
		}
		for i := d * bitLen; i < (d+1)*bitLen; i++ {
			order = append(order, i)
		}
	}
	return order
}

func SubtractPointOrdered(pattern, pointBin string, bitOrder []int) []string {
	if !matches(pattern, pointBin) {
		return []string{pattern}
	}
	var emptyRegions []string
	current := []byte(pattern)

	for _, i := range bitOrder {
		if current[i] == '*' {
			targetBit := pointBin[i]
			emptyBranch := make([]byte, len(current))
			copy(emptyBranch, current)
			if targetBit == '0' {
				emptyBranch[i] = '1'
			} else {
				emptyBranch[i] = '0'
			}
			emptyRegions = append(emptyRegions, string(emptyBranch))
			current[i] = targetBit
		}
	}
	return emptyRegions
}

func SubtractPointsOrdered(initialPatterns []string, dataPoints []Point, bitOrder []int) []string {
	currentPatterns := initialPatterns
	for _, p := range dataPoints {
		pointBin := FormatPointToBinary(p)
		var nextPatterns []string
		for _, pat := range currentPatterns {
			nextPatterns = append(nextPatterns, SubtractPointOrdered(pat, pointBin, bitOrder)...)
		}
		currentPatterns = nextPatterns
	}
	return currentPatterns
}

func ParseDate(dateStr string) int64 {
	layout := "2006-01-02"
	baseDate, _ := time.Parse(layout, "1992-01-01")
	targetDate, err := time.Parse(layout, dateStr)
	if err != nil {
		return 0
	}
	return int64(targetDate.Sub(baseDate).Hours() / 24)
}

// ==========================================
// Pure ZK-Accumulator Benchmark
// ==========================================
func main() {
	fmt.Println("[*] Starting Pure ZK-Accumulator Completeness/Correctness Benchmark...")

	// ========================================================
	// 0. 全局初始化 (BLS12-381 + ZK Accumulator)
	// ========================================================
	mcl.InitFromString("bls12-381")

	var acc bpacc.BpAcc
	keyDir := "./pkvk-17"
	acc.KeyGenLoad(8, 17, "my_secure_seed", keyDir)

	// ========================================================
	// 1. 数据读取与前缀提取
	// ========================================================
	file, err := os.Open("/home/xing/poneglyphdb/src/data/lineitem_120K.tbl")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	var dbData []Point
	var dbFr []mcl.Fr
	var I []mcl.Fr // 命中查询的真实数据
	var X []mcl.Fr // 未命中查询的数据

	var query RangeQuery
	query.Bounds[0] = [2]int64{ParseDate("1994-01-01"), ParseDate("1994-12-31")}
	query.Bounds[1] = [2]int64{5, 7}
	query.Bounds[2] = [2]int64{0, 23}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		cols := strings.Split(line, "|")
		if len(cols) < 11 {
			continue
		}

		var p Point
		qFloat, _ := strconv.ParseFloat(cols[4], 64)
		p.Coords[2] = int64(qFloat)
		dFloat, _ := strconv.ParseFloat(cols[6], 64)
		p.Coords[1] = int64(dFloat * 100)
		p.Coords[0] = ParseDate(cols[10])
		dbData = append(dbData, p)

		fr := bpacc.SeedToFr(FormatPointToBinary(p))
		dbFr = append(dbFr, fr)

		if IsPointInQuery(p, query) {
			I = append(I, fr)
		} else {
			X = append(X, fr)
		}
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
	fmt.Printf("[*] Loaded %d real TPC-H records, query hit %d rows.\n", len(dbData), len(I))

	// 全量数据库承诺 + 查询外补集承诺
	digest_DB, _ := acc.CommitFakeG1(dbFr)
	digest_X, _ := acc.CommitFakeG1(X)

	// --- 提取空前缀（后续用于非成员证明）---
	extractionStart := time.Now()
	initialPrefixes := MapToIDs(query)
	var initialPatterns []string
	for _, p := range initialPrefixes {
		initialPatterns = append(initialPatterns, FormatToWildcardPattern(p, NumDims, BitLength))
	}
	emptyPatternsX := SubtractPointsOrdered(initialPatterns, dbData, generateBitOrder(0, NumDims, BitLength))
	emptyPatternsY := SubtractPointsOrdered(initialPatterns, dbData, generateBitOrder(1, NumDims, BitLength))
	var combinedEmptyPatterns []string
	combinedEmptyPatterns = append(combinedEmptyPatterns, emptyPatternsX...)
	combinedEmptyPatterns = append(combinedEmptyPatterns, emptyPatternsY...)
	extractionMs := float64(time.Since(extractionStart).Nanoseconds()) / 1e6

	// ========================================================
	// [Proof A] 正确性：查询结果成员证明 (I ⊆ DB 且与 X 互补)
	// ========================================================
	fmt.Println("\n=== PROOF A: ZK-Membership (Correctness of returned rows) ===")
	zkMemStart := time.Now()
	var transcriptMem [32]byte
	var randMem mcl.Fr
	randMem.Random()
	I_poly := fft.PolyTree(I)
	C_I := bpacc.PedG2{Com: acc.PedersenG2(I_poly, acc.VK, randMem, acc.PedVK[0]), R: randMem}
	zkMemProof := acc.ZKMemProver(C_I, digest_X, transcriptMem)
	zkDegProof := acc.ZKDegCheckProver(C_I, I_poly, zkMemProof.HashProof(transcriptMem))
	zkMemProverMs := float64(time.Since(zkMemStart).Nanoseconds()) / 1e6

	zkMemSize := float64(zkMemProof.ByteSize()) / 1024.0
	zkDegSize := float64(zkDegProof.ByteSize()) / 1024.0
	memVerifyStart := time.Now()
	memOK1 := acc.ZKMemVerifier(zkMemProof, digest_DB, C_I.Com, transcriptMem)
	memOK2 := acc.ZKDegCheckVerifier(C_I.Com, zkDegProof, zkMemProof.HashProof(transcriptMem))
	memVerifyMs := float64(time.Since(memVerifyStart).Nanoseconds()) / 1e6

	// ========================================================
	// [Proof B] 完备性：空区域非成员证明 (E ∩ DB = ∅)
	// ========================================================
	fmt.Println("\n=== PROOF B: ZK-NonMembership (Completeness of empty regions) ===")

	// 准备空区域元素集合 E
	var emptySet []mcl.Fr
	for _, pattern := range combinedEmptyPatterns {
		emptySet = append(emptySet, bpacc.SeedToFr(pattern))
	}

	zkNonMemStart := time.Now()

	// 1. ZK 非成员证明 (证明这 12792 个空区域不包含真实数据)
	var transcriptNonMem [32]byte
	var randNonMem mcl.Fr
	randNonMem.Random()

	// 针对全库 dbFr 和空集合 emptySet 生成批量非成员证明
	A, B := acc.ProveBatchNonMemFake(dbFr, emptySet)

	// 构建空集合多项式承诺
	emptyPoly := fft.PolyTree(emptySet)
	CEmpty := bpacc.PedG2{Com: acc.PedersenG2(emptyPoly, acc.VK, randNonMem, acc.PedVK[0]), R: randNonMem}

	zkNonMemProof := acc.ZKNonMemProver(digest_DB, CEmpty, A, B, transcriptNonMem)
	zkDegNonMemProof := acc.ZKDegCheckProver(CEmpty, emptyPoly, zkNonMemProof.HashProof(transcriptNonMem))

	zkNonMemProverMs := float64(time.Since(zkNonMemStart).Nanoseconds()) / 1e6
	zkNonMemVerifyStart := time.Now()
	nonMemOK1 := acc.ZKNonMemVerifier(zkNonMemProof, digest_DB, CEmpty.Com, transcriptNonMem)
	nonMemOK2 := acc.ZKDegCheckVerifier(CEmpty.Com, zkDegNonMemProof, zkNonMemProof.HashProof(transcriptNonMem))
	zkNonMemVerifyMs := float64(time.Since(zkNonMemVerifyStart).Nanoseconds()) / 1e6

	nonMemSize := float64(zkNonMemProof.ByteSize()+zkDegNonMemProof.ByteSize()) / 1024.0

	fmt.Println("\n=== FINAL PURE ZK REPORT ===")
	fmt.Printf("Empty-prefix extraction time: %.2f ms\n", extractionMs)
	fmt.Printf("Membership proof: %.2f ms prover / %.2f ms verifier, size %.2f KB, ok=%v\n", zkMemProverMs, memVerifyMs, zkMemSize+zkDegSize, memOK1 && memOK2)
	fmt.Printf("Non-membership proof: %.2f ms prover / %.2f ms verifier, size %.2f KB, ok=%v\n", zkNonMemProverMs, zkNonMemVerifyMs, nonMemSize, nonMemOK1 && nonMemOK2)
	fmt.Printf("Overall (completeness && correctness): %v\n", (memOK1 && memOK2) && (nonMemOK1 && nonMemOK2))
}
