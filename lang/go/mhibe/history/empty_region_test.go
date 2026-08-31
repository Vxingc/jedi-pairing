package mhibe_test

import (
	"fmt"
	"strings"
	"testing"
)

// ==========================================
// Phase 4: 空区域切割算法 (Prefix Splitting)
// ==========================================

// FormatToWildcardPattern 将 "001||010" 转化为 "001*010*"
func FormatToWildcardPattern(prefix string, numDims int, bitLen int) string {
	dims := strings.Split(prefix, "||")
	var patternBuilder strings.Builder
	for d := 0; d < numDims; d++ {
		dimPrefix := dims[d]
		patternBuilder.WriteString(dimPrefix)
		// 补齐通配符 '*'
		for i := len(dimPrefix); i < bitLen; i++ {
			patternBuilder.WriteByte('*')
		}
	}
	return patternBuilder.String()
}

// FormatPointToBinary 将 Point 转化为完整的二进制字符串 "00110100"
func FormatPointToBinary(p Point) string {
	var builder strings.Builder
	for i := 0; i < NumDims; i++ {
		builder.WriteString(fmt.Sprintf("%0*b", BitLength, p.Coords[i]))
	}
	return builder.String()
}

// matches 检查一个具体的数据点是否落在某个包含通配符的 pattern 内
func matches(pattern string, pointBin string) bool {
	for i := 0; i < len(pattern); i++ {
		if pattern[i] != '*' && pattern[i] != pointBin[i] {
			return false
		}
	}
	return true
}

// SubtractPoint 核心算法：从一个 pattern 中“挖去”一个具体的数据点
// 返回一个或多个纯空区域的 pattern 集合
func SubtractPoint(pattern string, pointBin string) []string {
	// 如果数据点根本不在这个模式内，模式不受影响，直接返回
	if !matches(pattern, pointBin) {
		return []string{pattern}
	}

	var emptyRegions []string
	currentPattern := []byte(pattern)

	// 遍历查找通配符，进行二叉树分裂
	for i := 0; i < len(currentPattern); i++ {
		if currentPattern[i] == '*' {
			targetBit := pointBin[i]

			// 1. 生成不包含 target 的空分支 (Empty Branch)
			emptyBranch := make([]byte, len(currentPattern))
			copy(emptyBranch, currentPattern)
			if targetBit == '0' {
				emptyBranch[i] = '1'
			} else {
				emptyBranch[i] = '0'
			}
			emptyRegions = append(emptyRegions, string(emptyBranch))

			// 2. 将 currentPattern 更新为包含 target 的分支，继续向下分裂
			currentPattern[i] = targetBit
		}
	}

	// 循环结束后，currentPattern 就变成了数据点本身 (已被完全剥离)，不再返回
	return emptyRegions
}

// SubtractPoints 从一组初始查询 patterns 中，剔除掉所有真实存在的点
func SubtractPoints(initialPatterns []string, dataPoints []Point) []string {
	currentPatterns := initialPatterns

	for _, p := range dataPoints {
		pointBin := FormatPointToBinary(p)
		var nextPatterns []string

		// 让所有的 pattern 都经历一次这个点的剔除
		for _, pat := range currentPatterns {
			splitted := SubtractPoint(pat, pointBin)
			nextPatterns = append(nextPatterns, splitted...)
		}
		currentPatterns = nextPatterns
	}

	return currentPatterns
}

// ==========================================
// 单元测试与极端场景验证
// ==========================================

func TestEmptyRegionExtraction(t *testing.T) {
	fmt.Println("=== [Phase 4] Empty Region Extraction Engine ===")

	// 1. 模拟客户端发起的查询范围: X[2, 5], Y[3, 6] (共 16 个点)
	query := RangeQuery{Bounds: [NumDims][2]int64{{2, 5}, {3, 6}}}
	initialPrefixes := MapToIDs(query)

	var initialPatterns []string
	for _, p := range initialPrefixes {
		initialPatterns = append(initialPatterns, FormatToWildcardPattern(p, NumDims, BitLength))
	}
	fmt.Printf("Initial Query Patterns (Covers 16 points):\n %v\n\n", initialPatterns)

	// 2. 模拟数据库里的真实数据
	// 包含两个在范围内的点: (3,4) 和 (5,6)
	// 包含一个在范围外的点: (1,1) -> 应该被算法自动忽略
	dbData := []Point{
		{Coords: [NumDims]int64{3, 4}}, // 0011 0100
		{Coords: [NumDims]int64{5, 6}}, // 0101 0110
		{Coords: [NumDims]int64{1, 1}}, // out of bounds
	}
	fmt.Printf("Database contains points: (3,4), (5,6), (1,1)\n")

	// 3. 执行空区域提取
	emptyPatterns := SubtractPoints(initialPatterns, dbData)
	fmt.Printf("\nGenerated %d Empty Region Keys for Non-membership Proof:\n", len(emptyPatterns))
	for i, pat := range emptyPatterns {
		fmt.Printf("  [%d] %s\n", i, pat)
	}

	// 4. 严苛的神级验证 (Soundness & Completeness Check)
	// 我们遍历全空间 [0, 15] x [0, 15] 的 256 个点
	fmt.Println("\n[Verifying completeness and soundness of empty regions...]")
	matchCount := 0

	for x := int64(0); x <= 15; x++ {
		for y := int64(0); y <= 15; y++ {
			p := Point{Coords: [NumDims]int64{x, y}}
			binStr := FormatPointToBinary(p)

			// 判断这个点是否在查询范围内
			inRange := (x >= 2 && x <= 5) && (y >= 3 && y <= 6)
			// 判断这个点是否是真实数据
			isRealData := (x == 3 && y == 4) || (x == 5 && y == 6)

			// 计算这个点命中了多少个"空区域 Pattern"
			hitCount := 0
			for _, ep := range emptyPatterns {
				if matches(ep, binStr) {
					hitCount++
				}
			}

			// 断言规则:
			if isRealData {
				// 规则 A: 真实数据绝对不能被空区域覆盖 (否则数据库就伪造了空证明)
				if hitCount > 0 {
					t.Fatalf("CRITICAL ALARM: Real Data %v matched an empty region!", p.Coords)
				}
			} else if inRange {
				// 规则 B: 在查询范围内且不是真实数据的点，必须被且仅被 1 个空区域精确覆盖 (保证完整性)
				if hitCount != 1 {
					t.Fatalf("Completeness Error: Point %v is empty and in range, but hit %d empty regions!", p.Coords, hitCount)
				}
				matchCount++
			} else {
				// 规则 C: 范围外的点绝对不能被覆盖 (不越权)
				if hitCount > 0 {
					t.Fatalf("Out-of-bounds point %v matched an empty region!", p.Coords)
				}
			}
		}
	}

	expectedEmptyPoints := (5-2+1)*(6-3+1) - 2 // 16 个点 - 2个真实数据点 = 14个空点
	if matchCount != expectedEmptyPoints {
		t.Fatalf("Expected %d empty points covered, but got %d", expectedEmptyPoints, matchCount)
	}

	fmt.Printf("[Success] Algorithm mathematically perfect! Exactly %d empty points are strictly covered by the generated keys without any overlap or leakage.\n", matchCount)
}
