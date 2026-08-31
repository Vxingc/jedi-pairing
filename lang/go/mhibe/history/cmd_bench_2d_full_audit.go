//go:build ignore
// +build ignore

package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/accumulators-agg/bp/bpacc"
	"github.com/accumulators-agg/go-poly/fft"
	"github.com/alinush/go-mcl"
	"github.com/ucbrise/jedi-pairing/lang/go/cryptutils"
	"github.com/ucbrise/jedi-pairing/lang/go/wkdibe"
)

const (
	NumDims                    = 2
	BitLength                  = 12
	MaxKeyPatternDecryptChecks = 64
)

type Point struct{ Coords [NumDims]int64 }
type RangeQuery struct{ Bounds [NumDims][2]int64 }

type DerivedPatternKey struct {
	Pattern string
	Attrs   wkdibe.AttributeList
	Key     *wkdibe.SecretKey
}

type CoverCandidate struct {
	Pattern  string
	Coverage []uint64
}

type GlobalEmptyRegion struct {
	Pattern string
}

type OfflineEmptyMaterial2D struct {
	OccupancyIndex map[string]map[int64]struct{}
	Regions        []GlobalEmptyRegion
	ParentKeys     map[string]DerivedPatternKey
	ParentKeyBytes int
}

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

func join2DPrefix(prefixX, prefixY string) string {
	return prefixX + "||" + prefixY
}

func splitRect2D(
	xMin, xMax, yMin, yMax int64,
	nodeXMin, nodeXMax, nodeYMin, nodeYMax int64,
	prefixX, prefixY string,
) []string {
	if xMax < nodeXMin || xMin > nodeXMax || yMax < nodeYMin || yMin > nodeYMax {
		return nil
	}

	if xMin <= nodeXMin && nodeXMax <= xMax && yMin <= nodeYMin && nodeYMax <= yMax {
		return []string{join2DPrefix(prefixX, prefixY)}
	}

	if nodeXMin == nodeXMax && nodeYMin == nodeYMax {
		return nil
	}

	width := nodeXMax - nodeXMin
	height := nodeYMax - nodeYMin

	if width >= height && nodeXMin < nodeXMax {
		midX := nodeXMin + (nodeXMax-nodeXMin)/2
		left := splitRect2D(
			xMin, xMax, yMin, yMax,
			nodeXMin, midX, nodeYMin, nodeYMax,
			prefixX+"0", prefixY,
		)
		right := splitRect2D(
			xMin, xMax, yMin, yMax,
			midX+1, nodeXMax, nodeYMin, nodeYMax,
			prefixX+"1", prefixY,
		)
		return append(left, right...)
	}

	midY := nodeYMin + (nodeYMax-nodeYMin)/2
	bottom := splitRect2D(
		xMin, xMax, yMin, yMax,
		nodeXMin, nodeXMax, nodeYMin, midY,
		prefixX, prefixY+"0",
	)
	top := splitRect2D(
		xMin, xMax, yMin, yMax,
		nodeXMin, nodeXMax, midY+1, nodeYMax,
		prefixX, prefixY+"1",
	)
	return append(bottom, top...)
}

func MapToIDs(query RangeQuery) []string {
	if NumDims != 2 {
		panic("MapToIDs expects NumDims == 2 in this benchmark")
	}
	maxDomain := int64(math.Pow(2, BitLength)) - 1
	var dimCovers [][]string
	for i := 0; i < NumDims; i++ {
		dimCovers = append(dimCovers, getCanonicalCover(query.Bounds[i][0], query.Bounds[i][1], 0, maxDomain, ""))
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

func IsPointInQuery(p Point, q RangeQuery) bool {
	for i := 0; i < NumDims; i++ {
		if p.Coords[i] < q.Bounds[i][0] || p.Coords[i] > q.Bounds[i][1] {
			return false
		}
	}
	return true
}

// 支持二维/多维主顺序切分器
func generateBitOrderCustom(dimOrder []int, bitLen int) []int {
	var order []int
	for _, d := range dimOrder {
		for i := d * bitLen; i < (d+1)*bitLen; i++ {
			order = append(order, i)
		}
	}
	return order
}

func sumMarshalledKeyBytes(keys []DerivedPatternKey) int {
	total := 0
	for _, key := range keys {
		total += len(key.Key.Marshal(true))
	}
	return total
}

func materializeDatabasePointKeys(
	params *wkdibe.Params,
	msk *wkdibe.MasterKey,
	points []Point,
) ([]DerivedPatternKey, int, error) {
	if len(points) == 0 {
		return nil, 0, nil
	}

	checks := len(points)
	if checks > MaxKeyPatternDecryptChecks {
		checks = MaxKeyPatternDecryptChecks
	}
	sampleAt := make([]int, checks)
	for i := 0; i < checks; i++ {
		sampleAt[i] = i * len(points) / checks
	}

	sampled := make([]DerivedPatternKey, 0, checks)
	totalBytes := 0
	nextSample := 0

	for idx, point := range points {
		pattern := FormatPointToBinary(point)
		attrs, err := patternToAttributeList(pattern)
		if err != nil {
			return nil, 0, fmt.Errorf("database point %d malformed: %w", idx, err)
		}

		key := wkdibe.NonDelegableKeyGen(params, msk, attrs)
		totalBytes += len(key.Marshal(true))

		if nextSample < checks && idx == sampleAt[nextSample] {
			sampled = append(sampled, DerivedPatternKey{
				Pattern: pattern,
				Attrs:   attrs,
				Key:     key,
			})
			nextSample++
		}
	}

	return sampled, totalBytes, nil
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

func prefixBounds(prefix string, bitLen int) (int64, int64) {
	var minVal int64
	for i := 0; i < len(prefix); i++ {
		minVal <<= 1
		if prefix[i] == '1' {
			minVal |= 1
		}
	}

	freeBits := bitLen - len(prefix)
	minVal <<= freeBits
	maxVal := minVal + (int64(1) << freeBits) - 1
	return minVal, maxVal
}

func filterPointsByX(points []Point, minX, maxX int64) []Point {
	filtered := make([]Point, 0, len(points))
	for _, point := range points {
		if point.Coords[0] >= minX && point.Coords[0] <= maxX {
			filtered = append(filtered, point)
		}
	}
	return filtered
}

func buildXPrefixOccupancyIndex(points []Point) map[string]map[int64]struct{} {
	index := make(map[string]map[int64]struct{})
	for _, point := range points {
		xBin := fmt.Sprintf("%0*b", BitLength, point.Coords[0])
		y := point.Coords[1]
		for prefixLen := 0; prefixLen <= len(xBin); prefixLen++ {
			prefix := xBin[:prefixLen]
			bucket := index[prefix]
			if bucket == nil {
				bucket = make(map[int64]struct{})
				index[prefix] = bucket
			}
			bucket[y] = struct{}{}
		}
	}
	return index
}

func emptyYCoversForBounds(minY, maxY int64, occupied map[int64]struct{}) []string {
	values := make([]int64, 0, len(occupied))
	for y := range occupied {
		if y >= minY && y <= maxY {
			values = append(values, y)
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })

	maxDomain := int64(math.Pow(2, BitLength)) - 1
	gapStart := minY
	var covers []string
	for _, y := range values {
		if y < gapStart {
			continue
		}
		if gapStart <= y-1 {
			covers = append(covers, getCanonicalCover(gapStart, y-1, 0, maxDomain, "")...)
		}
		if y+1 > gapStart {
			gapStart = y + 1
		}
	}
	if gapStart <= maxY {
		covers = append(covers, getCanonicalCover(gapStart, maxY, 0, maxDomain, "")...)
	}
	return covers
}

func buildGlobalEmptyRegions2D(index map[string]map[int64]struct{}) []GlobalEmptyRegion {
	maxDomain := int64(math.Pow(2, BitLength)) - 1

	var walkX func(prefixX string, minX, maxX int64) []string
	walkX = func(prefixX string, minX, maxX int64) []string {
		occupied := index[prefixX]
		if len(occupied) == 0 {
			return []string{
				FormatToWildcardPattern(join2DPrefix(prefixX, ""), NumDims, BitLength),
			}
		}

		patterns := make([]string, 0)
		for _, prefixY := range emptyYCoversForBounds(0, maxDomain, occupied) {
			patterns = append(patterns, FormatToWildcardPattern(join2DPrefix(prefixX, prefixY), NumDims, BitLength))
		}

		if len(prefixX) == BitLength {
			return selectMaximalPatterns(patterns)
		}

		midX := minX + (maxX-minX)/2
		patterns = append(patterns, walkX(prefixX+"0", minX, midX)...)
		patterns = append(patterns, walkX(prefixX+"1", midX+1, maxX)...)
		return selectMaximalPatterns(patterns)
	}

	patterns := walkX("", 0, maxDomain)
	regions := make([]GlobalEmptyRegion, 0, len(patterns))
	for _, pattern := range patterns {
		regions = append(regions, GlobalEmptyRegion{Pattern: pattern})
	}
	return regions
}

func deriveGlobalEmptyParentKeys(
	params *wkdibe.Params,
	msk *wkdibe.MasterKey,
	regions []GlobalEmptyRegion,
) (map[string]DerivedPatternKey, int, error) {
	keys := make(map[string]DerivedPatternKey, len(regions))
	totalBytes := 0
	for idx, region := range regions {
		key, err := derivePatternKeyFromRoot(params, msk, region.Pattern, nil)
		if err != nil {
			return nil, 0, fmt.Errorf("global empty parent %d: %w", idx, err)
		}
		keys[region.Pattern] = key
		totalBytes += len(key.Key.Marshal(true))
	}
	return keys, totalBytes, nil
}

func prefixesFromBounds(minVal, maxVal int64) []string {
	maxDomain := int64(math.Pow(2, BitLength)) - 1
	return getCanonicalCover(minVal, maxVal, 0, maxDomain, "")
}

func intersectPatternWithQuery(pattern string, query RangeQuery) ([]string, bool, error) {
	bounds, err := patternToBounds(pattern)
	if err != nil {
		return nil, false, err
	}

	var dimCovers [][]string
	for d := 0; d < NumDims; d++ {
		minVal := bounds[d][0]
		if query.Bounds[d][0] > minVal {
			minVal = query.Bounds[d][0]
		}
		maxVal := bounds[d][1]
		if query.Bounds[d][1] < maxVal {
			maxVal = query.Bounds[d][1]
		}
		if minVal > maxVal {
			return nil, false, nil
		}
		dimCovers = append(dimCovers, prefixesFromBounds(minVal, maxVal))
	}

	patterns := make([]string, 0)
	for _, prefix := range cartesianProduct(dimCovers) {
		childPattern := FormatToWildcardPattern(prefix, NumDims, BitLength)
		if !patternContainsPattern(pattern, childPattern) {
			return nil, false, fmt.Errorf("intersection child %s escapes global empty pattern %s", childPattern, pattern)
		}
		patterns = append(patterns, childPattern)
	}
	return patterns, true, nil
}

func queryScopedEmptyPatternsFromGlobal(global []GlobalEmptyRegion, query RangeQuery) ([]string, error) {
	var scoped []string
	for _, region := range global {
		children, ok, err := intersectPatternWithQuery(region.Pattern, query)
		if err != nil {
			return nil, err
		}
		if ok {
			scoped = append(scoped, children...)
		}
	}
	return selectMaximalPatterns(scoped), nil
}

func deriveQueryScopedEmptyKeysFromOfflineParents(
	params *wkdibe.Params,
	global []GlobalEmptyRegion,
	globalParentKeys map[string]DerivedPatternKey,
	scopedPatterns []string,
) ([]DerivedPatternKey, int, error) {
	touchedParents := make(map[string]struct{})
	scopedKeys := make([]DerivedPatternKey, 0, len(scopedPatterns))

	for _, pattern := range scopedPatterns {
		parentPattern := ""
		for _, region := range global {
			if patternContainsPattern(region.Pattern, pattern) {
				parentPattern = region.Pattern
				break
			}
		}
		if parentPattern == "" {
			return nil, 0, fmt.Errorf("could not find global empty parent for query-scoped pattern %s", pattern)
		}

		parentKey, ok := globalParentKeys[parentPattern]
		if !ok {
			return nil, 0, fmt.Errorf("offline parent key missing for global empty pattern %s", parentPattern)
		}
		touchedParents[parentPattern] = struct{}{}

		childKey, err := derivePatternKeyFromParent(params, parentKey, pattern, nil)
		if err != nil {
			return nil, 0, err
		}
		scopedKeys = append(scopedKeys, childKey)
	}

	touchedParentBytes := 0
	for pattern := range touchedParents {
		touchedParentBytes += len(globalParentKeys[pattern].Key.Marshal(true))
	}
	return scopedKeys, touchedParentBytes, nil
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

// 计算包含 '*' 的通配符前缀所代表的空间体积 (2 的星号数量次方)
func calculateVolume(pattern string) int64 {
	starCount := strings.Count(pattern, "*")
	// 使用位移运算极速求 2^n
	return int64(1) << starCount
}

func attributeValueForBit(slot int, bit byte) (*big.Int, error) {
	if bit != '0' && bit != '1' {
		return nil, fmt.Errorf("invalid bit %q for attribute slot %d", bit, slot)
	}
	payload := []byte{
		'm', 'h', 'i', 'b', 'e',
		byte(slot / BitLength),
		byte(slot % BitLength),
		bit,
	}
	return cryptutils.HashToZp(new(big.Int), payload), nil
}

func patternToAttributeList(pattern string) (wkdibe.AttributeList, error) {
	if len(pattern) != NumDims*BitLength {
		return nil, fmt.Errorf("invalid pattern length %d", len(pattern))
	}

	attrs := make(wkdibe.AttributeList)
	for i := 0; i < len(pattern); i++ {
		switch pattern[i] {
		case '*':
			continue
		case '0', '1':
			value, err := attributeValueForBit(i, pattern[i])
			if err != nil {
				return nil, err
			}
			attrs[wkdibe.AttributeIndex(i)] = value
		default:
			return nil, fmt.Errorf("invalid pattern character %q at %d", pattern[i], i)
		}
	}
	return attrs, nil
}

func patternContainsPattern(parent, child string) bool {
	if len(parent) != len(child) {
		return false
	}
	for i := 0; i < len(parent); i++ {
		if parent[i] == '*' {
			continue
		}
		if parent[i] != child[i] {
			return false
		}
	}
	return true
}

func dedupePatterns(patterns []string) []string {
	seen := make(map[string]struct{}, len(patterns))
	unique := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		if _, ok := seen[pattern]; ok {
			continue
		}
		seen[pattern] = struct{}{}
		unique = append(unique, pattern)
	}
	return unique
}

func selectMaximalPatterns(patterns []string) []string {
	unique := dedupePatterns(patterns)

	sort.Slice(unique, func(i, j int) bool {
		starsI := strings.Count(unique[i], "*")
		starsJ := strings.Count(unique[j], "*")
		if starsI != starsJ {
			return starsI > starsJ
		}
		return unique[i] < unique[j]
	})

	starCounts := make([]int, len(unique))
	for i, pattern := range unique {
		starCounts[i] = strings.Count(pattern, "*")
	}

	maximal := make([]string, 0, len(unique))
	for i, candidate := range unique {
		dominated := false
		for j := 0; j < i && starCounts[j] > starCounts[i]; j++ {
			if patternContainsPattern(unique[j], candidate) {
				dominated = true
				break
			}
		}
		if !dominated {
			maximal = append(maximal, candidate)
		}
	}

	return maximal
}

func bitsetWordCount(size int) int {
	if size <= 0 {
		return 0
	}
	return (size + 63) / 64
}

func newFullBitset(size int) []uint64 {
	words := make([]uint64, bitsetWordCount(size))
	for i := range words {
		words[i] = ^uint64(0)
	}
	if rem := size % 64; rem != 0 {
		words[len(words)-1] = (uint64(1) << rem) - 1
	}
	return words
}

func isBitsetZero(words []uint64) bool {
	for _, word := range words {
		if word != 0 {
			return false
		}
	}
	return true
}

func intersectionCount(a, b []uint64) int {
	total := 0
	for i := range a {
		total += bits.OnesCount64(a[i] & b[i])
	}
	return total
}

func subtractCoverage(dst []uint64, coverage []uint64) {
	for i := range dst {
		dst[i] &^= coverage[i]
	}
}

func forEachSetBit(words []uint64, visit func(int) bool) bool {
	for wordIdx, word := range words {
		for word != 0 {
			bit := bits.TrailingZeros64(word)
			if stop := visit(wordIdx*64 + bit); stop {
				return true
			}
			word &= word - 1
		}
	}
	return false
}

func buildEmptyPointIndex(
	query RangeQuery,
	realPoints map[[NumDims]int64]struct{},
) (map[[NumDims]int64]int, int, error) {
	indexByPoint := make(map[[NumDims]int64]int)
	nextIndex := 0
	err := forEachPointInBounds(query.Bounds, func(p Point) error {
		key := p.Coords
		if _, ok := realPoints[key]; ok {
			return nil
		}
		indexByPoint[key] = nextIndex
		nextIndex++
		return nil
	})
	if err != nil {
		return nil, 0, err
	}
	return indexByPoint, nextIndex, nil
}

func buildCoverCandidates(
	patterns []string,
	query RangeQuery,
	realPoints map[[NumDims]int64]struct{},
) ([]CoverCandidate, int, error) {
	indexByPoint, emptyPointCount, err := buildEmptyPointIndex(query, realPoints)
	if err != nil {
		return nil, 0, err
	}

	candidates := make([]CoverCandidate, 0, len(patterns))
	wordCount := bitsetWordCount(emptyPointCount)

	for idx, pattern := range patterns {
		bounds, err := patternToBounds(pattern)
		if err != nil {
			return nil, 0, fmt.Errorf("candidate pattern %d malformed: %w", idx, err)
		}
		if !boundsInsideQuery(bounds, query) {
			return nil, 0, fmt.Errorf("candidate pattern %d escapes query bounds: %s", idx, pattern)
		}

		coverage := make([]uint64, wordCount)
		err = forEachPointInBounds(bounds, func(p Point) error {
			key := p.Coords
			if _, ok := realPoints[key]; ok {
				return fmt.Errorf("candidate pattern %d incorrectly covers real point %v", idx, key)
			}
			pointIdx, ok := indexByPoint[key]
			if !ok {
				return fmt.Errorf("candidate pattern %d covers unknown empty point %v", idx, key)
			}
			coverage[pointIdx/64] |= uint64(1) << (pointIdx % 64)
			return nil
		})
		if err != nil {
			return nil, 0, err
		}

		if !isBitsetZero(coverage) {
			candidates = append(candidates, CoverCandidate{
				Pattern:  pattern,
				Coverage: coverage,
			})
		}
	}

	return candidates, emptyPointCount, nil
}

func greedySetCover(candidates []CoverCandidate, emptyPointCount int) ([]CoverCandidate, error) {
	uncovered := newFullBitset(emptyPointCount)
	selectedIdx := make([]int, 0)

	for !isBitsetZero(uncovered) {
		bestIdx := -1
		bestGain := 0

		for idx, candidate := range candidates {
			gain := intersectionCount(candidate.Coverage, uncovered)
			if gain > bestGain {
				bestIdx = idx
				bestGain = gain
			}
		}

		if bestIdx == -1 || bestGain == 0 {
			return nil, errors.New("greedy set cover stalled before covering all empty points")
		}

		selectedIdx = append(selectedIdx, bestIdx)
		subtractCoverage(uncovered, candidates[bestIdx].Coverage)
	}

	coverCounts := make([]int, emptyPointCount)
	for _, idx := range selectedIdx {
		forEachSetBit(candidates[idx].Coverage, func(bit int) bool {
			coverCounts[bit]++
			return false
		})
	}

	keep := make([]bool, len(selectedIdx))
	for i := range keep {
		keep[i] = true
	}

	changed := true
	for changed {
		changed = false
		for pos, idx := range selectedIdx {
			if !keep[pos] {
				continue
			}

			essential := forEachSetBit(candidates[idx].Coverage, func(bit int) bool {
				return coverCounts[bit] == 1
			})
			if essential {
				continue
			}

			keep[pos] = false
			changed = true
			forEachSetBit(candidates[idx].Coverage, func(bit int) bool {
				coverCounts[bit]--
				return false
			})
		}
	}

	selected := make([]CoverCandidate, 0, len(selectedIdx))
	for pos, idx := range selectedIdx {
		if keep[pos] {
			selected = append(selected, candidates[idx])
		}
	}

	return selected, nil
}

func derivePatternKeyFromRoot(
	params *wkdibe.Params,
	msk *wkdibe.MasterKey,
	pattern string,
	bitOrder []int,
) (DerivedPatternKey, error) {
	_ = bitOrder
	attrs, err := patternToAttributeList(pattern)
	if err != nil {
		return DerivedPatternKey{}, err
	}

	return DerivedPatternKey{
		Pattern: pattern,
		Attrs:   attrs,
		Key:     wkdibe.KeyGen(params, msk, attrs),
	}, nil
}

func derivePatternKeyFromParent(
	params *wkdibe.Params,
	parent DerivedPatternKey,
	childPattern string,
	bitOrder []int,
) (DerivedPatternKey, error) {
	if !patternContainsPattern(parent.Pattern, childPattern) {
		return DerivedPatternKey{}, fmt.Errorf("child pattern %s is not contained in parent pattern %s", childPattern, parent.Pattern)
	}
	if parent.Pattern == childPattern {
		return parent, nil
	}
	_ = bitOrder
	attrs, err := patternToAttributeList(childPattern)
	if err != nil {
		return DerivedPatternKey{}, err
	}

	return DerivedPatternKey{
		Pattern: childPattern,
		Attrs:   attrs,
		Key:     wkdibe.NonDelegableQualifyKey(params, parent.Key, attrs),
	}, nil
}

func deriveInitialPatternKeys(
	params *wkdibe.Params,
	msk *wkdibe.MasterKey,
	initialPatterns []string,
	bitOrder []int,
) ([]DerivedPatternKey, error) {
	keys := make([]DerivedPatternKey, 0, len(initialPatterns))
	for _, pattern := range initialPatterns {
		derived, err := derivePatternKeyFromRoot(params, msk, pattern, bitOrder)
		if err != nil {
			return nil, err
		}
		keys = append(keys, derived)
	}
	return keys, nil
}

func deriveEmptyPatternKeys(
	params *wkdibe.Params,
	initialKeys []DerivedPatternKey,
	emptyPatterns []string,
	bitOrder []int,
) ([]DerivedPatternKey, error) {
	derived := make([]DerivedPatternKey, 0, len(emptyPatterns))

	for _, pattern := range emptyPatterns {
		parentIdx := -1
		for idx, initialKey := range initialKeys {
			if patternContainsPattern(initialKey.Pattern, pattern) {
				parentIdx = idx
				break
			}
		}
		if parentIdx == -1 {
			return nil, fmt.Errorf("could not find canonical-cover parent for empty pattern %s", pattern)
		}

		key, err := derivePatternKeyFromParent(params, initialKeys[parentIdx], pattern, bitOrder)
		if err != nil {
			return nil, err
		}
		derived = append(derived, key)
	}

	return derived, nil
}

func verifyDerivedPatternKeys(params *wkdibe.Params, derived []DerivedPatternKey) (int, error) {
	if len(derived) == 0 {
		return 0, nil
	}

	checks := len(derived)
	if checks > MaxKeyPatternDecryptChecks {
		checks = MaxKeyPatternDecryptChecks
	}

	for probe := 0; probe < checks; probe++ {
		idx := probe * len(derived) / checks
		item := derived[idx]
		message := new(cryptutils.Encryptable).Random()
		ciphertext := wkdibe.Encrypt(message, params, item.Attrs)
		decrypted := wkdibe.Decrypt(ciphertext, item.Key)
		if !bytes.Equal(message.Bytes(), decrypted.Bytes()) {
			return probe, fmt.Errorf("derived key %d failed to decrypt a ciphertext encrypted under its own pattern", idx)
		}
	}

	return checks, nil
}

func verifyAllDerivedPatternKeys(params *wkdibe.Params, derived []DerivedPatternKey) (int, error) {
	for idx, item := range derived {
		message := new(cryptutils.Encryptable).Random()
		ciphertext := wkdibe.Encrypt(message, params, item.Attrs)
		decrypted := wkdibe.Decrypt(ciphertext, item.Key)
		if !bytes.Equal(message.Bytes(), decrypted.Bytes()) {
			return idx, fmt.Errorf("derived key %d failed to decrypt a ciphertext encrypted under its own pattern", idx)
		}
	}
	return len(derived), nil
}

func globalParentKeysInRegionOrder(
	regions []GlobalEmptyRegion,
	parentKeys map[string]DerivedPatternKey,
) ([]DerivedPatternKey, error) {
	ordered := make([]DerivedPatternKey, len(regions))
	for idx, region := range regions {
		key, ok := parentKeys[region.Pattern]
		if !ok {
			return nil, fmt.Errorf("offline parent key missing for global region %d: %s", idx, region.Pattern)
		}
		ordered[idx] = key
	}
	return ordered, nil
}

func patternToBounds(pattern string) ([NumDims][2]int64, error) {
	var bounds [NumDims][2]int64

	if len(pattern) != NumDims*BitLength {
		return bounds, fmt.Errorf("invalid pattern length %d", len(pattern))
	}

	for d := 0; d < NumDims; d++ {
		var minVal int64
		var maxVal int64

		for i := 0; i < BitLength; i++ {
			idx := d*BitLength + i
			minVal <<= 1
			maxVal <<= 1

			switch pattern[idx] {
			case '0':
			case '1':
				minVal |= 1
				maxVal |= 1
			case '*':
				maxVal |= 1
			default:
				return bounds, fmt.Errorf("invalid pattern character %q at %d", pattern[idx], idx)
			}
		}

		bounds[d] = [2]int64{minVal, maxVal}
	}

	return bounds, nil
}

func boundsInsideQuery(bounds [NumDims][2]int64, query RangeQuery) bool {
	for d := 0; d < NumDims; d++ {
		if bounds[d][0] < query.Bounds[d][0] || bounds[d][1] > query.Bounds[d][1] {
			return false
		}
	}
	return true
}

func forEachPointInBounds(bounds [NumDims][2]int64, visit func(Point) error) error {
	var coords [NumDims]int64

	var walk func(dim int) error
	walk = func(dim int) error {
		if dim == NumDims {
			return visit(Point{Coords: coords})
		}
		for v := bounds[dim][0]; v <= bounds[dim][1]; v++ {
			coords[dim] = v
			if err := walk(dim + 1); err != nil {
				return err
			}
		}
		return nil
	}

	return walk(0)
}

func verifyGlobalEmptyRegions2D(
	regions []GlobalEmptyRegion,
	points []Point,
) (int64, int64, error) {
	domainSize := 1 << BitLength
	totalPoints := domainSize * domainSize
	realBits := make([]uint64, bitsetWordCount(totalPoints))
	emptyCoverBits := make([]uint64, bitsetWordCount(totalPoints))

	for _, point := range points {
		x := int(point.Coords[0])
		y := int(point.Coords[1])
		if x < 0 || x >= domainSize || y < 0 || y >= domainSize {
			return 0, 0, fmt.Errorf("database point %v lies outside the encoded domain", point.Coords)
		}
		idx := x*domainSize + y
		realBits[idx/64] |= uint64(1) << (idx % 64)
	}

	for regionIdx, region := range regions {
		bounds, err := patternToBounds(region.Pattern)
		if err != nil {
			return 0, 0, fmt.Errorf("global region %d malformed: %w", regionIdx, err)
		}
		for x := int(bounds[0][0]); x <= int(bounds[0][1]); x++ {
			rowBase := x * domainSize
			for y := int(bounds[1][0]); y <= int(bounds[1][1]); y++ {
				idx := rowBase + y
				mask := uint64(1) << (idx % 64)
				if realBits[idx/64]&mask != 0 {
					return 0, 0, fmt.Errorf("global empty region %d covers real point [%d %d]", regionIdx, x, y)
				}
				emptyCoverBits[idx/64] |= mask
			}
		}
	}

	var uniqueRealPoints int64
	var coveredEmptyPoints int64
	for wordIdx := range realBits {
		if realBits[wordIdx]&emptyCoverBits[wordIdx] != 0 {
			return 0, 0, fmt.Errorf("global empty cover intersects real data in bitset word %d", wordIdx)
		}
		if realBits[wordIdx]|emptyCoverBits[wordIdx] != ^uint64(0) {
			return 0, 0, fmt.Errorf("global empty cover leaves an uncovered domain point in bitset word %d", wordIdx)
		}
		uniqueRealPoints += int64(bits.OnesCount64(realBits[wordIdx]))
		coveredEmptyPoints += int64(bits.OnesCount64(emptyCoverBits[wordIdx]))
	}

	if uniqueRealPoints+coveredEmptyPoints != int64(totalPoints) {
		return 0, 0, fmt.Errorf(
			"global cover cardinality mismatch: real=%d empty=%d domain=%d",
			uniqueRealPoints,
			coveredEmptyPoints,
			totalPoints,
		)
	}
	return coveredEmptyPoints, uniqueRealPoints, nil
}

func verifyEmptyRegionPatterns(
	query RangeQuery,
	emptyPatterns []string,
	realPoints map[[NumDims]int64]struct{},
) (int64, int, error) {
	coverage := make(map[[NumDims]int64]int)
	maxMultiplicity := 0

	for idx, pattern := range emptyPatterns {
		bounds, err := patternToBounds(pattern)
		if err != nil {
			return 0, 0, fmt.Errorf("pattern %d malformed: %w", idx, err)
		}
		if !boundsInsideQuery(bounds, query) {
			return 0, 0, fmt.Errorf("pattern %d escapes query bounds: %s", idx, pattern)
		}

		err = forEachPointInBounds(bounds, func(p Point) error {
			key := p.Coords
			if _, ok := realPoints[key]; ok {
				return fmt.Errorf("pattern %d incorrectly covers real point %v", idx, key)
			}
			coverage[key]++
			if coverage[key] > maxMultiplicity {
				maxMultiplicity = coverage[key]
			}
			return nil
		})
		if err != nil {
			return 0, 0, err
		}
	}

	var coveredEmptyPoints int64
	err := forEachPointInBounds(query.Bounds, func(p Point) error {
		key := p.Coords
		_, isRealPoint := realPoints[key]
		hitCount := coverage[key]

		if isRealPoint {
			if hitCount != 0 {
				return fmt.Errorf("real point %v was covered by %d empty patterns", key, hitCount)
			}
			return nil
		}

		if hitCount == 0 {
			return fmt.Errorf("empty point %v was covered by %d empty patterns", key, hitCount)
		}

		coveredEmptyPoints++
		return nil
	})
	if err != nil {
		return 0, 0, err
	}

	if coveredEmptyPoints < int64(len(coverage)) {
		return 0, 0, errors.New("empty coverage cardinality mismatch")
	}

	return coveredEmptyPoints, maxMultiplicity, nil
}

// ==========================================
// 终极对决：2D M-HIBE Bi-Sweep + ZK-Accumulator
// ==========================================
func main() {
	uploadKeys := flag.Bool("upload-keys", false, "materialize WKD-IBE keys for every database row before benchmarking")
	skipZK := flag.Bool("skip-zk", false, "skip ZK accumulator proof generation and verification")
	dataPath := flag.String("data", "/home/xing/poneglyphdb/src/data/lineitem_120K.tbl", "TPC-H lineitem .tbl file")
	limit := flag.Int("limit", 0, "maximum number of lineitem rows to load; 0 means all rows")
	poneglyphQ6 := flag.Bool("poneglyph-q6", false, "use PoneglyphDB-compatible 2D range bounds: shipdate [1994-01-01, 1994-12-31] and discount [0.05, 0.07]")
	dateMin := flag.String("date-min", "1994-01-01", "inclusive shipdate lower bound for this benchmark")
	dateMax := flag.String("date-max", "1994-12-31", "inclusive shipdate upper bound for this benchmark")
	discountScale := flag.Int64("discount-scale", 100, "scale factor for encoding l_discount from the .tbl file")
	discountMin := flag.Int64("discount-min", 5, "inclusive encoded l_discount lower bound")
	discountMax := flag.Int64("discount-max", 7, "inclusive encoded l_discount upper bound")
	verifyOfflineGlobal := flag.Bool("verify-offline-global", true, "audit the query-independent global empty cover over the complete 2D domain")
	flag.Parse()

	if *poneglyphQ6 {
		// Equivalent to the PoneglyphDB circuit bounds:
		// 1993-12-31 < shipdate < 1995-01-01 and 0.04 < discount < 0.08.
		*dateMin = "1994-01-01"
		*dateMax = "1994-12-31"
		*discountMin = int64(math.Round(0.05 * float64(*discountScale)))
		*discountMax = int64(math.Round(0.07 * float64(*discountScale)))
		if *limit == 0 {
			*limit = 120000
		}
	}

	fmt.Println("[*] Starting ULTIMATE ARCHITECTURE Benchmark...")
	fmt.Println("[*] Mode: 2D Query-Independent Offline X-Parent Supplement + Optimized Serial + Full Cryptographic Audit")

	// 0. 全局初始化
	mcl.InitFromString("bls12-381")
	setupStart := time.Now()
	params, masterKey := wkdibe.Setup(NumDims*BitLength, true)

	var acc bpacc.BpAcc
	keyDir := "./pkvk-17"
	acc.KeyGenLoad(8, 17, "my_secure_seed", keyDir)
	setupMs := float64(time.Since(setupStart).Nanoseconds()) / 1e6
	fmt.Printf("[*] Global Setup Time: %.2f ms\n\n", setupMs)

	// 1. 数据加载与分类
	file, err := os.Open(*dataPath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	var dbData []Point
	var dbFr []mcl.Fr
	var I []mcl.Fr // 命中集合
	var X []mcl.Fr // 未命中集合
	queryUniquePoints := make(map[[NumDims]int64]struct{})

	fmt.Printf("[*] Data Path: %s\n", *dataPath)
	if *limit > 0 {
		fmt.Printf("[*] Row Limit: first %d lineitem rows\n", *limit)
	}
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if *limit > 0 && len(dbData) >= *limit {
			break
		}
		line := scanner.Text()
		cols := strings.Split(line, "|")
		if len(cols) < 11 {
			continue
		}

		var p Point
		dFloat, _ := strconv.ParseFloat(cols[6], 64)
		p.Coords[1] = int64(math.Round(dFloat * float64(*discountScale)))
		p.Coords[0] = ParseDate(cols[10])
		dbData = append(dbData, p)

		fr := bpacc.SeedToFr(FormatPointToBinary(p))
		dbFr = append(dbFr, fr)
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
	fmt.Printf("[*] Loaded %d real TPC-H records.\n", len(dbData))

	fmt.Println("\n=== QUERY-INDEPENDENT DATABASE OFFLINE INITIALIZATION ===")
	offlineEmptyStart := time.Now()

	emptyIndexStart := time.Now()
	databaseEmptyIndex := buildXPrefixOccupancyIndex(dbData)
	emptyIndexMs := float64(time.Since(emptyIndexStart).Nanoseconds()) / 1e6

	globalRegionStart := time.Now()
	globalEmptyRegions := buildGlobalEmptyRegions2D(databaseEmptyIndex)
	globalRegionMs := float64(time.Since(globalRegionStart).Nanoseconds()) / 1e6

	globalParentKeyStart := time.Now()
	globalParentKeys, globalParentKeyMaterialBytes, err := deriveGlobalEmptyParentKeys(params, masterKey, globalEmptyRegions)
	if err != nil {
		panic(err)
	}
	globalParentKeyMs := float64(time.Since(globalParentKeyStart).Nanoseconds()) / 1e6
	offlineEmptyMs := float64(time.Since(offlineEmptyStart).Nanoseconds()) / 1e6

	offlineEmptyMaterial := OfflineEmptyMaterial2D{
		OccupancyIndex: databaseEmptyIndex,
		Regions:        globalEmptyRegions,
		ParentKeys:     globalParentKeys,
		ParentKeyBytes: globalParentKeyMaterialBytes,
	}

	fmt.Printf("[+] X-Prefix Occupancy Index Build Time: %.2f ms\n", emptyIndexMs)
	fmt.Printf("[+] Global Empty Region Enumeration Time: %.2f ms\n", globalRegionMs)
	fmt.Printf("[+] Global Empty Parent Key Generation Time: %.2f ms\n", globalParentKeyMs)
	fmt.Printf("[+] Offline Empty Initialization Total: %.2f ms\n", offlineEmptyMs)
	fmt.Printf("[+] Indexed X-Prefix Nodes: %d\n", len(databaseEmptyIndex))
	fmt.Printf("[+] Database-Wide Global Empty Parent Regions: %d\n", len(globalEmptyRegions))
	fmt.Printf("[+] Database-Wide Global Parent Key Material: %.2f KB\n", float64(globalParentKeyMaterialBytes)/1024.0)
	fmt.Println("[+] Query Dependency: NONE (query has not been constructed)")
	var globalAuditMs float64
	if *verifyOfflineGlobal {
		globalAuditStart := time.Now()
		coveredGlobalEmptyPoints, uniqueGlobalRealPoints, auditErr := verifyGlobalEmptyRegions2D(globalEmptyRegions, dbData)
		globalAuditMs = float64(time.Since(globalAuditStart).Nanoseconds()) / 1e6
		if auditErr != nil {
			panic(fmt.Errorf("query-independent global empty cover audit failed: %w", auditErr))
		}
		fmt.Printf("[+] Offline Global Cover Audit Time: %.2f ms (SUCCESS)\n", globalAuditMs)
		fmt.Printf("    -> [Detail] %d unique real points + %d global empty points = %d domain points.\n",
			uniqueGlobalRealPoints,
			coveredGlobalEmptyPoints,
			uniqueGlobalRealPoints+coveredGlobalEmptyPoints,
		)
	}

	orderedGlobalParentKeys, err := globalParentKeysInRegionOrder(globalEmptyRegions, globalParentKeys)
	if err != nil {
		panic(err)
	}
	globalParentCryptoAuditStart := time.Now()
	globalParentKeyChecks, globalParentKeyCheckErr := verifyAllDerivedPatternKeys(params, orderedGlobalParentKeys)
	globalParentCryptoAuditMs := float64(time.Since(globalParentCryptoAuditStart).Nanoseconds()) / 1e6
	if globalParentKeyCheckErr != nil {
		panic(fmt.Errorf("offline global parent full cryptographic audit failed: %w", globalParentKeyCheckErr))
	}
	fmt.Printf("[+] Offline Global Parent Full Crypto Audit: %d/%d keys in %.2f ms (SUCCESS)\n",
		globalParentKeyChecks,
		len(orderedGlobalParentKeys),
		globalParentCryptoAuditMs,
	)
	fmt.Println("    -> [Detail] Audit time is reported separately and is not included in setup cost.")

	var query RangeQuery
	query.Bounds[0] = [2]int64{ParseDate(*dateMin), ParseDate(*dateMax)}
	query.Bounds[1] = [2]int64{*discountMin, *discountMax}
	for idx, p := range dbData {
		if IsPointInQuery(p, query) {
			I = append(I, dbFr[idx])
			queryUniquePoints[p.Coords] = struct{}{}
		} else {
			X = append(X, dbFr[idx])
		}
	}

	fmt.Println("\n=== QUERY ARRIVAL ===")
	fmt.Printf("[*] Query Bounds: shipdate [%s, %s], encoded discount [%d, %d] (scale=%d)\n",
		*dateMin, *dateMax, *discountMin, *discountMax, *discountScale)
	fmt.Printf("[*] Query matched %d real records.\n", len(I))

	if *uploadKeys {
		// ========================================================
		// UPLOAD STAGE: full database key materialization
		// ========================================================
		fmt.Println("\n=== UPLOAD STAGE: FULL DATABASE KEY GENERATION ===")
		uploadStart := time.Now()
		uploadKeySamples, uploadKeyBytes, err := materializeDatabasePointKeys(params, masterKey, dbData)
		if err != nil {
			panic(err)
		}
		uploadKeyChecks, uploadVerifyErr := verifyDerivedPatternKeys(params, uploadKeySamples)
		uploadMs := float64(time.Since(uploadStart).Nanoseconds()) / 1e6
		fmt.Printf("[+] Upload Key Materialization Time: %.2f ms\n", uploadMs)
		fmt.Printf("[+] Upload Key Material: %.2f KB\n", float64(uploadKeyBytes)/1024.0)
		if uploadVerifyErr != nil {
			fmt.Printf("[-] Upload Key Sampling Check FAILED: %v\n", uploadVerifyErr)
		} else {
			fmt.Printf("[+] Upload Key Sampling Check: %d samples\n", uploadKeyChecks)
		}
	} else {
		fmt.Println("\n=== UPLOAD STAGE: SKIPPED ===")
		fmt.Println("[*] Use -upload-keys to materialize WKD-IBE keys for every database row.")
	}

	// ========================================================
	// ENGINE A: 2D M-HIBE BI-SWEEP (绝对零知识边界)
	// ========================================================
	fmt.Println("\n=== ENGINE A: 2D M-HIBE X-PARENT SUPPLEMENT (Confidentiality & Access Control) ===")
	extractionStart := time.Now()

	initialPrefixes := MapToIDs(query)
	var initialPatterns []string
	for _, p := range initialPrefixes {
		initialPatterns = append(initialPatterns, FormatToWildcardPattern(p, NumDims, BitLength))
	}

	selectedCoverPatterns, err := queryScopedEmptyPatternsFromGlobal(offlineEmptyMaterial.Regions, query)
	if err != nil {
		panic(err)
	}
	extractionMs := float64(time.Since(extractionStart).Nanoseconds()) / 1e6

	cryptoStart := time.Now()
	queryRangeKeys, err := deriveInitialPatternKeys(params, masterKey, initialPatterns, nil)
	if err != nil {
		panic(err)
	}
	queryRangeKeyBytes := sumMarshalledKeyBytes(queryRangeKeys)
	verificationEmptyKeys, touchedGlobalParentKeyBytes, err := deriveQueryScopedEmptyKeysFromOfflineParents(
		params,
		offlineEmptyMaterial.Regions,
		offlineEmptyMaterial.ParentKeys,
		selectedCoverPatterns,
	)
	if err != nil {
		panic(err)
	}
	emptyKeyBytes := sumMarshalledKeyBytes(verificationEmptyKeys)
	mhibeCryptoMs := float64(time.Since(cryptoStart).Nanoseconds()) / 1e6
	engineAMs := extractionMs + mhibeCryptoMs

	fmt.Printf("1. Query Canonical Range Keys: %d\n", len(queryRangeKeys))
	fmt.Printf("2. Database-Wide Global Empty Parent Regions Available: %d\n", len(offlineEmptyMaterial.Regions))
	fmt.Printf("3. Query-Scoped Empty Regions: %d\n", len(verificationEmptyKeys))
	fmt.Printf("4. Cover Strategy: query-independent offline global parents + optimized serial online intersection/delegation\n")
	fmt.Printf("5. Online Query Intersection Time: %.2f ms\n", extractionMs)
	fmt.Printf("6. Query-Range Key Material: %.2f KB\n", float64(queryRangeKeyBytes)/1024.0)
	fmt.Printf("7. Offline Global Parent Key Material Total: %.2f KB\n", float64(offlineEmptyMaterial.ParentKeyBytes)/1024.0)
	fmt.Printf("8. Offline Global Parent Key Material Touched: %.2f KB\n", float64(touchedGlobalParentKeyBytes)/1024.0)
	fmt.Printf("9. Query-Scoped Empty Key Material: %.2f KB\n", float64(emptyKeyBytes)/1024.0)
	fmt.Printf("10. Online WKD-IBE Delegation Time: %.2f ms\n", mhibeCryptoMs)
	fmt.Printf("-> Engine A Total: %.2f ms\n", engineAMs)
	// ========================================================
	// CLIENT ENGINE A: COMPLETENESS VERIFIER (精准完备性校验)
	// ========================================================
	fmt.Println("\n=== ENGINE A: CLIENT PROTOCOL CHECK + SEPARATE EXPERIMENTAL AUDITS ===")

	// 1. 计算原始查询框的总容量
	var totalQueryVolume int64 = 0
	for _, p := range initialPatterns {
		totalQueryVolume += calculateVolume(p)
	}

	// 2. 客户端严格验证最终 selected cover 输出的空区域 key：
	//    - 每个 key 必须完全位于查询框内
	//    - 不能覆盖任何真实命中点
	//    - 所有查询内缺失点必须至少被 1 个 key 覆盖
	geometryCheckStart := time.Now()
	coveredEmptyPoints, maxOverlap, verifyErr := verifyEmptyRegionPatterns(query, selectedCoverPatterns, queryUniquePoints)
	geometryCheckMs := float64(time.Since(geometryCheckStart).Nanoseconds()) / 1e6

	queryRangeCryptoCheckStart := time.Now()
	queryRangeKeyChecks, queryRangeKeyVerifyErr := verifyAllDerivedPatternKeys(params, queryRangeKeys)
	queryRangeCryptoCheckMs := float64(time.Since(queryRangeCryptoCheckStart).Nanoseconds()) / 1e6

	emptyKeyCryptoCheckStart := time.Now()
	emptyKeyChecks, emptyKeyVerifyErr := verifyAllDerivedPatternKeys(params, verificationEmptyKeys)
	emptyKeyCryptoCheckMs := float64(time.Since(emptyKeyCryptoCheckStart).Nanoseconds()) / 1e6

	// 3. 统计真实命中点占据的独特空间点数
	realSpatialVolume := int64(len(queryUniquePoints))

	if verifyErr == nil && queryRangeKeyVerifyErr == nil && emptyKeyVerifyErr == nil && coveredEmptyPoints+realSpatialVolume == totalQueryVolume {
		fmt.Printf("[+] Client Protocol Geometric Completeness Time: %.4f ms (SUCCESS! Complete key cover.)\n", geometryCheckMs)
		fmt.Printf("    -> [Detail] %d matching rows collapsed into %d unique spatial points.\n", len(I), realSpatialVolume)
		fmt.Printf("    -> [Detail] %d empty-region keys cover %d empty spatial points.\n", len(verificationEmptyKeys), coveredEmptyPoints)
		fmt.Printf("    -> [Detail] Maximum overlap multiplicity among selected cover blocks: %d.\n", maxOverlap)
		fmt.Printf("[Audit] Query-range full crypto self-check: %d/%d keys in %.4f ms.\n",
			queryRangeKeyChecks,
			len(queryRangeKeys),
			queryRangeCryptoCheckMs,
		)
		fmt.Printf("[Audit] Query-scoped empty-key full crypto self-check: %d/%d keys in %.4f ms.\n",
			emptyKeyChecks,
			len(verificationEmptyKeys),
			emptyKeyCryptoCheckMs,
		)
	} else {
		if verifyErr != nil {
			fmt.Printf("[-] Client Empty-Key Check: FAILED! (%v)\n", verifyErr)
		} else if queryRangeKeyVerifyErr != nil {
			fmt.Printf("[-] Client Query-Range Full Crypto Audit: FAILED! (%v)\n", queryRangeKeyVerifyErr)
		} else if emptyKeyVerifyErr != nil {
			fmt.Printf("[-] Client Empty-Key Full Crypto Audit: FAILED! (%v)\n", emptyKeyVerifyErr)
		} else {
			fmt.Printf("[-] Client Empty-Key Check: FAILED! (Empty: %d, Unique Real: %d, Target: %d)\n", coveredEmptyPoints, realSpatialVolume, totalQueryVolume)
		}
	}
	var zkCommitMs, zkProverMs, zkVerifierMs float64
	if !*skipZK {
		// ========================================================
		// ENGINE B: ZK-ACCUMULATOR (Authenticity)
		// ========================================================
		fmt.Println("\n=== ENGINE B: ZK-ACCUMULATOR (Authenticity) ===")
		commitStart := time.Now()
		digestDB, _ := acc.Commit(dbFr)
		digestX, _ := acc.Commit(X)
		zkCommitMs = float64(time.Since(commitStart).Nanoseconds()) / 1e6
		fmt.Printf("[+] ZK Commitment Time: %.2f ms\n", zkCommitMs)

		zkProverStart := time.Now()
		var transcript [32]byte
		var random mcl.Fr
		random.Random()

		I_poly := fft.PolyTree(I)
		C_I := bpacc.PedG2{Com: acc.PedersenG2(I_poly, acc.VK, random, acc.PedVK[0]), R: random}

		zkMemProof := acc.ZKMemProver(C_I, digestX, transcript)
		zkDegProof := acc.ZKDegCheckProver(C_I, I_poly, zkMemProof.HashProof(transcript))

		zkProverMs = float64(time.Since(zkProverStart).Nanoseconds()) / 1e6
		zkMemSize := float64(zkMemProof.ByteSize()) / 1024.0
		zkDegSize := float64(zkDegProof.ByteSize()) / 1024.0

		fmt.Printf("[+] ZK Prover Time: %.2f ms\n", zkProverMs)
		fmt.Printf("[+] ZK Proof Size: %.2f KB (Mem) + %.2f KB (Deg) = %.2f KB\n", zkMemSize, zkDegSize, zkMemSize+zkDegSize)

		zkVerifierStart := time.Now()
		ok1 := acc.ZKMemVerifier(zkMemProof, digestDB, C_I.Com, transcript)
		ok2 := acc.ZKDegCheckVerifier(C_I.Com, zkDegProof, zkMemProof.HashProof(transcript))
		zkVerifierMs = float64(time.Since(zkVerifierStart).Nanoseconds()) / 1e6

		if ok1 && ok2 {
			fmt.Printf("[+] Client ZK Verifier Time: %.2f ms (SUCCESS!)\n", zkVerifierMs)
		} else {
			fmt.Println("[-] ZK Verification FAILED!")
		}
	} else {
		fmt.Println("\n=== ENGINE B: SKIPPED ===")
	}

	// ========================================================
	// FINAL REPORT
	// ========================================================
	fmt.Println("\n=== ULTIMATE ACADEMIC REPORT ===")
	fmt.Printf("Architecture: 2D Query-Independent Offline M-HIBE X-Parent Supplement + Optimized Serial + Full Cryptographic Audit + ZK-Accumulator\n")
	totalSetupMs := setupMs + offlineEmptyMs + zkCommitMs
	totalServerMs := engineAMs + zkProverMs
	totalClientProtocolMs := zkVerifierMs + geometryCheckMs
	fmt.Printf("Total Setup Time: %.2f ms\n", totalSetupMs)
	fmt.Printf("Total Server Proving Time: %.2f ms (%.2f s)\n", totalServerMs, totalServerMs/1000.0)
	fmt.Printf("Total Client Protocol Verification Time: %.2f ms\n", totalClientProtocolMs)
	fmt.Printf("Total Protocol Time Excluding Experimental Audits: %.2f ms\n", totalSetupMs+totalServerMs+totalClientProtocolMs)
	totalFullCryptoAuditMs := globalParentCryptoAuditMs + queryRangeCryptoCheckMs + emptyKeyCryptoCheckMs
	fmt.Printf("Total Full Cryptographic Audit Time: %.2f ms (offline parents + query range + query empty keys)\n", totalFullCryptoAuditMs)
	fmt.Printf("Total Experimental Audit Time: %.2f ms (global cover + all cryptographic self-checks)\n", globalAuditMs+totalFullCryptoAuditMs)
}
