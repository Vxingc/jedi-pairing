//go:build ignore
// +build ignore

package main

import (
	"bufio"
	"container/heap"
	"errors"
	"flag"
	"fmt"
	"math"
	"math/big"
	"math/bits"
	"os"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/accumulators-agg/bp/bpacc"
	"github.com/accumulators-agg/go-poly/fft"
	"github.com/alinush/go-mcl"
	"github.com/ucbrise/jedi-pairing/lang/go/cryptutils"
	"github.com/ucbrise/jedi-pairing/lang/go/wkdibe"
)

const (
	NumDims   = 10
	BitLength = 12
)

var mhibeWorkers = runtime.NumCPU()

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

type OfflineEmptyMaterial struct {
	Regions        []GlobalEmptyRegion
	ParentKeys     map[string]DerivedPatternKey
	ParentKeyBytes int
}

func fullDomainQuery() RangeQuery {
	var query RangeQuery
	maxDomain := int64(1<<BitLength) - 1
	for dim := 0; dim < NumDims; dim++ {
		query.Bounds[dim] = [2]int64{0, maxDomain}
	}
	return query
}

type PrefixNode struct {
	Prefix string
	Min    int64
	Max    int64
}

func effectiveWorkers(workItems int) int {
	if workItems <= 1 {
		return 1
	}
	workers := mhibeWorkers
	if workers < 1 {
		workers = 1
	}
	if workers > workItems {
		workers = workItems
	}
	return workers
}

func parallelFor(workItems int, fn func(int) error) error {
	workers := effectiveWorkers(workItems)
	if workers == 1 {
		for i := 0; i < workItems; i++ {
			if err := fn(i); err != nil {
				return err
			}
		}
		return nil
	}

	jobs := make(chan int)
	var wg sync.WaitGroup
	var once sync.Once
	var firstErr error

	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for idx := range jobs {
				if err := fn(idx); err != nil {
					once.Do(func() {
						firstErr = err
					})
				}
			}
		}()
	}

	for i := 0; i < workItems; i++ {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return firstErr
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

	var totalBytes int64

	if err := parallelFor(len(points), func(idx int) error {
		point := points[idx]
		pattern := FormatPointToBinary(point)
		attrs, err := patternToAttributeList(pattern)
		if err != nil {
			return fmt.Errorf("database point %d malformed: %w", idx, err)
		}

		key := wkdibe.NonDelegableKeyGen(params, msk, attrs)
		atomic.AddInt64(&totalBytes, int64(len(key.Marshal(true))))

		return nil
	}); err != nil {
		return nil, 0, err
	}

	return nil, int(totalBytes), nil
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

func prefixPairKey(prefixX, prefixY string) string {
	return prefixX + "||" + prefixY
}

func addOccupiedValue(index map[string]map[int64]struct{}, key string, value int64) {
	bucket := index[key]
	if bucket == nil {
		bucket = make(map[int64]struct{})
		index[key] = bucket
	}
	bucket[value] = struct{}{}
}

func mergeOccupiedIndex(dst, src map[string]map[int64]struct{}) {
	for key, values := range src {
		bucket := dst[key]
		if bucket == nil {
			bucket = make(map[int64]struct{}, len(values))
			dst[key] = bucket
		}
		for value := range values {
			bucket[value] = struct{}{}
		}
	}
}

type EmptyIndexND struct {
	Levels []map[string]map[int64]struct{}
}

func parentCacheKey(nextDim int, parentPrefixes []string) string {
	return fmt.Sprintf("%d::%s", nextDim, strings.Join(parentPrefixes, "||"))
}

func prefixNodeBounds(prefix string) (int64, int64) {
	var minVal int64
	for i := 0; i < len(prefix); i++ {
		minVal <<= 1
		if prefix[i] == '1' {
			minVal |= 1
		}
	}
	remaining := BitLength - len(prefix)
	maxVal := minVal
	if remaining > 0 {
		minVal <<= remaining
		maxVal = minVal + (int64(1) << remaining) - 1
	}
	return minVal, maxVal
}

func prefixesForValueIntersectingQuery(value, queryMin, queryMax int64) []string {
	valueBin := fmt.Sprintf("%0*b", BitLength, value)
	prefixes := make([]string, 0, BitLength+1)
	for prefixLen := 0; prefixLen <= BitLength; prefixLen++ {
		prefix := valueBin[:prefixLen]
		minVal, maxVal := prefixNodeBounds(prefix)
		if maxVal < queryMin || minVal > queryMax {
			continue
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes
}

func buildNDPrefixOccupancyIndex(points []Point, query RangeQuery, maxParentDim int) EmptyIndexND {
	workers := effectiveWorkers(len(points))
	if workers <= 1 {
		return buildNDPrefixOccupancyIndexSerial(points, query, maxParentDim)
	}

	shards := make([]EmptyIndexND, workers)
	if err := parallelFor(workers, func(worker int) error {
		start := worker * len(points) / workers
		end := (worker + 1) * len(points) / workers
		shards[worker] = buildNDPrefixOccupancyIndexSerial(points[start:end], query, maxParentDim)
		return nil
	}); err != nil {
		panic(err)
	}

	if maxParentDim < 1 || maxParentDim > NumDims {
		maxParentDim = NumDims
	}
	levels := make([]map[string]map[int64]struct{}, NumDims-1)
	for i := range levels {
		levels[i] = make(map[string]map[int64]struct{})
	}
	for _, shard := range shards {
		for levelIdx := range levels {
			mergeOccupiedIndex(levels[levelIdx], shard.Levels[levelIdx])
		}
	}
	return EmptyIndexND{Levels: levels}
}

func buildNDPrefixOccupancyIndexSerial(points []Point, query RangeQuery, maxParentDim int) EmptyIndexND {
	if maxParentDim < 1 || maxParentDim > NumDims {
		maxParentDim = NumDims
	}
	levels := make([]map[string]map[int64]struct{}, NumDims-1)
	for i := range levels {
		levels[i] = make(map[string]map[int64]struct{})
	}
	for _, point := range points {
		prefixOptions := make([][]string, NumDims)
		for d := 0; d < NumDims; d++ {
			prefixOptions[d] = prefixesForValueIntersectingQuery(point.Coords[d], query.Bounds[d][0], query.Bounds[d][1])
		}

		for nextDim := 1; nextDim < NumDims && nextDim < maxParentDim; nextDim++ {
			if len(prefixOptions[nextDim-1]) == 0 {
				continue
			}
			parentPrefixes := make([]string, nextDim)
			var walk func(dim int)
			walk = func(dim int) {
				if dim == nextDim {
					key := parentCacheKey(nextDim, parentPrefixes)
					addOccupiedValue(levels[nextDim-1], key, point.Coords[nextDim])
					return
				}
				if len(prefixOptions[dim]) == 0 {
					return
				}
				for _, prefix := range prefixOptions[dim] {
					parentPrefixes[dim] = prefix
					walk(dim + 1)
				}
			}
			walk(0)
		}
	}

	return EmptyIndexND{Levels: levels}
}

func (index *EmptyIndexND) occupiedValues(parentPrefixes []string, nextDim int) map[int64]struct{} {
	if nextDim <= 0 || nextDim > len(index.Levels) {
		return nil
	}
	return index.Levels[nextDim-1][parentCacheKey(nextDim, parentPrefixes)]
}

func totalIndexedParentNodes(index EmptyIndexND) int {
	total := 0
	for _, level := range index.Levels {
		total += len(level)
	}
	return total
}

func emptyCoversForBounds(minVal, maxVal int64, occupied map[int64]struct{}) []string {
	values := make([]int64, 0, len(occupied))
	for value := range occupied {
		if value >= minVal && value <= maxVal {
			values = append(values, value)
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })

	maxDomain := int64(math.Pow(2, BitLength)) - 1
	gapStart := minVal
	var covers []string
	for _, value := range values {
		if value < gapStart {
			continue
		}
		if gapStart <= value-1 {
			covers = append(covers, getCanonicalCover(gapStart, value-1, 0, maxDomain, "")...)
		}
		if value+1 > gapStart {
			gapStart = value + 1
		}
	}
	if gapStart <= maxVal {
		covers = append(covers, getCanonicalCover(gapStart, maxVal, 0, maxDomain, "")...)
	}
	return covers
}

func collectIntersectingPrefixNodes(minQuery, maxQuery int64) []PrefixNode {
	maxDomain := int64(math.Pow(2, BitLength)) - 1
	var nodes []PrefixNode

	var walk func(prefix string, minVal, maxVal int64)
	walk = func(prefix string, minVal, maxVal int64) {
		if maxVal < minQuery || minVal > maxQuery {
			return
		}
		nodes = append(nodes, PrefixNode{Prefix: prefix, Min: minVal, Max: maxVal})
		if len(prefix) == BitLength {
			return
		}
		mid := minVal + (maxVal-minVal)/2
		walk(prefix+"0", minVal, mid)
		walk(prefix+"1", mid+1, maxVal)
	}

	walk("", 0, maxDomain)
	return nodes
}

func hasOccupiedValueInBounds(occupied map[int64]struct{}, minVal, maxVal int64) bool {
	for value := range occupied {
		if value >= minVal && value <= maxVal {
			return true
		}
	}
	return false
}

func buildPatternFromPrefixes(prefixes []string) string {
	joined := strings.Join(prefixes, "||")
	return FormatToWildcardPattern(joined, NumDims, BitLength)
}

func buildQueryTouchedGlobalEmptyRegionsND(
	query RangeQuery,
	index *EmptyIndexND,
	maxGlobalRegions int,
	maxParentDim int,
) []GlobalEmptyRegion {
	nodesByDim := make([][]PrefixNode, NumDims)
	for d := 0; d < NumDims; d++ {
		nodesByDim[d] = collectIntersectingPrefixNodes(query.Bounds[d][0], query.Bounds[d][1])
	}

	localPatterns := make([][]string, len(nodesByDim[0]))
	var stopFlag int32
	err := parallelFor(len(nodesByDim[0]), func(firstIdx int) error {
		if atomic.LoadInt32(&stopFlag) != 0 {
			return nil
		}

		patterns := make([]string, 0)
		var localStop bool
		var recurse func(nextDim int, parentPrefixes []string)
		recurse = func(nextDim int, parentPrefixes []string) {
			if localStop || atomic.LoadInt32(&stopFlag) != 0 || nextDim >= NumDims {
				return
			}

			occupied := index.occupiedValues(parentPrefixes, nextDim)
			for _, emptyPrefix := range emptyCoversForBounds(query.Bounds[nextDim][0], query.Bounds[nextDim][1], occupied) {
				prefixes := make([]string, NumDims)
				copy(prefixes, parentPrefixes)
				prefixes[nextDim] = emptyPrefix
				patterns = append(patterns, buildPatternFromPrefixes(prefixes))
				if len(patterns)%4096 == 0 {
					patterns = selectMaximalPatterns(patterns)
				}
				if maxGlobalRegions > 0 && len(patterns) > maxGlobalRegions {
					patterns = selectMaximalPatterns(patterns)
					if len(patterns) > maxGlobalRegions {
						localStop = true
						atomic.StoreInt32(&stopFlag, 1)
						return
					}
				}
			}

			if nextDim+1 >= NumDims || nextDim+1 >= maxParentDim {
				return
			}
			for _, node := range nodesByDim[nextDim] {
				if !hasOccupiedValueInBounds(occupied, node.Min, node.Max) {
					continue
				}
				childPrefixes := append(append([]string{}, parentPrefixes...), node.Prefix)
				recurse(nextDim+1, childPrefixes)
				if localStop || atomic.LoadInt32(&stopFlag) != 0 {
					return
				}
			}
		}

		firstNode := nodesByDim[0][firstIdx]
		recurse(1, []string{firstNode.Prefix})
		localPatterns[firstIdx] = selectMaximalPatterns(patterns)
		return nil
	})
	if err != nil {
		panic(err)
	}
	if atomic.LoadInt32(&stopFlag) != 0 {
		panic(fmt.Sprintf("database-wide global empty region generation exceeded -max-global-regions=%d; lower -limit, raise the cap, or set it to 0", maxGlobalRegions))
	}

	patterns := make([]string, 0)
	for _, local := range localPatterns {
		patterns = append(patterns, local...)
	}
	patterns = selectMaximalPatterns(patterns)
	if maxGlobalRegions > 0 && len(patterns) > maxGlobalRegions {
		panic(fmt.Sprintf("database-wide global empty region generation exceeded -max-global-regions=%d; lower -limit, raise the cap, or set it to 0", maxGlobalRegions))
	}
	regions := make([]GlobalEmptyRegion, 0, len(patterns))
	for _, pattern := range patterns {
		regions = append(regions, GlobalEmptyRegion{Pattern: pattern})
	}
	return regions
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
	localScoped := make([][]string, len(global))
	if err := parallelFor(len(global), func(i int) error {
		region := global[i]
		children, ok, err := intersectPatternWithQuery(region.Pattern, query)
		if err != nil {
			return err
		}
		if ok {
			localScoped[i] = children
		}
		return nil
	}); err != nil {
		return nil, err
	}

	var scoped []string
	for _, local := range localScoped {
		scoped = append(scoped, local...)
	}
	return selectMaximalPatterns(scoped), nil
}

func deriveQueryScopedEmptyKeysFromGlobal(
	params *wkdibe.Params,
	msk *wkdibe.MasterKey,
	global []GlobalEmptyRegion,
	scopedPatterns []string,
) ([]DerivedPatternKey, int, error) {
	parentForScoped := make([]string, len(scopedPatterns))
	if err := parallelFor(len(scopedPatterns), func(i int) error {
		pattern := scopedPatterns[i]
		for _, region := range global {
			if patternContainsPattern(region.Pattern, pattern) {
				parentForScoped[i] = region.Pattern
				return nil
			}
		}
		return fmt.Errorf("could not find global empty parent for query-scoped pattern %s", pattern)
	}); err != nil {
		return nil, 0, err
	}

	parentSeen := make(map[string]int)
	uniqueParents := make([]string, 0)
	childrenByParent := make([][]int, 0)
	for idx, parentPattern := range parentForScoped {
		parentIdx, ok := parentSeen[parentPattern]
		if !ok {
			parentIdx = len(uniqueParents)
			parentSeen[parentPattern] = parentIdx
			uniqueParents = append(uniqueParents, parentPattern)
			childrenByParent = append(childrenByParent, nil)
		}
		childrenByParent[parentIdx] = append(childrenByParent[parentIdx], idx)
	}

	parentKeys := make([]DerivedPatternKey, len(uniqueParents))
	if err := parallelFor(len(uniqueParents), func(i int) error {
		parentKey, err := derivePatternKeyFromRoot(params, msk, uniqueParents[i], nil)
		if err != nil {
			return err
		}
		parentKeys[i] = parentKey
		return nil
	}); err != nil {
		return nil, 0, err
	}

	scopedKeys := make([]DerivedPatternKey, len(scopedPatterns))
	if err := parallelFor(len(uniqueParents), func(parentIdx int) error {
		parentKey := parentKeys[parentIdx]
		for _, childIdx := range childrenByParent[parentIdx] {
			childKey, err := derivePatternKeyFromParent(params, parentKey, scopedPatterns[childIdx], nil)
			if err != nil {
				return err
			}
			scopedKeys[childIdx] = childKey
		}
		return nil
	}); err != nil {
		return nil, 0, err
	}

	return scopedKeys, sumMarshalledKeyBytes(parentKeys), nil
}

func deriveGlobalEmptyParentKeysOffline(
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

func deriveQueryScopedKeysFromOfflineParents(
	params *wkdibe.Params,
	global []GlobalEmptyRegion,
	parentKeys map[string]DerivedPatternKey,
	scopedPatterns []string,
) ([]DerivedPatternKey, int, error) {
	keys := make([]DerivedPatternKey, len(scopedPatterns))
	touched := make(map[string]struct{})
	for idx, pattern := range scopedPatterns {
		parentPattern := ""
		for _, region := range global {
			if patternContainsPattern(region.Pattern, pattern) {
				parentPattern = region.Pattern
				break
			}
		}
		if parentPattern == "" {
			return nil, 0, fmt.Errorf("no offline parent contains query-scoped pattern %s", pattern)
		}
		parentKey, ok := parentKeys[parentPattern]
		if !ok {
			return nil, 0, fmt.Errorf("offline parent key missing for %s", parentPattern)
		}
		childKey, err := derivePatternKeyFromParent(params, parentKey, pattern, nil)
		if err != nil {
			return nil, 0, err
		}
		keys[idx] = childKey
		touched[parentPattern] = struct{}{}
	}
	touchedBytes := 0
	for pattern := range touched {
		touchedBytes += len(parentKeys[pattern].Key.Marshal(true))
	}
	return keys, touchedBytes, nil
}

func offlineParentKeysInRegionOrder(
	regions []GlobalEmptyRegion,
	parentKeys map[string]DerivedPatternKey,
) ([]DerivedPatternKey, error) {
	keys := make([]DerivedPatternKey, len(regions))
	for idx, region := range regions {
		key, ok := parentKeys[region.Pattern]
		if !ok {
			return nil, fmt.Errorf("offline parent key missing for region %d", idx)
		}
		keys[idx] = key
	}
	return keys, nil
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

	keep := make([]bool, len(unique))
	if err := parallelFor(len(unique), func(i int) error {
		candidate := unique[i]
		candidateStars := starCounts[i]
		for j := 0; j < i && starCounts[j] > candidateStars; j++ {
			if patternContainsPattern(unique[j], candidate) {
				return nil
			}
		}
		keep[i] = true
		return nil
	}); err != nil {
		panic(err)
	}

	maximal := make([]string, 0, len(unique))
	for i, candidate := range unique {
		if keep[i] {
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
	candidateSlots := make([]CoverCandidate, len(patterns))
	keep := make([]bool, len(patterns))

	if err := parallelFor(len(patterns), func(idx int) error {
		pattern := patterns[idx]
		bounds, err := patternToBounds(pattern)
		if err != nil {
			return fmt.Errorf("candidate pattern %d malformed: %w", idx, err)
		}
		if !boundsInsideQuery(bounds, query) {
			return fmt.Errorf("candidate pattern %d escapes query bounds: %s", idx, pattern)
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
			return err
		}

		if !isBitsetZero(coverage) {
			candidateSlots[idx] = CoverCandidate{
				Pattern:  pattern,
				Coverage: coverage,
			}
			keep[idx] = true
		}
		return nil
	}); err != nil {
		return nil, 0, err
	}

	for idx := range candidateSlots {
		if keep[idx] {
			candidates = append(candidates, candidateSlots[idx])
		}
	}

	return candidates, emptyPointCount, nil
}

type coverHeapItem struct {
	idx  int
	gain int
}

type coverMaxHeap []coverHeapItem

func (h coverMaxHeap) Len() int { return len(h) }
func (h coverMaxHeap) Less(i, j int) bool {
	if h[i].gain != h[j].gain {
		return h[i].gain > h[j].gain
	}
	return h[i].idx < h[j].idx
}
func (h coverMaxHeap) Swap(i, j int) { h[i], h[j] = h[j], h[i] }
func (h *coverMaxHeap) Push(x interface{}) {
	*h = append(*h, x.(coverHeapItem))
}
func (h *coverMaxHeap) Pop() interface{} {
	old := *h
	n := len(old)
	item := old[n-1]
	*h = old[:n-1]
	return item
}

func greedySetCover(candidates []CoverCandidate, emptyPointCount int) ([]CoverCandidate, error) {
	if emptyPointCount == 0 {
		return nil, nil
	}

	pointToCandidates := make([][]int, emptyPointCount)
	gains := make([]int, len(candidates))
	selectedCandidate := make([]bool, len(candidates))

	pq := make(coverMaxHeap, 0, len(candidates))
	for idx, candidate := range candidates {
		gain := 0
		forEachSetBit(candidate.Coverage, func(bit int) bool {
			if bit >= emptyPointCount {
				return false
			}
			pointToCandidates[bit] = append(pointToCandidates[bit], idx)
			gain++
			return false
		})
		gains[idx] = gain
		if gain > 0 {
			pq = append(pq, coverHeapItem{idx: idx, gain: gain})
		}
	}
	heap.Init(&pq)

	covered := make([]bool, emptyPointCount)
	coveredCount := 0
	selectedIdx := make([]int, 0)

	for coveredCount < emptyPointCount {
		bestIdx := -1
		bestGain := 0
		for pq.Len() > 0 {
			item := heap.Pop(&pq).(coverHeapItem)
			if selectedCandidate[item.idx] || item.gain != gains[item.idx] {
				continue
			}
			bestIdx = item.idx
			bestGain = item.gain
			break
		}
		if bestIdx == -1 || bestGain == 0 {
			return nil, errors.New("greedy set cover stalled before covering all empty points")
		}

		selectedCandidate[bestIdx] = true
		selectedIdx = append(selectedIdx, bestIdx)

		newlyCovered := make([]int, 0, bestGain)
		forEachSetBit(candidates[bestIdx].Coverage, func(bit int) bool {
			if bit >= emptyPointCount || covered[bit] {
				return false
			}
			covered[bit] = true
			coveredCount++
			newlyCovered = append(newlyCovered, bit)
			return false
		})

		for _, bit := range newlyCovered {
			for _, candidateIdx := range pointToCandidates[bit] {
				if selectedCandidate[candidateIdx] || gains[candidateIdx] == 0 {
					continue
				}
				gains[candidateIdx]--
				heap.Push(&pq, coverHeapItem{idx: candidateIdx, gain: gains[candidateIdx]})
			}
		}
	}

	coverCounts := make([]int, emptyPointCount)
	for _, idx := range selectedIdx {
		forEachSetBit(candidates[idx].Coverage, func(bit int) bool {
			if bit < emptyPointCount {
				coverCounts[bit]++
			}
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
				return bit < emptyPointCount && coverCounts[bit] == 1
			})
			if essential {
				continue
			}

			keep[pos] = false
			changed = true
			forEachSetBit(candidates[idx].Coverage, func(bit int) bool {
				if bit < emptyPointCount {
					coverCounts[bit]--
				}
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
	keys := make([]DerivedPatternKey, len(initialPatterns))
	if err := parallelFor(len(initialPatterns), func(i int) error {
		derived, err := derivePatternKeyFromRoot(params, msk, initialPatterns[i], bitOrder)
		if err != nil {
			return err
		}
		keys[i] = derived
		return nil
	}); err != nil {
		return nil, err
	}
	return keys, nil
}

func deriveEmptyPatternKeys(
	params *wkdibe.Params,
	initialKeys []DerivedPatternKey,
	emptyPatterns []string,
	bitOrder []int,
) ([]DerivedPatternKey, error) {
	derived := make([]DerivedPatternKey, len(emptyPatterns))

	if err := parallelFor(len(emptyPatterns), func(i int) error {
		pattern := emptyPatterns[i]
		parentIdx := -1
		for idx, initialKey := range initialKeys {
			if patternContainsPattern(initialKey.Pattern, pattern) {
				parentIdx = idx
				break
			}
		}
		if parentIdx == -1 {
			return fmt.Errorf("could not find canonical-cover parent for empty pattern %s", pattern)
		}

		key, err := derivePatternKeyFromParent(params, initialKeys[parentIdx], pattern, bitOrder)
		if err != nil {
			return err
		}
		derived[i] = key
		return nil
	}); err != nil {
		return nil, err
	}

	return derived, nil
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

func queryPointIndex(query RangeQuery, p Point) (int, bool) {
	var idx int64
	for d := 0; d < NumDims; d++ {
		minVal := query.Bounds[d][0]
		maxVal := query.Bounds[d][1]
		if p.Coords[d] < minVal || p.Coords[d] > maxVal {
			return 0, false
		}

		width := maxVal - minVal + 1
		idx = idx*width + (p.Coords[d] - minVal)
	}
	if idx > int64(^uint(0)>>1) {
		return 0, false
	}
	return int(idx), true
}

func verifyEmptyRegionPatterns(
	query RangeQuery,
	emptyPatterns []string,
	realPoints map[[NumDims]int64]struct{},
) (int64, int, error) {
	var totalVolume int64 = 1
	for d := 0; d < NumDims; d++ {
		width := query.Bounds[d][1] - query.Bounds[d][0] + 1
		if width <= 0 {
			return 0, 0, fmt.Errorf("invalid query bounds at dimension %d", d)
		}
		totalVolume *= width
		if totalVolume > int64(^uint(0)>>1) {
			return 0, 0, fmt.Errorf("query volume %d is too large for in-memory verifier", totalVolume)
		}
	}

	patternBounds := make([][NumDims][2]int64, len(emptyPatterns))
	for idx, pattern := range emptyPatterns {
		bounds, err := patternToBounds(pattern)
		if err != nil {
			return 0, 0, fmt.Errorf("pattern %d malformed: %w", idx, err)
		}
		if !boundsInsideQuery(bounds, query) {
			return 0, 0, fmt.Errorf("pattern %d escapes query bounds: %s", idx, pattern)
		}
		patternBounds[idx] = bounds
	}

	coverage := make([]int32, int(totalVolume))
	if err := parallelFor(len(patternBounds), func(idx int) error {
		return forEachPointInBounds(patternBounds[idx], func(p Point) error {
			key := p.Coords
			if _, ok := realPoints[key]; ok {
				return fmt.Errorf("pattern %d incorrectly covers real point %v", idx, key)
			}
			coverageIdx, ok := queryPointIndex(query, p)
			if !ok {
				return fmt.Errorf("pattern %d produced point outside query bounds: %v", idx, key)
			}
			atomic.AddInt32(&coverage[coverageIdx], 1)
			return nil
		})
	}); err != nil {
		return 0, 0, err
	}

	var coveredEmptyPoints int64
	maxMultiplicity := 0
	err := forEachPointInBounds(query.Bounds, func(p Point) error {
		key := p.Coords
		_, isRealPoint := realPoints[key]
		coverageIdx, ok := queryPointIndex(query, p)
		if !ok {
			return fmt.Errorf("query point indexing failed for %v", key)
		}
		hitCount := int(atomic.LoadInt32(&coverage[coverageIdx]))
		if hitCount > maxMultiplicity {
			maxMultiplicity = hitCount
		}

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

	return coveredEmptyPoints, maxMultiplicity, nil
}

// ==========================================
// 终极对决：2D M-HIBE Bi-Sweep + ZK-Accumulator
// ==========================================

func positiveMod(value, mod int64) int64 {
	if mod <= 0 {
		return value
	}
	value %= mod
	if value < 0 {
		value += mod
	}
	return value
}

func clampToDomain(value int64) int64 {
	maxDomain := int64(1<<BitLength) - 1
	if value < 0 {
		return 0
	}
	if value > maxDomain {
		return maxDomain
	}
	return value
}

func parseScaledFloat(value string, scale float64) int64 {
	parsed, _ := strconv.ParseFloat(value, 64)
	return clampToDomain(int64(math.Round(parsed * scale)))
}

func parseLineItemPoint(cols []string, discountScale int64) (Point, bool) {
	var p Point
	if len(cols) < 13 {
		return p, false
	}
	qFloat, _ := strconv.ParseFloat(cols[4], 64)
	priceFloat, _ := strconv.ParseFloat(cols[5], 64)
	orderKey, _ := strconv.ParseInt(cols[0], 10, 64)
	partKey, _ := strconv.ParseInt(cols[1], 10, 64)
	suppKey, _ := strconv.ParseInt(cols[2], 10, 64)
	lineNumber, _ := strconv.ParseInt(cols[3], 10, 64)

	values := []int64{
		ParseDate(cols[10]),
		parseScaledFloat(cols[6], float64(discountScale)),
		clampToDomain(int64(qFloat)),
		parseScaledFloat(cols[7], 100),
		clampToDomain(lineNumber),
		clampToDomain(int64(priceFloat / 1000.0)),
		ParseDate(cols[11]),
		ParseDate(cols[12]),
		positiveMod(partKey, 1<<BitLength),
		positiveMod(suppKey, 1<<BitLength),
		positiveMod(orderKey, 1<<BitLength),
	}
	for d := 0; d < NumDims; d++ {
		if d < len(values) {
			p.Coords[d] = values[d]
		} else {
			p.Coords[d] = positiveMod(values[len(values)-1]+int64(97*d), 1<<BitLength)
		}
	}
	return p, true
}

func pointInBaseQuery(p Point, dateMin, dateMax, discountMin, discountMax, quantityMin, quantityMax int64) bool {
	if p.Coords[0] < dateMin || p.Coords[0] > dateMax {
		return false
	}
	if NumDims > 1 && (p.Coords[1] < discountMin || p.Coords[1] > discountMax) {
		return false
	}
	if NumDims > 2 && (p.Coords[2] < quantityMin || p.Coords[2] > quantityMax) {
		return false
	}
	return true
}

func buildDefaultQuery(points []Point, dateMin, dateMax, discountMin, discountMax, quantityMin, quantityMax, extraWidth int64) RangeQuery {
	var query RangeQuery
	maxDomain := int64(1<<BitLength) - 1
	for d := 0; d < NumDims; d++ {
		query.Bounds[d] = [2]int64{0, maxDomain}
	}
	query.Bounds[0] = [2]int64{dateMin, dateMax}
	if NumDims > 1 {
		query.Bounds[1] = [2]int64{discountMin, discountMax}
	}
	if NumDims > 2 {
		query.Bounds[2] = [2]int64{quantityMin, quantityMax}
	}

	var exemplar *Point
	for i := range points {
		if pointInBaseQuery(points[i], dateMin, dateMax, discountMin, discountMax, quantityMin, quantityMax) {
			exemplar = &points[i]
			break
		}
	}
	if exemplar == nil && len(points) > 0 {
		exemplar = &points[0]
	}
	if exemplar != nil {
		for d := 3; d < NumDims; d++ {
			lo := exemplar.Coords[d] - extraWidth
			hi := exemplar.Coords[d] + extraWidth
			if lo < 0 {
				lo = 0
			}
			if hi > maxDomain {
				hi = maxDomain
			}
			query.Bounds[d] = [2]int64{lo, hi}
		}
	}
	return query
}

func printQueryBounds(query RangeQuery) {
	for d := 0; d < NumDims; d++ {
		fmt.Printf("    dim%d [%d, %d]\n", d, query.Bounds[d][0], query.Bounds[d][1])
	}
}

func main() {
	uploadKeys := flag.Bool("upload-keys", false, "materialize WKD-IBE keys for every database row before benchmarking")
	skipZK := flag.Bool("skip-zk", false, "skip ZK accumulator proof generation and verification")
	dataPath := flag.String("data", "/home/xing/poneglyphdb/src/data/lineitem_120K.tbl", "TPC-H lineitem .tbl file")
	limit := flag.Int("limit", 5000, "maximum number of lineitem rows to load; 0 means all rows")
	poneglyphQ6 := flag.Bool("poneglyph-q6", false, "use PoneglyphDB-compatible 3D range bounds: shipdate [1994-01-01, 1994-12-31], discount [0.05, 0.07], quantity [0, 23]")
	dateMin := flag.String("date-min", "1994-01-01", "inclusive shipdate lower bound for this benchmark")
	dateMax := flag.String("date-max", "1994-12-31", "inclusive shipdate upper bound for this benchmark")
	discountScale := flag.Int64("discount-scale", 100, "scale factor for encoding l_discount from the .tbl file")
	discountMin := flag.Int64("discount-min", 5, "inclusive encoded l_discount lower bound")
	discountMax := flag.Int64("discount-max", 7, "inclusive encoded l_discount upper bound")
	quantityMin := flag.Int64("quantity-min", 0, "inclusive l_quantity lower bound")
	quantityMax := flag.Int64("quantity-max", 23, "inclusive l_quantity upper bound")
	taxMin := flag.Int64("tax-min", 2, "inclusive encoded l_tax lower bound for dim3; l_tax is scaled by 100")
	taxMax := flag.Int64("tax-max", 6, "inclusive encoded l_tax upper bound for dim3; l_tax is scaled by 100")
	lineNumberMin := flag.Int64("line-number-min", 1, "inclusive l_linenumber lower bound for dim4")
	lineNumberMax := flag.Int64("line-number-max", 4, "inclusive l_linenumber upper bound for dim4")
	extraWidth := flag.Int64("extra-width", 0, "half-width for automatically anchored dimensions 5 and above")
	maxGlobalRegions := flag.Int("max-global-regions", 200000, "abort if database-wide global empty region generation exceeds this cap; 0 disables the cap")
	maxParentDim := flag.Int("max-parent-dim", NumDims, "maximum dimension depth for parent recursion; NumDims means exact full-depth generation")
	workers := flag.Int("mhibe-workers", runtime.NumCPU(), "number of workers for parallel extraction, M-HIBE proving, and client verification")
	flag.Parse()
	mhibeWorkers = *workers
	if mhibeWorkers < 1 {
		mhibeWorkers = 1
	}
	runtime.GOMAXPROCS(mhibeWorkers)

	if *poneglyphQ6 {
		// Equivalent to the PoneglyphDB circuit bounds:
		// 1993-12-31 < shipdate < 1995-01-01, 0.04 < discount < 0.08,
		// and quantity < 24. This benchmark uses closed integer ranges.
		*dateMin = "1994-01-01"
		*dateMax = "1994-12-31"
		*discountMin = int64(math.Round(0.05 * float64(*discountScale)))
		*discountMax = int64(math.Round(0.07 * float64(*discountScale)))
		*quantityMin = 0
		*quantityMax = 23
	}

	fmt.Println("[*] Starting ULTIMATE ARCHITECTURE Benchmark...")
	fmt.Println("[*] Mode: 10D Query-Independent Offline Fixed-Order Parent Supplement Protocol")
	fmt.Printf("[*] Full Parallel Workers: %d\n", mhibeWorkers)

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
	// 1. ?????????
	file, err := os.Open(*dataPath)
	if err != nil {
		panic(err)
	}
	defer file.Close()

	var dbData []Point
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if *limit > 0 && len(dbData) >= *limit {
			break
		}
		line := scanner.Text()
		cols := strings.Split(line, "|")
		p, ok := parseLineItemPoint(cols, *discountScale)
		if !ok {
			continue
		}
		dbData = append(dbData, p)
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}

	query := buildDefaultQuery(
		dbData,
		ParseDate(*dateMin), ParseDate(*dateMax),
		*discountMin, *discountMax,
		*quantityMin, *quantityMax,
		*extraWidth,
	)
	if NumDims > 3 {
		query.Bounds[3] = [2]int64{*taxMin, *taxMax}
	}
	if NumDims > 4 {
		query.Bounds[4] = [2]int64{*lineNumberMin, *lineNumberMax}
	}

	var dbFr []mcl.Fr
	var I []mcl.Fr
	var X []mcl.Fr
	queryUniquePoints := make(map[[NumDims]int64]struct{})
	for _, p := range dbData {
		fr := bpacc.SeedToFr(FormatPointToBinary(p))
		dbFr = append(dbFr, fr)
		if IsPointInQuery(p, query) {
			I = append(I, fr)
			queryUniquePoints[p.Coords] = struct{}{}
		} else {
			X = append(X, fr)
		}
	}

	fmt.Printf("[*] Data Path: %s\n", *dataPath)
	if *limit > 0 {
		fmt.Printf("[*] Row Limit: first %d lineitem rows\n", *limit)
	}
	fmt.Printf("[*] Query Bounds (%dD encoded coordinates):\n", NumDims)
	printQueryBounds(query)
	fmt.Printf("[*] Loaded %d real TPC-H records.\n", len(dbData))
	fmt.Printf("[*] Query matched %d real records.\n", len(I))

	fmt.Println("\n=== QUERY-INDEPENDENT DATABASE OFFLINE INITIALIZATION ===")
	offlineStart := time.Now()
	offlineDomain := fullDomainQuery()
	emptyIndexStart := time.Now()
	databaseEmptyIndex := buildNDPrefixOccupancyIndex(dbData, offlineDomain, *maxParentDim)
	emptyIndexMs := float64(time.Since(emptyIndexStart).Nanoseconds()) / 1e6

	globalRegionStart := time.Now()
	globalEmptyRegions := buildQueryTouchedGlobalEmptyRegionsND(offlineDomain, &databaseEmptyIndex, *maxGlobalRegions, *maxParentDim)
	globalRegionMs := float64(time.Since(globalRegionStart).Nanoseconds()) / 1e6

	globalParentStart := time.Now()
	globalParentKeys, globalParentKeyBytes, err := deriveGlobalEmptyParentKeysOffline(params, masterKey, globalEmptyRegions)
	if err != nil {
		panic(err)
	}
	globalParentKeyMs := float64(time.Since(globalParentStart).Nanoseconds()) / 1e6
	offlineInitMs := float64(time.Since(offlineStart).Nanoseconds()) / 1e6
	offlineMaterial := OfflineEmptyMaterial{Regions: globalEmptyRegions, ParentKeys: globalParentKeys, ParentKeyBytes: globalParentKeyBytes}

	fmt.Printf("[+] Database Empty Index Build Time: %.2f ms\n", emptyIndexMs)
	fmt.Printf("[+] Database-Wide Empty Region Enumeration Time: %.2f ms\n", globalRegionMs)
	fmt.Printf("[+] Database-Wide Parent Key Generation Time: %.2f ms\n", globalParentKeyMs)
	fmt.Printf("[+] Offline Initialization Total: %.2f ms\n", offlineInitMs)
	fmt.Printf("[+] Empty Index Mode: complete-domain fixed-order parent occupancy\n")
	fmt.Printf("[+] Indexed Database-Wide Parent Nodes: %d\n", totalIndexedParentNodes(databaseEmptyIndex))
	fmt.Printf("[+] Database-Wide Global Empty Parent Regions: %d\n", len(globalEmptyRegions))
	fmt.Printf("[+] Database-Wide Parent Key Material: %.2f KB\n", float64(globalParentKeyBytes)/1024.0)
	fmt.Println("[+] Query Dependency: NONE (offline domain is fixed to the complete encoded space)")

	if *uploadKeys {
		// ========================================================
		// UPLOAD STAGE: full database key materialization
		// ========================================================
		fmt.Println("\n=== UPLOAD STAGE: FULL DATABASE KEY GENERATION ===")
		uploadStart := time.Now()
		_, uploadKeyBytes, err := materializeDatabasePointKeys(params, masterKey, dbData)
		if err != nil {
			panic(err)
		}
		uploadMs := float64(time.Since(uploadStart).Nanoseconds()) / 1e6
		fmt.Printf("[+] Upload Key Materialization Time: %.2f ms\n", uploadMs)
		fmt.Printf("[+] Upload Key Material: %.2f KB\n", float64(uploadKeyBytes)/1024.0)
	} else {
		fmt.Println("\n=== UPLOAD STAGE: SKIPPED ===")
		fmt.Println("[*] Use -upload-keys to materialize WKD-IBE keys for every database row.")
	}

	// ========================================================
	// ENGINE A: 2D M-HIBE BI-SWEEP (绝对零知识边界)
	// ========================================================
	fmt.Println("\n=== ENGINE A: 10D M-HIBE FIXED-ORDER PARENT SUPPLEMENT (Confidentiality & Access Control) ===")
	extractionStart := time.Now()

	initialPrefixes := MapToIDs(query)
	var initialPatterns []string
	for _, p := range initialPrefixes {
		initialPatterns = append(initialPatterns, FormatToWildcardPattern(p, NumDims, BitLength))
	}

	fmt.Println("    [Trace] Starting query intersection/maximal crop...")
	stepStart := time.Now()
	selectedCoverPatterns, err := queryScopedEmptyPatternsFromGlobal(offlineMaterial.Regions, query)
	if err != nil {
		panic(err)
	}
	fmt.Printf("    [Trace] Query intersection/maximal crop: %.2f ms (%d scoped candidates)\n", float64(time.Since(stepStart).Nanoseconds())/1e6, len(selectedCoverPatterns))

	fmt.Println("    [Trace] Starting candidate bitset construction...")
	stepStart = time.Now()
	coverCandidates, emptyPointCount, err := buildCoverCandidates(selectedCoverPatterns, query, queryUniquePoints)
	if err != nil {
		panic(err)
	}
	fmt.Printf("    [Trace] Candidate bitset construction: %.2f ms (%d candidates, %d empty points)\n", float64(time.Since(stepStart).Nanoseconds())/1e6, len(coverCandidates), emptyPointCount)

	fmt.Println("    [Trace] Starting incremental greedy cover...")
	stepStart = time.Now()
	selectedCandidates, err := greedySetCover(coverCandidates, emptyPointCount)
	if err != nil {
		panic(err)
	}
	fmt.Printf("    [Trace] Incremental greedy cover: %.2f ms (%d selected)\n", float64(time.Since(stepStart).Nanoseconds())/1e6, len(selectedCandidates))
	selectedCoverPatterns = make([]string, 0, len(selectedCandidates))
	for _, candidate := range selectedCandidates {
		selectedCoverPatterns = append(selectedCoverPatterns, candidate.Pattern)
	}
	extractionMs := float64(time.Since(extractionStart).Nanoseconds()) / 1e6

	cryptoStart := time.Now()
	queryRangeKeys, err := deriveInitialPatternKeys(params, masterKey, initialPatterns, nil)
	if err != nil {
		panic(err)
	}
	queryRangeKeyBytes := sumMarshalledKeyBytes(queryRangeKeys)
	verificationEmptyKeys, touchedGlobalParentKeyBytes, err := deriveQueryScopedKeysFromOfflineParents(params, offlineMaterial.Regions, offlineMaterial.ParentKeys, selectedCoverPatterns)
	if err != nil {
		panic(err)
	}
	emptyKeyBytes := sumMarshalledKeyBytes(verificationEmptyKeys)
	mhibeCryptoMs := float64(time.Since(cryptoStart).Nanoseconds()) / 1e6
	engineAMs := extractionMs + mhibeCryptoMs

	fmt.Printf("1. Query Canonical Range Keys: %d\n", len(queryRangeKeys))
	fmt.Printf("2. Database-Wide Global Empty Parent Regions Available: %d\n", len(offlineMaterial.Regions))
	fmt.Printf("3. Query-Scoped Empty Regions: %d\n", len(verificationEmptyKeys))
	fmt.Printf("4. Cover Strategy: query-independent database-wide parents + optimized serial online intersection/delegation\n")
	fmt.Printf("5. Prefix Extraction Time: %.2f ms\n", extractionMs)
	fmt.Printf("6. Query-Range Key Material: %.2f KB\n", float64(queryRangeKeyBytes)/1024.0)
	fmt.Printf("7. Global Empty Parent Key Material Total: %.2f KB\n", float64(offlineMaterial.ParentKeyBytes)/1024.0)
	fmt.Printf("8. Global Empty Parent Key Material Touched: %.2f KB\n", float64(touchedGlobalParentKeyBytes)/1024.0)
	fmt.Printf("9. Query-Scoped Empty Key Material: %.2f KB\n", float64(emptyKeyBytes)/1024.0)
	fmt.Printf("10. WKD-IBE Delegation Time: %.2f ms\n", mhibeCryptoMs)
	fmt.Printf("-> Engine A Total: %.2f ms\n", engineAMs)
	// ========================================================
	// CLIENT ENGINE A: COMPLETENESS VERIFIER (精准完备性校验)
	// ========================================================
	fmt.Println("\n=== ENGINE A: CLIENT PROTOCOL COMPLETENESS CHECK ===")

	// 1. 计算原始查询框的总容量
	var totalQueryVolume int64 = 0
	for _, p := range initialPatterns {
		totalQueryVolume += calculateVolume(p)
	}

	// 2. 客户端严格验证最终 selected cover 输出的空区域 key：
	//    - 每个 key 必须完全位于查询框内
	//    - 不能覆盖任何真实命中点
	//    - 所有查询内缺失点必须至少被 1 个 key 覆盖
	geometryStart := time.Now()
	coveredEmptyPoints, maxOverlap, verifyErr := verifyEmptyRegionPatterns(query, selectedCoverPatterns, queryUniquePoints)
	geometryMs := float64(time.Since(geometryStart).Nanoseconds()) / 1e6

	// 3. 统计真实命中点占据的独特空间点数
	realSpatialVolume := int64(len(queryUniquePoints))
	if verifyErr == nil && coveredEmptyPoints+realSpatialVolume == totalQueryVolume {
		fmt.Printf("[+] Client Protocol Geometric Completeness Time: %.4f ms (SUCCESS! Complete key cover.)\n", geometryMs)
		fmt.Printf("    -> [Detail] %d matching rows collapsed into %d unique spatial points.\n", len(I), realSpatialVolume)
		fmt.Printf("    -> [Detail] %d empty-region keys cover %d empty spatial points.\n", len(verificationEmptyKeys), coveredEmptyPoints)
		fmt.Printf("    -> [Detail] Maximum overlap multiplicity among selected cover blocks: %d.\n", maxOverlap)
	} else {
		if verifyErr != nil {
			fmt.Printf("[-] Client Empty-Key Check: FAILED! (%v)\n", verifyErr)
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
	fmt.Printf("Architecture: 10D Query-Independent Offline M-HIBE + Optimized Serial Protocol + ZK-Accumulator\n")
	totalSetupMs := setupMs + offlineInitMs + zkCommitMs
	totalServerMs := engineAMs + zkProverMs
	totalClientProtocolMs := geometryMs + zkVerifierMs
	fmt.Printf("Total Setup Time: %.2f ms\n", totalSetupMs)
	fmt.Printf("Total Server Proving Time: %.2f ms (%.2f s)\n", totalServerMs, totalServerMs/1000.0)
	fmt.Printf("Total Client Protocol Verification Time: %.2f ms\n", totalClientProtocolMs)
	fmt.Printf("Total Protocol Time: %.2f ms\n", totalSetupMs+totalServerMs+totalClientProtocolMs)
}
