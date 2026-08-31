package mhibe_test

import (
	"errors"
	"fmt"
	"math"
	"math/bits"
	"os"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

const (
	dryRunNumDims   = 3
	dryRunBitLength = 12
)

type dryRunPoint struct {
	Coords [dryRunNumDims]int64
}

type dryRunRangeQuery struct {
	Bounds [dryRunNumDims][2]int64
}

type dryRunPrefixNode struct {
	Prefix string
	Min    int64
	Max    int64
}

type dryRunEmptyIndex3D struct {
	XToY  map[string]map[int64]struct{}
	XYToZ map[string]map[int64]struct{}
}

type dryRunGlobalEmptyRegion struct {
	Pattern string
}

type dryRunCoverCandidate struct {
	Pattern  string
	Coverage []uint64
}

type dryRunOrderEstimate struct {
	Name                  string
	Order                 [dryRunNumDims]int
	GlobalParentRegions   int
	QueryScopedCandidates int
	SelectedEmptyKeys     int
	EmptyPointCount       int
	MaxOverlap            int
	Elapsed               time.Duration
}

func TestDryRunSelectBestDimensionOrder3D(t *testing.T) {
	if testing.Short() {
		t.Skip("dry-run dimension-order estimation scans the 120K TPC-H fixture")
	}
	if os.Getenv("MHIBE_DRY_RUN_ORDER") != "1" {
		t.Skip("set MHIBE_DRY_RUN_ORDER=1 to run the expensive dry-run dimension-order estimator")
	}

	points, err := dryRunLoadTPCH3D("/home/xing/poneglyphdb/src/data/lineitem_120K.tbl")
	if err != nil {
		t.Fatal(err)
	}

	query := dryRunRangeQuery{}
	query.Bounds[0] = [2]int64{dryRunParseDate("1994-01-01"), dryRunParseDate("1994-12-31")}
	query.Bounds[1] = [2]int64{5, 7}
	query.Bounds[2] = [2]int64{0, 23}

	orders := [][dryRunNumDims]int{
		{0, 1, 2},
		{0, 2, 1},
		{1, 0, 2},
		{1, 2, 0},
		{2, 0, 1},
		{2, 1, 0},
	}

	var estimates []dryRunOrderEstimate
	for _, order := range orders {
		estimate, err := dryRunEstimateOrder(points, query, order)
		if err != nil {
			t.Fatalf("dry-run order %s failed: %v", dryRunOrderName(order), err)
		}
		estimates = append(estimates, estimate)
		t.Logf(
			"order=%s global_parents=%d scoped_candidates=%d selected_empty_keys=%d empty_points=%d max_overlap=%d elapsed=%s",
			estimate.Name,
			estimate.GlobalParentRegions,
			estimate.QueryScopedCandidates,
			estimate.SelectedEmptyKeys,
			estimate.EmptyPointCount,
			estimate.MaxOverlap,
			estimate.Elapsed,
		)
	}

	best := estimates[0]
	for _, estimate := range estimates[1:] {
		if estimate.SelectedEmptyKeys < best.SelectedEmptyKeys ||
			(estimate.SelectedEmptyKeys == best.SelectedEmptyKeys && estimate.GlobalParentRegions < best.GlobalParentRegions) {
			best = estimate
		}
	}

	baseline := estimates[0]
	if best.SelectedEmptyKeys > baseline.SelectedEmptyKeys {
		t.Fatalf("best order %s has %d keys, worse than X->Y->Z baseline %d", best.Name, best.SelectedEmptyKeys, baseline.SelectedEmptyKeys)
	}

	t.Logf(
		"best_order=%s selected_empty_keys=%d global_parents=%d scoped_candidates=%d",
		best.Name,
		best.SelectedEmptyKeys,
		best.GlobalParentRegions,
		best.QueryScopedCandidates,
	)
}

func dryRunEstimateOrder(points []dryRunPoint, query dryRunRangeQuery, order [dryRunNumDims]int) (dryRunOrderEstimate, error) {
	start := time.Now()

	orderedPoints := make([]dryRunPoint, 0, len(points))
	orderedRealPoints := make(map[[dryRunNumDims]int64]struct{})
	for _, point := range points {
		ordered := dryRunReorderPoint(point, order)
		orderedPoints = append(orderedPoints, ordered)
		if dryRunPointInQuery(point, query) {
			orderedRealPoints[ordered.Coords] = struct{}{}
		}
	}
	orderedQuery := dryRunReorderQuery(query, order)

	index := dryRunBuild3DPrefixOccupancyIndex(orderedPoints)
	global := dryRunBuildQueryTouchedGlobalEmptyRegions3D(orderedQuery, index)
	scoped, err := dryRunQueryScopedEmptyPatternsFromGlobal(global, orderedQuery)
	if err != nil {
		return dryRunOrderEstimate{}, err
	}

	candidates, emptyPointCount, err := dryRunBuildCoverCandidates(scoped, orderedQuery, orderedRealPoints)
	if err != nil {
		return dryRunOrderEstimate{}, err
	}
	selected, err := dryRunGreedySetCover(candidates, emptyPointCount)
	if err != nil {
		return dryRunOrderEstimate{}, err
	}

	selectedPatterns := make([]string, 0, len(selected))
	for _, candidate := range selected {
		selectedPatterns = append(selectedPatterns, candidate.Pattern)
	}
	covered, maxOverlap, err := dryRunVerifyEmptyRegionPatterns(orderedQuery, selectedPatterns, orderedRealPoints)
	if err != nil {
		return dryRunOrderEstimate{}, err
	}
	if int(covered) != emptyPointCount {
		return dryRunOrderEstimate{}, fmt.Errorf("covered %d empty points, expected %d", covered, emptyPointCount)
	}

	return dryRunOrderEstimate{
		Name:                  dryRunOrderName(order),
		Order:                 order,
		GlobalParentRegions:   len(global),
		QueryScopedCandidates: len(scoped),
		SelectedEmptyKeys:     len(selected),
		EmptyPointCount:       emptyPointCount,
		MaxOverlap:            maxOverlap,
		Elapsed:               time.Since(start),
	}, nil
}

func dryRunLoadTPCH3D(path string) ([]dryRunPoint, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(data), "\n")
	points := make([]dryRunPoint, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}
		cols := strings.Split(line, "|")
		if len(cols) < 11 {
			continue
		}

		discount, err := strconv.ParseFloat(cols[6], 64)
		if err != nil {
			return nil, fmt.Errorf("parse discount %q: %w", cols[6], err)
		}
		quantity, err := strconv.ParseFloat(cols[4], 64)
		if err != nil {
			return nil, fmt.Errorf("parse quantity %q: %w", cols[4], err)
		}

		points = append(points, dryRunPoint{Coords: [dryRunNumDims]int64{
			dryRunParseDate(cols[10]),
			int64(discount * 100),
			int64(quantity),
		}})
	}
	return points, nil
}

func dryRunParseDate(dateStr string) int64 {
	baseDate, _ := time.Parse("2006-01-02", "1992-01-01")
	targetDate, err := time.Parse("2006-01-02", dateStr)
	if err != nil {
		return 0
	}
	return int64(targetDate.Sub(baseDate).Hours() / 24)
}

func dryRunOrderName(order [dryRunNumDims]int) string {
	names := []string{"X", "Y", "Z"}
	return names[order[0]] + "->" + names[order[1]] + "->" + names[order[2]]
}

func dryRunReorderPoint(point dryRunPoint, order [dryRunNumDims]int) dryRunPoint {
	var ordered dryRunPoint
	for i, dim := range order {
		ordered.Coords[i] = point.Coords[dim]
	}
	return ordered
}

func dryRunReorderQuery(query dryRunRangeQuery, order [dryRunNumDims]int) dryRunRangeQuery {
	var ordered dryRunRangeQuery
	for i, dim := range order {
		ordered.Bounds[i] = query.Bounds[dim]
	}
	return ordered
}

func dryRunPointInQuery(point dryRunPoint, query dryRunRangeQuery) bool {
	for dim := 0; dim < dryRunNumDims; dim++ {
		if point.Coords[dim] < query.Bounds[dim][0] || point.Coords[dim] > query.Bounds[dim][1] {
			return false
		}
	}
	return true
}

func dryRunBuild3DPrefixOccupancyIndex(points []dryRunPoint) dryRunEmptyIndex3D {
	index := dryRunEmptyIndex3D{
		XToY:  make(map[string]map[int64]struct{}),
		XYToZ: make(map[string]map[int64]struct{}),
	}

	for _, point := range points {
		xBin := fmt.Sprintf("%0*b", dryRunBitLength, point.Coords[0])
		yBin := fmt.Sprintf("%0*b", dryRunBitLength, point.Coords[1])
		for xLen := 0; xLen <= len(xBin); xLen++ {
			prefixX := xBin[:xLen]
			dryRunAddOccupiedValue(index.XToY, prefixX, point.Coords[1])
			for yLen := 0; yLen <= len(yBin); yLen++ {
				dryRunAddOccupiedValue(index.XYToZ, dryRunPrefixPairKey(prefixX, yBin[:yLen]), point.Coords[2])
			}
		}
	}

	return index
}

func dryRunAddOccupiedValue(index map[string]map[int64]struct{}, key string, value int64) {
	bucket := index[key]
	if bucket == nil {
		bucket = make(map[int64]struct{})
		index[key] = bucket
	}
	bucket[value] = struct{}{}
}

func dryRunBuildQueryTouchedGlobalEmptyRegions3D(query dryRunRangeQuery, index dryRunEmptyIndex3D) []dryRunGlobalEmptyRegion {
	maxDomain := int64(math.Pow(2, dryRunBitLength)) - 1
	var patterns []string

	xNodes := dryRunCollectIntersectingPrefixNodes(query.Bounds[0][0], query.Bounds[0][1])
	yNodes := dryRunCollectIntersectingPrefixNodes(query.Bounds[1][0], query.Bounds[1][1])
	for _, xNode := range xNodes {
		occupiedY := index.XToY[xNode.Prefix]
		for _, prefixY := range dryRunEmptyCoversForBounds(0, maxDomain, occupiedY) {
			patterns = append(patterns, dryRunFormatToWildcardPattern(xNode.Prefix+"||"+prefixY+"||"))
		}

		for _, yNode := range yNodes {
			if !dryRunHasOccupiedValueInBounds(occupiedY, yNode.Min, yNode.Max) {
				continue
			}

			parentKey := dryRunPrefixPairKey(xNode.Prefix, yNode.Prefix)
			for _, prefixZ := range dryRunEmptyCoversForBounds(0, maxDomain, index.XYToZ[parentKey]) {
				patterns = append(patterns, dryRunFormatToWildcardPattern(xNode.Prefix+"||"+yNode.Prefix+"||"+prefixZ))
			}
		}
	}

	patterns = dryRunSelectMaximalPatterns(patterns)
	regions := make([]dryRunGlobalEmptyRegion, 0, len(patterns))
	for _, pattern := range patterns {
		regions = append(regions, dryRunGlobalEmptyRegion{Pattern: pattern})
	}
	return regions
}

func dryRunCollectIntersectingPrefixNodes(minQuery, maxQuery int64) []dryRunPrefixNode {
	maxDomain := int64(math.Pow(2, dryRunBitLength)) - 1
	var nodes []dryRunPrefixNode

	var walk func(prefix string, minVal, maxVal int64)
	walk = func(prefix string, minVal, maxVal int64) {
		if maxVal < minQuery || minVal > maxQuery {
			return
		}
		nodes = append(nodes, dryRunPrefixNode{Prefix: prefix, Min: minVal, Max: maxVal})
		if len(prefix) == dryRunBitLength {
			return
		}
		mid := minVal + (maxVal-minVal)/2
		walk(prefix+"0", minVal, mid)
		walk(prefix+"1", mid+1, maxVal)
	}

	walk("", 0, maxDomain)
	return nodes
}

func dryRunEmptyCoversForBounds(minVal, maxVal int64, occupied map[int64]struct{}) []string {
	values := make([]int64, 0, len(occupied))
	for value := range occupied {
		if value >= minVal && value <= maxVal {
			values = append(values, value)
		}
	}
	sort.Slice(values, func(i, j int) bool { return values[i] < values[j] })

	maxDomain := int64(math.Pow(2, dryRunBitLength)) - 1
	gapStart := minVal
	var covers []string
	for _, value := range values {
		if value < gapStart {
			continue
		}
		if gapStart <= value-1 {
			covers = append(covers, dryRunCanonicalCover(gapStart, value-1, 0, maxDomain, "")...)
		}
		if value+1 > gapStart {
			gapStart = value + 1
		}
	}
	if gapStart <= maxVal {
		covers = append(covers, dryRunCanonicalCover(gapStart, maxVal, 0, maxDomain, "")...)
	}
	return covers
}

func dryRunCanonicalCover(minVal, maxVal, nodeMin, nodeMax int64, prefix string) []string {
	if minVal <= nodeMin && nodeMax <= maxVal {
		return []string{prefix}
	}
	if nodeMax < minVal || nodeMin > maxVal {
		return nil
	}
	mid := nodeMin + (nodeMax-nodeMin)/2
	left := dryRunCanonicalCover(minVal, maxVal, nodeMin, mid, prefix+"0")
	right := dryRunCanonicalCover(minVal, maxVal, mid+1, nodeMax, prefix+"1")
	return append(left, right...)
}

func dryRunHasOccupiedValueInBounds(occupied map[int64]struct{}, minVal, maxVal int64) bool {
	for value := range occupied {
		if value >= minVal && value <= maxVal {
			return true
		}
	}
	return false
}

func dryRunQueryScopedEmptyPatternsFromGlobal(global []dryRunGlobalEmptyRegion, query dryRunRangeQuery) ([]string, error) {
	var scoped []string
	for _, region := range global {
		children, ok, err := dryRunIntersectPatternWithQuery(region.Pattern, query)
		if err != nil {
			return nil, err
		}
		if ok {
			scoped = append(scoped, children...)
		}
	}
	return dryRunSelectMaximalPatterns(scoped), nil
}

func dryRunIntersectPatternWithQuery(pattern string, query dryRunRangeQuery) ([]string, bool, error) {
	bounds, err := dryRunPatternToBounds(pattern)
	if err != nil {
		return nil, false, err
	}

	var dimCovers [][]string
	for dim := 0; dim < dryRunNumDims; dim++ {
		minVal := bounds[dim][0]
		if query.Bounds[dim][0] > minVal {
			minVal = query.Bounds[dim][0]
		}
		maxVal := bounds[dim][1]
		if query.Bounds[dim][1] < maxVal {
			maxVal = query.Bounds[dim][1]
		}
		if minVal > maxVal {
			return nil, false, nil
		}
		dimCovers = append(dimCovers, dryRunPrefixesFromBounds(minVal, maxVal))
	}

	patterns := make([]string, 0)
	for _, prefix := range dryRunCartesianProduct(dimCovers) {
		childPattern := dryRunFormatToWildcardPattern(prefix)
		if !dryRunPatternContainsPattern(pattern, childPattern) {
			return nil, false, fmt.Errorf("intersection child %s escapes global empty pattern %s", childPattern, pattern)
		}
		patterns = append(patterns, childPattern)
	}
	return patterns, true, nil
}

func dryRunPrefixesFromBounds(minVal, maxVal int64) []string {
	maxDomain := int64(math.Pow(2, dryRunBitLength)) - 1
	return dryRunCanonicalCover(minVal, maxVal, 0, maxDomain, "")
}

func dryRunBuildCoverCandidates(
	patterns []string,
	query dryRunRangeQuery,
	realPoints map[[dryRunNumDims]int64]struct{},
) ([]dryRunCoverCandidate, int, error) {
	indexByPoint, emptyPointCount, err := dryRunBuildEmptyPointIndex(query, realPoints)
	if err != nil {
		return nil, 0, err
	}

	candidates := make([]dryRunCoverCandidate, 0, len(patterns))
	wordCount := dryRunBitsetWordCount(emptyPointCount)
	for idx, pattern := range patterns {
		bounds, err := dryRunPatternToBounds(pattern)
		if err != nil {
			return nil, 0, fmt.Errorf("candidate pattern %d malformed: %w", idx, err)
		}
		if !dryRunBoundsInsideQuery(bounds, query) {
			return nil, 0, fmt.Errorf("candidate pattern %d escapes query bounds: %s", idx, pattern)
		}

		coverage := make([]uint64, wordCount)
		err = dryRunForEachPointInBounds(bounds, func(point dryRunPoint) error {
			key := point.Coords
			if _, ok := realPoints[key]; ok {
				return fmt.Errorf("candidate pattern %d covers real point %v", idx, key)
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
		if !dryRunIsBitsetZero(coverage) {
			candidates = append(candidates, dryRunCoverCandidate{Pattern: pattern, Coverage: coverage})
		}
	}

	return candidates, emptyPointCount, nil
}

func dryRunBuildEmptyPointIndex(
	query dryRunRangeQuery,
	realPoints map[[dryRunNumDims]int64]struct{},
) (map[[dryRunNumDims]int64]int, int, error) {
	indexByPoint := make(map[[dryRunNumDims]int64]int)
	nextIndex := 0
	err := dryRunForEachPointInBounds(query.Bounds, func(point dryRunPoint) error {
		key := point.Coords
		if _, ok := realPoints[key]; ok {
			return nil
		}
		indexByPoint[key] = nextIndex
		nextIndex++
		return nil
	})
	return indexByPoint, nextIndex, err
}

func dryRunGreedySetCover(candidates []dryRunCoverCandidate, emptyPointCount int) ([]dryRunCoverCandidate, error) {
	uncovered := dryRunNewFullBitset(emptyPointCount)
	selectedIdx := make([]int, 0)

	for !dryRunIsBitsetZero(uncovered) {
		bestIdx := -1
		bestGain := 0
		for idx, candidate := range candidates {
			gain := dryRunIntersectionCount(candidate.Coverage, uncovered)
			if gain > bestGain {
				bestIdx = idx
				bestGain = gain
			}
		}
		if bestIdx == -1 || bestGain == 0 {
			return nil, errors.New("greedy set cover stalled before covering all empty points")
		}
		selectedIdx = append(selectedIdx, bestIdx)
		dryRunSubtractCoverage(uncovered, candidates[bestIdx].Coverage)
	}

	coverCounts := make([]int, emptyPointCount)
	for _, idx := range selectedIdx {
		dryRunForEachSetBit(candidates[idx].Coverage, func(bit int) bool {
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
			essential := dryRunForEachSetBit(candidates[idx].Coverage, func(bit int) bool {
				return coverCounts[bit] == 1
			})
			if essential {
				continue
			}
			keep[pos] = false
			changed = true
			dryRunForEachSetBit(candidates[idx].Coverage, func(bit int) bool {
				coverCounts[bit]--
				return false
			})
		}
	}

	selected := make([]dryRunCoverCandidate, 0, len(selectedIdx))
	for pos, idx := range selectedIdx {
		if keep[pos] {
			selected = append(selected, candidates[idx])
		}
	}
	return selected, nil
}

func dryRunVerifyEmptyRegionPatterns(
	query dryRunRangeQuery,
	emptyPatterns []string,
	realPoints map[[dryRunNumDims]int64]struct{},
) (int64, int, error) {
	coverage := make(map[[dryRunNumDims]int64]int)
	maxMultiplicity := 0

	for idx, pattern := range emptyPatterns {
		bounds, err := dryRunPatternToBounds(pattern)
		if err != nil {
			return 0, 0, fmt.Errorf("pattern %d malformed: %w", idx, err)
		}
		if !dryRunBoundsInsideQuery(bounds, query) {
			return 0, 0, fmt.Errorf("pattern %d escapes query bounds: %s", idx, pattern)
		}
		err = dryRunForEachPointInBounds(bounds, func(point dryRunPoint) error {
			key := point.Coords
			if _, ok := realPoints[key]; ok {
				return fmt.Errorf("pattern %d covers real point %v", idx, key)
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
	err := dryRunForEachPointInBounds(query.Bounds, func(point dryRunPoint) error {
		key := point.Coords
		_, real := realPoints[key]
		hits := coverage[key]
		if real {
			if hits != 0 {
				return fmt.Errorf("real point %v was covered by %d empty patterns", key, hits)
			}
			return nil
		}
		if hits == 0 {
			return fmt.Errorf("empty point %v was not covered", key)
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

func dryRunPatternToBounds(pattern string) ([dryRunNumDims][2]int64, error) {
	var bounds [dryRunNumDims][2]int64
	if len(pattern) != dryRunNumDims*dryRunBitLength {
		return bounds, fmt.Errorf("invalid pattern length %d", len(pattern))
	}

	for dim := 0; dim < dryRunNumDims; dim++ {
		var minVal int64
		var maxVal int64
		for bit := 0; bit < dryRunBitLength; bit++ {
			idx := dim*dryRunBitLength + bit
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
		bounds[dim] = [2]int64{minVal, maxVal}
	}
	return bounds, nil
}

func dryRunBoundsInsideQuery(bounds [dryRunNumDims][2]int64, query dryRunRangeQuery) bool {
	for dim := 0; dim < dryRunNumDims; dim++ {
		if bounds[dim][0] < query.Bounds[dim][0] || bounds[dim][1] > query.Bounds[dim][1] {
			return false
		}
	}
	return true
}

func dryRunForEachPointInBounds(bounds [dryRunNumDims][2]int64, visit func(dryRunPoint) error) error {
	var coords [dryRunNumDims]int64
	var walk func(dim int) error
	walk = func(dim int) error {
		if dim == dryRunNumDims {
			return visit(dryRunPoint{Coords: coords})
		}
		for value := bounds[dim][0]; value <= bounds[dim][1]; value++ {
			coords[dim] = value
			if err := walk(dim + 1); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(0)
}

func dryRunFormatToWildcardPattern(prefix string) string {
	dims := strings.Split(prefix, "||")
	var b strings.Builder
	for dim := 0; dim < dryRunNumDims; dim++ {
		b.WriteString(dims[dim])
		for i := len(dims[dim]); i < dryRunBitLength; i++ {
			b.WriteByte('*')
		}
	}
	return b.String()
}

func dryRunPatternContainsPattern(parent, child string) bool {
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

func dryRunSelectMaximalPatterns(patterns []string) []string {
	unique := dryRunDedupePatterns(patterns)
	sort.Slice(unique, func(i, j int) bool {
		starsI := strings.Count(unique[i], "*")
		starsJ := strings.Count(unique[j], "*")
		if starsI != starsJ {
			return starsI > starsJ
		}
		return unique[i] < unique[j]
	})

	maximal := make([]string, 0, len(unique))
	for _, candidate := range unique {
		dominated := false
		for _, chosen := range maximal {
			if dryRunPatternContainsPattern(chosen, candidate) {
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

func dryRunDedupePatterns(patterns []string) []string {
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

func dryRunCartesianProduct(dimCovers [][]string) []string {
	if len(dimCovers) == 0 {
		return nil
	}
	result := dimCovers[0]
	for i := 1; i < len(dimCovers); i++ {
		next := make([]string, 0, len(result)*len(dimCovers[i]))
		for _, prefix := range result {
			for _, cover := range dimCovers[i] {
				next = append(next, prefix+"||"+cover)
			}
		}
		result = next
	}
	return result
}

func dryRunPrefixPairKey(prefixX, prefixY string) string {
	return prefixX + "||" + prefixY
}

func dryRunBitsetWordCount(size int) int {
	if size <= 0 {
		return 0
	}
	return (size + 63) / 64
}

func dryRunNewFullBitset(size int) []uint64 {
	words := make([]uint64, dryRunBitsetWordCount(size))
	for i := range words {
		words[i] = ^uint64(0)
	}
	if rem := size % 64; rem != 0 {
		words[len(words)-1] = (uint64(1) << rem) - 1
	}
	return words
}

func dryRunIsBitsetZero(words []uint64) bool {
	for _, word := range words {
		if word != 0 {
			return false
		}
	}
	return true
}

func dryRunIntersectionCount(a, b []uint64) int {
	total := 0
	for i := range a {
		total += bits.OnesCount64(a[i] & b[i])
	}
	return total
}

func dryRunSubtractCoverage(dst []uint64, coverage []uint64) {
	for i := range dst {
		dst[i] &^= coverage[i]
	}
}

func dryRunForEachSetBit(words []uint64, visit func(int) bool) bool {
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
