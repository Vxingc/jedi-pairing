//go:build ignore
// +build ignore

package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
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
	NumDims                    = 3
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

type SignatureConstraint struct {
	CandidateIDs []int
	PointCount   int
}

type ComponentConstraint struct {
	CandidateIDs []int
	PointCount   int
}

type ExactCoverComponent struct {
	GlobalCandidateIDs []int
	Constraints        []ComponentConstraint
}

type PreparedExactCoverComponent struct {
	GlobalCandidateIDs []int
	Constraints        []ComponentConstraint
	ConstraintBits     [][]uint64
	CandidateCover     [][]uint64
}

type ExactComponentReport struct {
	CandidateCount  int
	ConstraintCount int
	OptimalKeys     int
	SearchNodes     int64
}

type ExactCoverReport struct {
	SignatureConstraintCount    int
	ReducedConstraintCount      int
	ComponentCount              int
	LargestComponentCandidates  int
	LargestComponentConstraints int
	SearchNodes                 int64
	Components                  []ExactComponentReport
}

type exactComponentSearch struct {
	component *PreparedExactCoverComponent
	bestCount int
	bestSet   []int
	nodes     int64
	deadline  time.Time
	timedOut  bool
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

func IsPointInQuery(p Point, q RangeQuery) bool {
	for i := 0; i < NumDims; i++ {
		if p.Coords[i] < q.Bounds[i][0] || p.Coords[i] > q.Bounds[i][1] {
			return false
		}
	}
	return true
}

func generateBitOrderCustom(dimOrder []int, bitLen int) []int {
	var order []int
	for _, d := range dimOrder {
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

func calculateVolume(pattern string) int64 {
	starCount := strings.Count(pattern, "*")
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

	maximal := make([]string, 0, len(unique))
	for _, candidate := range unique {
		dominated := false
		for _, chosen := range maximal {
			if patternContainsPattern(chosen, candidate) {
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

func cloneBitset(words []uint64) []uint64 {
	dup := make([]uint64, len(words))
	copy(dup, words)
	return dup
}

func isBitsetZero(words []uint64) bool {
	for _, word := range words {
		if word != 0 {
			return false
		}
	}
	return true
}

func bitsetPopCount(words []uint64) int {
	total := 0
	for _, word := range words {
		total += bits.OnesCount64(word)
	}
	return total
}

func bitsetSubset(subset, superset []uint64) bool {
	for i := range subset {
		if subset[i]&^superset[i] != 0 {
			return false
		}
	}
	return true
}

func bitsetIntersects(a, b []uint64) bool {
	for i := range a {
		if a[i]&b[i] != 0 {
			return true
		}
	}
	return false
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

func bitsetHas(words []uint64, bit int) bool {
	return words[bit/64]&(uint64(1)<<(bit%64)) != 0
}

func bitsetSet(words []uint64, bit int) {
	words[bit/64] |= uint64(1) << (bit % 64)
}

func bitsetClear(words []uint64, bit int) {
	words[bit/64] &^= uint64(1) << (bit % 64)
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

func encodeIntSliceKey(values []int) string {
	buf := make([]byte, len(values)*4)
	for i, value := range values {
		binary.LittleEndian.PutUint32(buf[i*4:], uint32(value))
	}
	return string(buf)
}

func compareIntSlices(a, b []int) int {
	limit := len(a)
	if len(b) < limit {
		limit = len(b)
	}
	for i := 0; i < limit; i++ {
		if a[i] < b[i] {
			return -1
		}
		if a[i] > b[i] {
			return 1
		}
	}
	switch {
	case len(a) < len(b):
		return -1
	case len(a) > len(b):
		return 1
	default:
		return 0
	}
}

func buildSignatureConstraints(candidates []CoverCandidate, emptyPointCount int) ([]SignatureConstraint, error) {
	pointCandidateLists := make([][]int, emptyPointCount)

	for candidateIdx, candidate := range candidates {
		forEachSetBit(candidate.Coverage, func(bit int) bool {
			if bit >= emptyPointCount {
				return true
			}
			pointCandidateLists[bit] = append(pointCandidateLists[bit], candidateIdx)
			return false
		})
	}

	constraintByKey := make(map[string]int)
	constraints := make([]SignatureConstraint, 0)

	for pointIdx, candidateIDs := range pointCandidateLists {
		if len(candidateIDs) == 0 {
			return nil, fmt.Errorf("empty point %d is not covered by any maximal candidate", pointIdx)
		}
		key := encodeIntSliceKey(candidateIDs)
		if idx, ok := constraintByKey[key]; ok {
			constraints[idx].PointCount++
			continue
		}

		idsCopy := append([]int(nil), candidateIDs...)
		constraintByKey[key] = len(constraints)
		constraints = append(constraints, SignatureConstraint{
			CandidateIDs: idsCopy,
			PointCount:   1,
		})
	}

	sort.Slice(constraints, func(i, j int) bool {
		if len(constraints[i].CandidateIDs) != len(constraints[j].CandidateIDs) {
			return len(constraints[i].CandidateIDs) < len(constraints[j].CandidateIDs)
		}
		return compareIntSlices(constraints[i].CandidateIDs, constraints[j].CandidateIDs) < 0
	})

	return constraints, nil
}

type disjointSet struct {
	parent []int
	rank   []int
}

func newDisjointSet(size int) *disjointSet {
	parent := make([]int, size)
	rank := make([]int, size)
	for i := range parent {
		parent[i] = i
	}
	return &disjointSet{parent: parent, rank: rank}
}

func (d *disjointSet) find(x int) int {
	if d.parent[x] != x {
		d.parent[x] = d.find(d.parent[x])
	}
	return d.parent[x]
}

func (d *disjointSet) union(a, b int) {
	rootA := d.find(a)
	rootB := d.find(b)
	if rootA == rootB {
		return
	}
	if d.rank[rootA] < d.rank[rootB] {
		rootA, rootB = rootB, rootA
	}
	d.parent[rootB] = rootA
	if d.rank[rootA] == d.rank[rootB] {
		d.rank[rootA]++
	}
}

func buildExactCoverComponents(constraints []SignatureConstraint, numCandidates int) []ExactCoverComponent {
	if len(constraints) == 0 {
		return nil
	}

	dsu := newDisjointSet(numCandidates)
	for _, constraint := range constraints {
		if len(constraint.CandidateIDs) == 0 {
			continue
		}
		base := constraint.CandidateIDs[0]
		for _, candidateID := range constraint.CandidateIDs[1:] {
			dsu.union(base, candidateID)
		}
	}

	type tempComponent struct {
		candidateSet map[int]struct{}
		constraints  []SignatureConstraint
	}

	tempByRoot := make(map[int]*tempComponent)
	for _, constraint := range constraints {
		root := dsu.find(constraint.CandidateIDs[0])
		temp, ok := tempByRoot[root]
		if !ok {
			temp = &tempComponent{candidateSet: make(map[int]struct{})}
			tempByRoot[root] = temp
		}
		temp.constraints = append(temp.constraints, constraint)
		for _, candidateID := range constraint.CandidateIDs {
			temp.candidateSet[candidateID] = struct{}{}
		}
	}

	components := make([]ExactCoverComponent, 0, len(tempByRoot))
	for _, temp := range tempByRoot {
		globalCandidateIDs := make([]int, 0, len(temp.candidateSet))
		for candidateID := range temp.candidateSet {
			globalCandidateIDs = append(globalCandidateIDs, candidateID)
		}
		sort.Ints(globalCandidateIDs)

		localIndex := make(map[int]int, len(globalCandidateIDs))
		for localID, globalID := range globalCandidateIDs {
			localIndex[globalID] = localID
		}

		componentConstraints := make([]ComponentConstraint, 0, len(temp.constraints))
		for _, constraint := range temp.constraints {
			localCandidateIDs := make([]int, len(constraint.CandidateIDs))
			for i, globalID := range constraint.CandidateIDs {
				localCandidateIDs[i] = localIndex[globalID]
			}
			sort.Ints(localCandidateIDs)
			componentConstraints = append(componentConstraints, ComponentConstraint{
				CandidateIDs: localCandidateIDs,
				PointCount:   constraint.PointCount,
			})
		}

		components = append(components, ExactCoverComponent{
			GlobalCandidateIDs: globalCandidateIDs,
			Constraints:        componentConstraints,
		})
	}

	sort.Slice(components, func(i, j int) bool {
		if len(components[i].GlobalCandidateIDs) != len(components[j].GlobalCandidateIDs) {
			return len(components[i].GlobalCandidateIDs) > len(components[j].GlobalCandidateIDs)
		}
		return len(components[i].Constraints) > len(components[j].Constraints)
	})

	return components
}

func dedupeComponentConstraints(constraints []ComponentConstraint) []ComponentConstraint {
	indexByKey := make(map[string]int, len(constraints))
	deduped := make([]ComponentConstraint, 0, len(constraints))

	for _, constraint := range constraints {
		key := encodeIntSliceKey(constraint.CandidateIDs)
		if idx, ok := indexByKey[key]; ok {
			deduped[idx].PointCount += constraint.PointCount
			continue
		}

		idsCopy := append([]int(nil), constraint.CandidateIDs...)
		indexByKey[key] = len(deduped)
		deduped = append(deduped, ComponentConstraint{
			CandidateIDs: idsCopy,
			PointCount:   constraint.PointCount,
		})
	}

	sort.Slice(deduped, func(i, j int) bool {
		if len(deduped[i].CandidateIDs) != len(deduped[j].CandidateIDs) {
			return len(deduped[i].CandidateIDs) < len(deduped[j].CandidateIDs)
		}
		return compareIntSlices(deduped[i].CandidateIDs, deduped[j].CandidateIDs) < 0
	})
	return deduped
}

func intSliceToBitset(values []int, size int) []uint64 {
	bits := make([]uint64, bitsetWordCount(size))
	for _, value := range values {
		bitsetSet(bits, value)
	}
	return bits
}

func removeRedundantConstraints(
	constraints []ComponentConstraint,
	candidateCount int,
) ([]ComponentConstraint, bool) {
	if len(constraints) <= 1 {
		return constraints, false
	}

	constraintBits := make([][]uint64, len(constraints))
	order := make([]int, len(constraints))
	for i, constraint := range constraints {
		constraintBits[i] = intSliceToBitset(constraint.CandidateIDs, candidateCount)
		order[i] = i
	}

	sort.Slice(order, func(i, j int) bool {
		left := constraints[order[i]]
		right := constraints[order[j]]
		if len(left.CandidateIDs) != len(right.CandidateIDs) {
			return len(left.CandidateIDs) < len(right.CandidateIDs)
		}
		return compareIntSlices(left.CandidateIDs, right.CandidateIDs) < 0
	})

	removed := make([]bool, len(constraints))
	changed := false

	for orderPos, idxA := range order {
		if removed[idxA] {
			continue
		}
		for _, idxB := range order[orderPos+1:] {
			if removed[idxB] {
				continue
			}
			if len(constraints[idxA].CandidateIDs) > len(constraints[idxB].CandidateIDs) {
				continue
			}
			if bitsetSubset(constraintBits[idxA], constraintBits[idxB]) {
				removed[idxB] = true
				changed = true
			}
		}
	}

	if !changed {
		return constraints, false
	}

	filtered := make([]ComponentConstraint, 0, len(constraints))
	for idx, constraint := range constraints {
		if !removed[idx] {
			filtered = append(filtered, constraint)
		}
	}
	return filtered, true
}

func buildCandidateConstraintCoverage(constraints []ComponentConstraint, candidateCount int) [][]uint64 {
	coverage := make([][]uint64, candidateCount)
	constraintWords := bitsetWordCount(len(constraints))
	for i := range coverage {
		coverage[i] = make([]uint64, constraintWords)
	}
	for constraintIdx, constraint := range constraints {
		for _, candidateID := range constraint.CandidateIDs {
			bitsetSet(coverage[candidateID], constraintIdx)
		}
	}
	return coverage
}

func removeDominatedCandidates(component ExactCoverComponent) (ExactCoverComponent, bool, error) {
	candidateCoverage := buildCandidateConstraintCoverage(component.Constraints, len(component.GlobalCandidateIDs))
	keep := make([]bool, len(component.GlobalCandidateIDs))
	changed := false

	for i := range keep {
		keep[i] = !isBitsetZero(candidateCoverage[i])
		if !keep[i] {
			changed = true
		}
	}

	for i := 0; i < len(component.GlobalCandidateIDs); i++ {
		if !keep[i] {
			continue
		}
		for j := i + 1; j < len(component.GlobalCandidateIDs); j++ {
			if !keep[j] {
				continue
			}

			if bitsetSubset(candidateCoverage[j], candidateCoverage[i]) {
				keep[j] = false
				changed = true
				continue
			}
			if bitsetSubset(candidateCoverage[i], candidateCoverage[j]) {
				keep[i] = false
				changed = true
				break
			}
		}
	}

	if !changed {
		return component, false, nil
	}

	newGlobalCandidateIDs := make([]int, 0, len(component.GlobalCandidateIDs))
	newIndex := make(map[int]int, len(component.GlobalCandidateIDs))
	for oldID, ok := range keep {
		if !ok {
			continue
		}
		newIndex[oldID] = len(newGlobalCandidateIDs)
		newGlobalCandidateIDs = append(newGlobalCandidateIDs, component.GlobalCandidateIDs[oldID])
	}

	newConstraints := make([]ComponentConstraint, 0, len(component.Constraints))
	for _, constraint := range component.Constraints {
		localCandidateIDs := make([]int, 0, len(constraint.CandidateIDs))
		for _, oldID := range constraint.CandidateIDs {
			if mappedID, ok := newIndex[oldID]; ok {
				localCandidateIDs = append(localCandidateIDs, mappedID)
			}
		}
		if len(localCandidateIDs) == 0 {
			return ExactCoverComponent{}, false, errors.New("candidate domination pruning removed all options from a constraint")
		}
		newConstraints = append(newConstraints, ComponentConstraint{
			CandidateIDs: localCandidateIDs,
			PointCount:   constraint.PointCount,
		})
	}

	return ExactCoverComponent{
		GlobalCandidateIDs: newGlobalCandidateIDs,
		Constraints:        newConstraints,
	}, true, nil
}

func simplifyExactCoverComponent(component ExactCoverComponent) (ExactCoverComponent, error) {
	changed := true
	for changed {
		changed = false

		deduped := dedupeComponentConstraints(component.Constraints)
		if len(deduped) != len(component.Constraints) {
			changed = true
		}
		component.Constraints = deduped

		filteredConstraints, removed := removeRedundantConstraints(component.Constraints, len(component.GlobalCandidateIDs))
		if removed {
			component.Constraints = filteredConstraints
			changed = true
		}

		prunedComponent, candidateChanged, err := removeDominatedCandidates(component)
		if err != nil {
			return ExactCoverComponent{}, err
		}
		if candidateChanged {
			component = prunedComponent
			changed = true
		}
	}

	return component, nil
}

func prepareExactCoverComponent(component ExactCoverComponent) PreparedExactCoverComponent {
	candidateCount := len(component.GlobalCandidateIDs)
	constraintCount := len(component.Constraints)
	candidateWords := bitsetWordCount(candidateCount)
	constraintWords := bitsetWordCount(constraintCount)

	constraintBits := make([][]uint64, constraintCount)
	candidateCover := make([][]uint64, candidateCount)
	for i := range candidateCover {
		candidateCover[i] = make([]uint64, constraintWords)
	}

	for constraintIdx, constraint := range component.Constraints {
		bitsForConstraint := make([]uint64, candidateWords)
		for _, candidateID := range constraint.CandidateIDs {
			bitsetSet(bitsForConstraint, candidateID)
			bitsetSet(candidateCover[candidateID], constraintIdx)
		}
		constraintBits[constraintIdx] = bitsForConstraint
	}

	return PreparedExactCoverComponent{
		GlobalCandidateIDs: component.GlobalCandidateIDs,
		Constraints:        component.Constraints,
		ConstraintBits:     constraintBits,
		CandidateCover:     candidateCover,
	}
}

func collectIntersectionBits(a, b []uint64) []int {
	values := make([]int, 0)
	for wordIdx := range a {
		word := a[wordIdx] & b[wordIdx]
		for word != 0 {
			bit := bits.TrailingZeros64(word)
			values = append(values, wordIdx*64+bit)
			word &= word - 1
		}
	}
	return values
}

func selectCandidateInState(
	component *PreparedExactCoverComponent,
	uncovered []uint64,
	active []uint64,
	candidateID int,
	selected *[]int,
) {
	if !bitsetHas(active, candidateID) {
		return
	}
	bitsetClear(active, candidateID)
	subtractCoverage(uncovered, component.CandidateCover[candidateID])
	*selected = append(*selected, candidateID)
}

func singleActiveCandidate(constraintBits, active []uint64) (int, int) {
	found := -1
	count := 0
	for wordIdx := range constraintBits {
		word := constraintBits[wordIdx] & active[wordIdx]
		for word != 0 {
			bit := bits.TrailingZeros64(word)
			found = wordIdx*64 + bit
			count++
			if count > 1 {
				return found, count
			}
			word &= word - 1
		}
	}
	return found, count
}

func propagateForcedSelections(
	component *PreparedExactCoverComponent,
	uncovered []uint64,
	active []uint64,
	selected *[]int,
) error {
	for {
		progress := false
		infeasible := false

		stopped := forEachSetBit(uncovered, func(constraintIdx int) bool {
			candidateID, optionCount := singleActiveCandidate(component.ConstraintBits[constraintIdx], active)
			if optionCount == 0 {
				infeasible = true
				return true
			}
			if optionCount == 1 {
				selectCandidateInState(component, uncovered, active, candidateID, selected)
				progress = true
				return true
			}
			return false
		})

		if infeasible {
			return errors.New("infeasible exact-cover state")
		}
		if !progress {
			return nil
		}
		if !stopped {
			return nil
		}
	}
}

func greedyPackingLowerBound(
	component *PreparedExactCoverComponent,
	uncovered []uint64,
	active []uint64,
) int {
	type choice struct {
		constraintIdx int
		optionCount   int
	}

	choices := make([]choice, 0)
	forEachSetBit(uncovered, func(constraintIdx int) bool {
		optionCount := intersectionCount(component.ConstraintBits[constraintIdx], active)
		if optionCount > 0 {
			choices = append(choices, choice{
				constraintIdx: constraintIdx,
				optionCount:   optionCount,
			})
		}
		return false
	})

	sort.Slice(choices, func(i, j int) bool {
		if choices[i].optionCount != choices[j].optionCount {
			return choices[i].optionCount < choices[j].optionCount
		}
		return choices[i].constraintIdx < choices[j].constraintIdx
	})

	usedCandidates := make([]uint64, len(active))
	packing := 0

	for _, item := range choices {
		if bitsetIntersects(component.ConstraintBits[item.constraintIdx], usedCandidates) {
			continue
		}
		for wordIdx := range usedCandidates {
			usedCandidates[wordIdx] |= component.ConstraintBits[item.constraintIdx][wordIdx] & active[wordIdx]
		}
		packing++
	}

	return packing
}

func exactCoverLowerBound(
	component *PreparedExactCoverComponent,
	uncovered []uint64,
	active []uint64,
) int {
	remainingConstraints := bitsetPopCount(uncovered)
	if remainingConstraints == 0 {
		return 0
	}

	maxGain := 0
	for candidateID := range component.CandidateCover {
		if !bitsetHas(active, candidateID) {
			continue
		}
		gain := intersectionCount(component.CandidateCover[candidateID], uncovered)
		if gain > maxGain {
			maxGain = gain
		}
	}

	if maxGain == 0 {
		return int(^uint(0) >> 1)
	}

	lbByCoverage := (remainingConstraints + maxGain - 1) / maxGain
	lbByPacking := greedyPackingLowerBound(component, uncovered, active)
	if lbByPacking > lbByCoverage {
		return lbByPacking
	}
	return lbByCoverage
}

func chooseBranchConstraint(
	component *PreparedExactCoverComponent,
	uncovered []uint64,
	active []uint64,
) (int, []int, error) {
	bestConstraint := -1
	bestOptions := []int(nil)
	bestCount := int(^uint(0) >> 1)

	stopped := forEachSetBit(uncovered, func(constraintIdx int) bool {
		options := collectIntersectionBits(component.ConstraintBits[constraintIdx], active)
		if len(options) == 0 {
			bestConstraint = -1
			bestOptions = nil
			bestCount = 0
			return true
		}
		if len(options) < bestCount {
			bestConstraint = constraintIdx
			bestOptions = options
			bestCount = len(options)
			if bestCount == 1 {
				return true
			}
		}
		return false
	})

	if stopped && bestCount == 0 {
		return -1, nil, errors.New("infeasible exact-cover branch")
	}
	if bestConstraint == -1 {
		return -1, nil, errors.New("failed to choose a branch constraint")
	}

	sort.Slice(bestOptions, func(i, j int) bool {
		gainI := intersectionCount(component.CandidateCover[bestOptions[i]], uncovered)
		gainJ := intersectionCount(component.CandidateCover[bestOptions[j]], uncovered)
		if gainI != gainJ {
			return gainI > gainJ
		}
		return bestOptions[i] < bestOptions[j]
	})

	return bestConstraint, bestOptions, nil
}

func greedyExactCoverUpperBound(component *PreparedExactCoverComponent) ([]int, error) {
	uncovered := newFullBitset(len(component.Constraints))
	active := newFullBitset(len(component.GlobalCandidateIDs))
	selected := make([]int, 0)

	if err := propagateForcedSelections(component, uncovered, active, &selected); err != nil {
		return nil, err
	}

	for !isBitsetZero(uncovered) {
		bestCandidate := -1
		bestGain := 0

		for candidateID := range component.CandidateCover {
			if !bitsetHas(active, candidateID) {
				continue
			}
			gain := intersectionCount(component.CandidateCover[candidateID], uncovered)
			if gain > bestGain {
				bestCandidate = candidateID
				bestGain = gain
			}
		}

		if bestCandidate == -1 || bestGain == 0 {
			return nil, errors.New("greedy upper bound failed to cover all reduced constraints")
		}

		selectCandidateInState(component, uncovered, active, bestCandidate, &selected)
		if err := propagateForcedSelections(component, uncovered, active, &selected); err != nil {
			return nil, err
		}
	}

	return selected, nil
}

func (s *exactComponentSearch) solve() ([]int, error) {
	initialUpperBound, err := greedyExactCoverUpperBound(s.component)
	if err != nil {
		return nil, err
	}
	s.bestCount = len(initialUpperBound)
	s.bestSet = append([]int(nil), initialUpperBound...)

	uncovered := newFullBitset(len(s.component.Constraints))
	active := newFullBitset(len(s.component.GlobalCandidateIDs))
	s.search(uncovered, active, nil)

	if s.timedOut {
		return nil, errors.New("exact set-cover search timed out before proving optimality")
	}
	return s.bestSet, nil
}

func (s *exactComponentSearch) search(uncovered, active []uint64, selected []int) {
	if s.timedOut {
		return
	}
	if !s.deadline.IsZero() && time.Now().After(s.deadline) {
		s.timedOut = true
		return
	}

	s.nodes++
	if len(selected) >= s.bestCount {
		return
	}

	localSelected := append([]int(nil), selected...)
	if err := propagateForcedSelections(s.component, uncovered, active, &localSelected); err != nil {
		return
	}
	if len(localSelected) >= s.bestCount {
		return
	}

	if isBitsetZero(uncovered) {
		s.bestCount = len(localSelected)
		s.bestSet = append([]int(nil), localSelected...)
		return
	}

	lowerBound := exactCoverLowerBound(s.component, uncovered, active)
	if lowerBound == int(^uint(0)>>1) || len(localSelected)+lowerBound >= s.bestCount {
		return
	}

	_, branchOptions, err := chooseBranchConstraint(s.component, uncovered, active)
	if err != nil {
		return
	}

	for _, candidateID := range branchOptions {
		branchUncovered := cloneBitset(uncovered)
		branchActive := cloneBitset(active)
		branchSelected := append([]int(nil), localSelected...)

		selectCandidateInState(s.component, branchUncovered, branchActive, candidateID, &branchSelected)
		s.search(branchUncovered, branchActive, branchSelected)
		if s.timedOut {
			return
		}
	}
}

func writeExactCoverILP(path string, components []ExactCoverComponent) error {
	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	fmt.Fprintln(file, "Minimize")
	fmt.Fprint(file, " obj:")

	firstVar := true
	for compIdx, component := range components {
		for candIdx := range component.GlobalCandidateIDs {
			if !firstVar {
				fmt.Fprint(file, " +")
			}
			fmt.Fprintf(file, " x_%d_%d", compIdx, candIdx)
			firstVar = false
		}
	}
	fmt.Fprintln(file)
	fmt.Fprintln(file, "Subject To")

	constraintCounter := 0
	for compIdx, component := range components {
		for _, constraint := range component.Constraints {
			fmt.Fprintf(file, " c_%d:", constraintCounter)
			for _, candIdx := range constraint.CandidateIDs {
				fmt.Fprintf(file, " + x_%d_%d", compIdx, candIdx)
			}
			fmt.Fprintln(file, " >= 1")
			constraintCounter++
		}
	}

	fmt.Fprintln(file, "Binary")
	for compIdx, component := range components {
		for candIdx := range component.GlobalCandidateIDs {
			fmt.Fprintf(file, " x_%d_%d\n", compIdx, candIdx)
		}
	}
	fmt.Fprintln(file, "End")
	return nil
}

func solveExactSetCover(
	candidates []CoverCandidate,
	emptyPointCount int,
	timeLimit time.Duration,
	lpOut string,
) ([]CoverCandidate, ExactCoverReport, error) {
	signatureConstraints, err := buildSignatureConstraints(candidates, emptyPointCount)
	if err != nil {
		return nil, ExactCoverReport{}, err
	}

	components := buildExactCoverComponents(signatureConstraints, len(candidates))
	simplifiedComponents := make([]ExactCoverComponent, 0, len(components))
	report := ExactCoverReport{
		SignatureConstraintCount: len(signatureConstraints),
		ComponentCount:           len(components),
	}

	for _, component := range components {
		simplified, err := simplifyExactCoverComponent(component)
		if err != nil {
			return nil, ExactCoverReport{}, err
		}
		report.ReducedConstraintCount += len(simplified.Constraints)
		if len(simplified.GlobalCandidateIDs) > report.LargestComponentCandidates {
			report.LargestComponentCandidates = len(simplified.GlobalCandidateIDs)
		}
		if len(simplified.Constraints) > report.LargestComponentConstraints {
			report.LargestComponentConstraints = len(simplified.Constraints)
		}
		simplifiedComponents = append(simplifiedComponents, simplified)
	}

	if lpOut != "" {
		if err := writeExactCoverILP(lpOut, simplifiedComponents); err != nil {
			return nil, ExactCoverReport{}, err
		}
	}

	deadline := time.Time{}
	if timeLimit > 0 {
		deadline = time.Now().Add(timeLimit)
	}

	selectedGlobalIDs := make([]int, 0)
	report.Components = make([]ExactComponentReport, 0, len(simplifiedComponents))

	for compIdx, component := range simplifiedComponents {
		fmt.Printf("    -> Solving exact component %d/%d: %d candidates, %d reduced constraints...\n",
			compIdx+1, len(simplifiedComponents), len(component.GlobalCandidateIDs), len(component.Constraints))

		prepared := prepareExactCoverComponent(component)
		search := exactComponentSearch{
			component: &prepared,
			bestCount: int(^uint(0) >> 1),
			deadline:  deadline,
		}

		selectedLocalIDs, err := search.solve()
		if err != nil {
			return nil, ExactCoverReport{}, err
		}

		report.SearchNodes += search.nodes
		report.Components = append(report.Components, ExactComponentReport{
			CandidateCount:  len(component.GlobalCandidateIDs),
			ConstraintCount: len(component.Constraints),
			OptimalKeys:     len(selectedLocalIDs),
			SearchNodes:     search.nodes,
		})

		for _, localID := range selectedLocalIDs {
			selectedGlobalIDs = append(selectedGlobalIDs, prepared.GlobalCandidateIDs[localID])
		}

		fmt.Printf("       exact optimum = %d keys, search nodes = %d\n", len(selectedLocalIDs), search.nodes)
	}

	sort.Ints(selectedGlobalIDs)
	selected := make([]CoverCandidate, 0, len(selectedGlobalIDs))
	for _, globalID := range selectedGlobalIDs {
		selected = append(selected, candidates[globalID])
	}

	return selected, report, nil
}

func derivePatternKeyFromRoot(
	params *wkdibe.Params,
	rootKey *wkdibe.SecretKey,
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
		Key:     wkdibe.QualifyKey(params, rootKey, attrs),
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
	rootKey *wkdibe.SecretKey,
	initialPatterns []string,
	bitOrder []int,
) ([]DerivedPatternKey, error) {
	keys := make([]DerivedPatternKey, 0, len(initialPatterns))
	for _, pattern := range initialPatterns {
		derived, err := derivePatternKeyFromRoot(params, rootKey, pattern, bitOrder)
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

func makeCoverageBitset(size int, points ...int) []uint64 {
	words := make([]uint64, bitsetWordCount(size))
	for _, point := range points {
		bitsetSet(words, point)
	}
	return words
}

func runSelfTest() error {
	candidates := []CoverCandidate{
		{Pattern: "A", Coverage: makeCoverageBitset(4, 0, 1)},
		{Pattern: "B", Coverage: makeCoverageBitset(4, 1, 2)},
		{Pattern: "C", Coverage: makeCoverageBitset(4, 2, 3)},
		{Pattern: "D", Coverage: makeCoverageBitset(4, 0, 3)},
	}

	selected, report, err := solveExactSetCover(candidates, 4, 0, "")
	if err != nil {
		return err
	}
	if len(selected) != 2 {
		return fmt.Errorf("self-test expected optimum 2, got %d", len(selected))
	}
	fmt.Printf("[+] Self-test passed: optimum=%d, signatures=%d, reduced=%d, components=%d\n",
		len(selected), report.SignatureConstraintCount, report.ReducedConstraintCount, report.ComponentCount)
	return nil
}

func main() {
	selfTest := flag.Bool("self-test", false, "run a small exact-cover self-test and exit")
	lpOut := flag.String("lp-out", "", "optional path for writing the reduced exact-cover ILP model")
	timeLimit := flag.Duration("time-limit", 0, "optional exact-search time limit, e.g. 5m")
	skipZK := flag.Bool("skip-zk", false, "skip Engine B and stop after Engine A")
	flag.Parse()

	if *selfTest {
		if err := runSelfTest(); err != nil {
			panic(err)
		}
		return
	}

	fmt.Println("[*] Starting ULTIMATE ARCHITECTURE Benchmark...")
	fmt.Println("[*] Mode: Hexa-Sweep + EXACT Set Cover / ILP + ZK-Accumulator")

	mcl.InitFromString("bls12-381")
	setupStart := time.Now()
	params, masterKey := wkdibe.Setup(36, true)

	var acc bpacc.BpAcc
	keyDir := "./pkvk-17"
	acc.KeyGenLoad(8, 17, "my_secure_seed", keyDir)
	setupMs := float64(time.Since(setupStart).Nanoseconds()) / 1e6
	fmt.Printf("[*] Global Setup Time: %.2f ms\n\n", setupMs)

	file, err := os.Open("/home/xing/poneglyphdb/src/data/lineitem_120K.tbl")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	var dbData []Point
	var dbFr []mcl.Fr
	var I []mcl.Fr
	var X []mcl.Fr
	queryUniquePoints := make(map[[NumDims]int64]struct{})

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
			queryUniquePoints[p.Coords] = struct{}{}
		} else {
			X = append(X, fr)
		}
	}
	if err := scanner.Err(); err != nil {
		panic(err)
	}
	fmt.Printf("[*] Loaded %d real TPC-H records.\n", len(dbData))
	fmt.Printf("[*] Query matched %d real records.\n", len(I))

	digest_DB, _ := acc.CommitFakeG1(dbFr)
	digest_X, _ := acc.CommitFakeG1(X)

	fmt.Println("\n=== ENGINE A: M-HIBE HEXA-SWEEP (Confidentiality & Access Control) ===")
	extractionStart := time.Now()

	initialPrefixes := MapToIDs(query)
	var initialPatterns []string
	for _, p := range initialPrefixes {
		initialPatterns = append(initialPatterns, FormatToWildcardPattern(p, NumDims, BitLength))
	}

	permutations := [][]int{
		{0, 1, 2}, {0, 2, 1}, {1, 0, 2},
		{1, 2, 0}, {2, 0, 1}, {2, 1, 0},
	}
	permNames := []string{"X->Y->Z", "X->Z->Y", "Y->X->Z", "Y->Z->X", "Z->X->Y", "Z->Y->X"}

	var combinedEmptyPatterns []string
	var sweepCounts []int

	for i, perm := range permutations {
		fmt.Printf("    -> Executing Permutation %d: [%s]...\n", i+1, permNames[i])
		order := generateBitOrderCustom(perm, BitLength)
		patterns := SubtractPointsOrdered(initialPatterns, dbData, order)
		sweepCounts = append(sweepCounts, len(patterns))
		combinedEmptyPatterns = append(combinedEmptyPatterns, patterns...)
	}
	extractionMs := float64(time.Since(extractionStart).Nanoseconds()) / 1e6

	coverStart := time.Now()
	maximalEmptyPatterns := selectMaximalPatterns(combinedEmptyPatterns)
	coverCandidates, emptyPointCount, err := buildCoverCandidates(maximalEmptyPatterns, query, queryUniquePoints)
	if err != nil {
		panic(err)
	}

	selectedCover, exactReport, err := solveExactSetCover(coverCandidates, emptyPointCount, *timeLimit, *lpOut)
	if err != nil {
		panic(err)
	}

	if *lpOut != "" {
		fmt.Printf("    -> Wrote reduced exact-cover ILP to %s\n", *lpOut)
	}

	selectedCoverPatterns := make([]string, 0, len(selectedCover))
	for _, candidate := range selectedCover {
		selectedCoverPatterns = append(selectedCoverPatterns, candidate.Pattern)
	}
	exactCoverMs := float64(time.Since(coverStart).Nanoseconds()) / 1e6

	cryptoStart := time.Now()
	rootKey := wkdibe.KeyGen(params, masterKey, make(wkdibe.AttributeList))
	initialKeys, err := deriveInitialPatternKeys(params, rootKey, initialPatterns, nil)
	if err != nil {
		panic(err)
	}
	verificationEmptyKeys, err := deriveEmptyPatternKeys(params, initialKeys, selectedCoverPatterns, nil)
	if err != nil {
		panic(err)
	}

	totalKeyBytes := 0
	for _, key := range verificationEmptyKeys {
		totalKeyBytes += len(key.Key.Marshal(true))
	}
	mhibeCryptoMs := float64(time.Since(cryptoStart).Nanoseconds()) / 1e6
	engineAMs := extractionMs + exactCoverMs + mhibeCryptoMs

	for i, count := range sweepCounts {
		fmt.Printf("    - Permutation %d (%s): %d regions\n", i+1, permNames[i], count)
	}
	fmt.Printf("1. Total Empty Regions Across Six Sweeps: %d\n", len(combinedEmptyPatterns))
	fmt.Printf("2. Maximal Empty Blocks After Merge: %d\n", len(maximalEmptyPatterns))
	fmt.Printf("3. Signature Constraints After Compression: %d\n", exactReport.SignatureConstraintCount)
	fmt.Printf("4. Reduced Exact-Cover Constraints: %d\n", exactReport.ReducedConstraintCount)
	fmt.Printf("5. Independent Exact-Cover Components: %d\n", exactReport.ComponentCount)
	fmt.Printf("6. Exact Minimum Cover Keys: %d\n", len(verificationEmptyKeys))
	fmt.Printf("7. Prefix Extraction Time: %.2f ms\n", extractionMs)
	fmt.Printf("8. Exact Cover Solve Time: %.2f ms\n", exactCoverMs)
	fmt.Printf("9. Exact Cover Search Nodes: %d\n", exactReport.SearchNodes)
	fmt.Printf("10. WKD-IBE Delegation Time: %.2f ms\n", mhibeCryptoMs)
	fmt.Printf("11. WKD-IBE Secret Key Material: %.2f KB\n", float64(totalKeyBytes)/1024.0)
	fmt.Printf("-> Engine A Total: %.2f ms\n", engineAMs)
	fmt.Printf("    -> Largest reduced component: %d candidates / %d constraints\n",
		exactReport.LargestComponentCandidates, exactReport.LargestComponentConstraints)

	fmt.Println("\n=== ENGINE A: CLIENT COMPLETENESS CHECK ===")
	clientCheckStart := time.Now()

	var totalQueryVolume int64
	for _, p := range initialPatterns {
		totalQueryVolume += calculateVolume(p)
	}

	coveredEmptyPoints, maxOverlap, verifyErr := verifyEmptyRegionPatterns(query, selectedCoverPatterns, queryUniquePoints)
	keyChecks, keyVerifyErr := verifyDerivedPatternKeys(params, verificationEmptyKeys)
	realSpatialVolume := int64(len(queryUniquePoints))
	clientCheckMs := float64(time.Since(clientCheckStart).Nanoseconds()) / 1e6

	if verifyErr == nil && keyVerifyErr == nil && coveredEmptyPoints+realSpatialVolume == totalQueryVolume {
		fmt.Printf("[+] Client Empty-Key Check Time: %.4f ms (SUCCESS! Exact minimum key cover verified.)\n", clientCheckMs)
		fmt.Printf("    -> [Detail] %d matching rows collapsed into %d unique spatial points.\n", len(I), realSpatialVolume)
		fmt.Printf("    -> [Detail] %d empty-region keys cover %d empty spatial points.\n", len(verificationEmptyKeys), coveredEmptyPoints)
		fmt.Printf("    -> [Detail] Maximum overlap multiplicity among selected cover blocks: %d.\n", maxOverlap)
		fmt.Printf("    -> [Detail] %d sampled verification keys successfully decrypted same-pattern WKD-IBE ciphertexts.\n", keyChecks)
	} else {
		if verifyErr != nil {
			fmt.Printf("[-] Client Empty-Key Check: FAILED! (%v)\n", verifyErr)
		} else if keyVerifyErr != nil {
			fmt.Printf("[-] Client Empty-Key Check: FAILED! (%v)\n", keyVerifyErr)
		} else {
			fmt.Printf("[-] Client Empty-Key Check: FAILED! (Empty: %d, Unique Real: %d, Target: %d)\n", coveredEmptyPoints, realSpatialVolume, totalQueryVolume)
		}
	}

	if *skipZK {
		return
	}

	fmt.Println("\n=== ENGINE B: ZK-ACCUMULATOR (Authenticity) ===")
	zkProverStart := time.Now()

	var transcript [32]byte
	var random mcl.Fr
	random.Random()

	I_poly := fft.PolyTree(I)
	C_I := bpacc.PedG2{Com: acc.PedersenG2(I_poly, acc.VK, random, acc.PedVK[0]), R: random}

	zkMemProof := acc.ZKMemProver(C_I, digest_X, transcript)
	zkDegProof := acc.ZKDegCheckProver(C_I, I_poly, zkMemProof.HashProof(transcript))

	zkProverMs := float64(time.Since(zkProverStart).Nanoseconds()) / 1e6
	zkMemSize := float64(zkMemProof.ByteSize()) / 1024.0
	zkDegSize := float64(zkDegProof.ByteSize()) / 1024.0

	fmt.Printf("[+] ZK Prover Time: %.2f ms\n", zkProverMs)
	fmt.Printf("[+] ZK Proof Size: %.2f KB (Mem) + %.2f KB (Deg) = %.2f KB\n", zkMemSize, zkDegSize, zkMemSize+zkDegSize)

	zkVerifierStart := time.Now()
	ok1 := acc.ZKMemVerifier(zkMemProof, digest_DB, C_I.Com, transcript)
	ok2 := acc.ZKDegCheckVerifier(C_I.Com, zkDegProof, zkMemProof.HashProof(transcript))
	zkVerifierMs := float64(time.Since(zkVerifierStart).Nanoseconds()) / 1e6
	if ok1 && ok2 {
		fmt.Printf("[+] Client ZK Verifier Time: %.2f ms (SUCCESS!)\n", zkVerifierMs)
	} else {
		fmt.Printf("[-] Client ZK Verifier: FAILED!\n")
	}

	fmt.Println("\n=== ULTIMATE ACADEMIC REPORT ===")
	fmt.Println("Architecture: M-HIBE Hexa-Sweep + Exact Minimum Key Cover + ZK-Accumulator")
	fmt.Printf("Total Server Proving Time: %.2f ms (%.2f s)\n", engineAMs+zkProverMs, (engineAMs+zkProverMs)/1000.0)
	fmt.Printf("Total Client Verification Time: %.2f ms\n", clientCheckMs+zkVerifierMs)
}
