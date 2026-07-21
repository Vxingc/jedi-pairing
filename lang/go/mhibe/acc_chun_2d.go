//go:build ignore
// +build ignore

package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/accumulators-agg/bp/bpacc"
	"github.com/accumulators-agg/go-poly/fft"
	"github.com/alinush/go-mcl"
)

const (
	NumDims   = 2
	BitLength = 12
)

type Point struct{ Coords [NumDims]int64 }
type RangeQuery struct{ Bounds [NumDims][2]int64 }

type loadedPartition struct {
	dbFr              []mcl.Fr
	hitFr             []mcl.Fr
	missFr            []mcl.Fr
	queryUniquePoints map[[NumDims]int64]struct{}
	rows              int
	hitRows           int
}

type proofMetrics struct {
	proverMs   float64
	verifierMs float64
	sizeKB     float64
	ok         bool
	skipped    bool
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

func FormatPointToBinary(p Point) string {
	var b strings.Builder
	for i := 0; i < NumDims; i++ {
		b.WriteString(fmt.Sprintf("%0*b", BitLength, p.Coords[i]))
	}
	return b.String()
}

func IsPointInQuery(p Point, q RangeQuery) bool {
	for i := 0; i < NumDims; i++ {
		if p.Coords[i] < q.Bounds[i][0] || p.Coords[i] > q.Bounds[i][1] {
			return false
		}
	}
	return true
}

func queryVolume(query RangeQuery) (int64, error) {
	volume := int64(1)
	for d := 0; d < NumDims; d++ {
		lo, hi := query.Bounds[d][0], query.Bounds[d][1]
		if lo < 0 || hi < lo {
			return 0, fmt.Errorf("invalid query bounds on dim %d: [%d, %d]", d, lo, hi)
		}
		if hi >= 1<<BitLength {
			return 0, fmt.Errorf("query bound %d exceeds %d-bit domain", hi, BitLength)
		}
		volume *= hi - lo + 1
	}
	return volume, nil
}

func forEachPointInBounds(bounds [NumDims][2]int64, visit func(Point) error) error {
	var p Point
	var walk func(int) error
	walk = func(dim int) error {
		if dim == NumDims {
			return visit(p)
		}
		for v := bounds[dim][0]; v <= bounds[dim][1]; v++ {
			p.Coords[dim] = v
			if err := walk(dim + 1); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(0)
}

func loadTPCPartition(dataPath string, limit int, discountScale int64, query RangeQuery) (loadedPartition, error) {
	file, err := os.Open(dataPath)
	if err != nil {
		return loadedPartition{}, err
	}
	defer file.Close()

	part := loadedPartition{
		queryUniquePoints: make(map[[NumDims]int64]struct{}),
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		if limit > 0 && part.rows >= limit {
			break
		}
		cols := strings.Split(scanner.Text(), "|")
		if len(cols) < 11 {
			continue
		}

		var p Point
		dFloat, err := strconv.ParseFloat(cols[6], 64)
		if err != nil {
			return loadedPartition{}, fmt.Errorf("parse l_discount in row %d: %w", part.rows+1, err)
		}
		p.Coords[0] = ParseDate(cols[10])
		p.Coords[1] = int64(math.Round(dFloat * float64(discountScale)))

		fr := bpacc.SeedToFr(FormatPointToBinary(p))
		part.dbFr = append(part.dbFr, fr)
		part.rows++

		if IsPointInQuery(p, query) {
			part.hitFr = append(part.hitFr, fr)
			part.queryUniquePoints[p.Coords] = struct{}{}
			part.hitRows++
		} else {
			part.missFr = append(part.missFr, fr)
		}
	}
	if err := scanner.Err(); err != nil {
		return loadedPartition{}, err
	}
	return part, nil
}

func enumerateEmptyQueryPoints(query RangeQuery, realPoints map[[NumDims]int64]struct{}) ([]mcl.Fr, int64, error) {
	empty := make([]mcl.Fr, 0)
	var count int64
	err := forEachPointInBounds(query.Bounds, func(p Point) error {
		if _, ok := realPoints[p.Coords]; ok {
			return nil
		}
		empty = append(empty, bpacc.SeedToFr(FormatPointToBinary(p)))
		count++
		return nil
	})
	return empty, count, err
}

func nextPowerOfTwo(n int) int {
	if n <= 1 {
		return 1
	}
	pow := 1
	for pow < n {
		pow <<= 1
	}
	return pow
}

func frSetKey(fr mcl.Fr) string {
	return fr.GetString(10)
}

func padNonMembersToPowerOfTwo(dbSet, emptySet []mcl.Fr) []mcl.Fr {
	target := nextPowerOfTwo(len(emptySet))
	if len(emptySet) == target {
		return emptySet
	}

	seen := make(map[string]struct{}, len(dbSet)+target)
	for _, fr := range dbSet {
		seen[frSetKey(fr)] = struct{}{}
	}
	padded := append([]mcl.Fr(nil), emptySet...)
	for _, fr := range padded {
		seen[frSetKey(fr)] = struct{}{}
	}

	for nonce := 0; len(padded) < target; nonce++ {
		fr := bpacc.SeedToFr(fmt.Sprintf("__zkacc_pad_2d_%d", nonce))
		key := frSetKey(fr)
		if _, ok := seen[key]; ok {
			continue
		}
		padded = append(padded, fr)
		seen[key] = struct{}{}
	}
	return padded
}

func proveCorrectness(acc *bpacc.BpAcc, digestDB, digestComplement mcl.G1, hitSet []mcl.Fr) proofMetrics {
	if len(hitSet) == 0 {
		return proofMetrics{ok: true, skipped: true}
	}

	var transcript [32]byte
	var random mcl.Fr
	random.Random()

	hitPoly := fft.PolyTree(hitSet)
	commitHit := bpacc.PedG2{Com: acc.PedersenG2(hitPoly, acc.VK, random, acc.PedVK[0]), R: random}

	proverStart := time.Now()
	zkMemProof := acc.ZKMemProver(commitHit, digestComplement, transcript)
	zkDegProof := acc.ZKDegCheckProver(commitHit, hitPoly, zkMemProof.HashProof(transcript))
	proverMs := float64(time.Since(proverStart).Nanoseconds()) / 1e6

	verifierStart := time.Now()
	ok1 := acc.ZKMemVerifier(zkMemProof, digestDB, commitHit.Com, transcript)
	ok2 := acc.ZKDegCheckVerifier(commitHit.Com, zkDegProof, zkMemProof.HashProof(transcript))
	verifierMs := float64(time.Since(verifierStart).Nanoseconds()) / 1e6

	return proofMetrics{
		proverMs:   proverMs,
		verifierMs: verifierMs,
		sizeKB:     float64(zkMemProof.ByteSize()+zkDegProof.ByteSize()) / 1024.0,
		ok:         ok1 && ok2,
	}
}

func proveCompleteness(acc *bpacc.BpAcc, digestDB mcl.G1, dbSet, emptySet []mcl.Fr, proofMode string) proofMetrics {
	if len(emptySet) == 0 {
		return proofMetrics{ok: true, skipped: true}
	}

	var transcript [32]byte
	var random mcl.Fr
	random.Random()

	proverStart := time.Now()
	var A mcl.G2
	var B mcl.G1
	var emptyPoly []mcl.Fr
	switch proofMode {
	case "trapdoor":
		A, B = acc.ProveBatchNonMemFake(dbSet, emptySet)
		emptyPoly = fft.PolyTree(emptySet)
	case "real":
		paddedEmptySet := padNonMembersToPowerOfTwo(dbSet, emptySet)
		if len(paddedEmptySet) != len(emptySet) {
			fmt.Printf("[*] Real aggregation padding: |E| %d -> %d non-members\n", len(emptySet), len(paddedEmptySet))
		}
		nonMemProofs := acc.NonMemProve(dbSet, paddedEmptySet)
		A, B, emptyPoly = acc.AggNonMemProve(paddedEmptySet, nonMemProofs)
	default:
		panic(fmt.Sprintf("unknown proof mode %q", proofMode))
	}
	commitEmpty := bpacc.PedG2{Com: acc.PedersenG2(emptyPoly, acc.VK, random, acc.PedVK[0]), R: random}
	zkNonMemProof := acc.ZKNonMemProver(digestDB, commitEmpty, A, B, transcript)
	zkDegProof := acc.ZKDegCheckProver(commitEmpty, emptyPoly, zkNonMemProof.HashProof(transcript))
	proverMs := float64(time.Since(proverStart).Nanoseconds()) / 1e6

	verifierStart := time.Now()
	ok1 := acc.ZKNonMemVerifier(zkNonMemProof, digestDB, commitEmpty.Com, transcript)
	ok2 := acc.ZKDegCheckVerifier(commitEmpty.Com, zkDegProof, zkNonMemProof.HashProof(transcript))
	verifierMs := float64(time.Since(verifierStart).Nanoseconds()) / 1e6

	return proofMetrics{
		proverMs:   proverMs,
		verifierMs: verifierMs,
		sizeKB:     float64(zkNonMemProof.ByteSize()+zkDegProof.ByteSize()) / 1024.0,
		ok:         ok1 && ok2,
	}
}

func main() {
	dataPath := flag.String("data", "/home/xing/poneglyphdb/src/data/lineitem_120K.tbl", "TPC-H lineitem .tbl file")
	keyDir := flag.String("keys", "./pkvk-17", "ZK accumulator proving/verifying key directory")
	proofMode := flag.String("proof-mode", "trapdoor", "witness mode: trapdoor uses CommitFakeG1/ProveBatchNonMemFake; real uses Commit/NonMemProve/AggNonMemProve")
	limit := flag.Int("limit", 0, "maximum number of lineitem rows to load; 0 means all rows")
	poneglyphQ6 := flag.Bool("poneglyph-q6", false, "use PoneglyphDB q6_final_v2 projected 2D bounds: 1994-01-01 < shipdate < 1995-01-01 and 0.05 < discount < 0.07")
	dateMin := flag.String("date-min", "1994-01-01", "inclusive shipdate lower bound for this benchmark")
	dateMax := flag.String("date-max", "1994-12-31", "inclusive shipdate upper bound for this benchmark")
	discountScale := flag.Int64("discount-scale", 100, "scale factor for encoding l_discount from the .tbl file")
	discountMin := flag.Int64("discount-min", 5, "inclusive encoded l_discount lower bound")
	discountMax := flag.Int64("discount-max", 7, "inclusive encoded l_discount upper bound")
	flag.Parse()

	if *poneglyphQ6 {
		*dateMin = "1994-01-02"
		*dateMax = "1994-12-31"
		encodedDiscount := int64(math.Round(0.06 * float64(*discountScale)))
		*discountMin = encodedDiscount
		*discountMax = encodedDiscount
		if *limit == 0 {
			*limit = 120000
		}
	}

	query := RangeQuery{}
	query.Bounds[0] = [2]int64{ParseDate(*dateMin), ParseDate(*dateMax)}
	query.Bounds[1] = [2]int64{*discountMin, *discountMax}
	volume, err := queryVolume(query)
	if err != nil {
		panic(err)
	}

	fmt.Println("[*] Starting Native ZK-Accumulator Baseline Benchmark...")
	fmt.Println("[*] Mode: 2D full correctness + full completeness")
	fmt.Printf("[*] Accumulator proof mode: %s\n", *proofMode)
	fmt.Printf("[*] Data Path: %s\n", *dataPath)
	if *limit > 0 {
		fmt.Printf("[*] Row Limit: first %d lineitem rows\n", *limit)
	}
	fmt.Printf("[*] Query Bounds: shipdate [%s, %s], encoded discount [%d, %d] (scale=%d)\n",
		*dateMin, *dateMax, *discountMin, *discountMax, *discountScale)
	fmt.Printf("[*] Full query volume: %d points\n", volume)

	mcl.InitFromString("bls12-381")

	setupStart := time.Now()
	var acc bpacc.BpAcc
	acc.KeyGenLoad(8, 17, "my_secure_seed", *keyDir)
	setupMs := float64(time.Since(setupStart).Nanoseconds()) / 1e6

	loadStart := time.Now()
	part, err := loadTPCPartition(*dataPath, *limit, *discountScale, query)
	if err != nil {
		panic(err)
	}
	loadMs := float64(time.Since(loadStart).Nanoseconds()) / 1e6
	if len(part.dbFr) == 0 {
		panic(errors.New("empty database after loading"))
	}

	emptyStart := time.Now()
	emptySet, emptyPointCount, err := enumerateEmptyQueryPoints(query, part.queryUniquePoints)
	if err != nil {
		panic(err)
	}
	emptyEnumMs := float64(time.Since(emptyStart).Nanoseconds()) / 1e6

	partitionOK := int64(len(part.queryUniquePoints))+emptyPointCount == volume
	if !partitionOK {
		panic("query partition sanity check failed")
	}

	fmt.Printf("[*] Global Setup Time: %.2f ms\n", setupMs)
	fmt.Printf("[*] Data Load + Direct Partition Time: %.2f ms\n", loadMs)
	fmt.Printf("[*] Loaded %d real TPC-H rows.\n", part.rows)
	fmt.Printf("[*] Query matched %d rows, collapsed into %d unique 2D points.\n",
		part.hitRows, len(part.queryUniquePoints))
	fmt.Printf("[*] Full completeness empty-set enumeration: %d points in %.2f ms\n",
		emptyPointCount, emptyEnumMs)

	commitStart := time.Now()
	var digestDB mcl.G1
	var digestComplement mcl.G1
	switch *proofMode {
	case "trapdoor":
		digestDB, _ = acc.CommitFakeG1(part.dbFr)
		digestComplement, _ = acc.CommitFakeG1(part.missFr)
	case "real":
		digestDB, _ = acc.Commit(part.dbFr)
		digestComplement, _ = acc.Commit(part.missFr)
	default:
		panic(fmt.Sprintf("unknown proof mode %q", *proofMode))
	}
	commitMs := float64(time.Since(commitStart).Nanoseconds()) / 1e6
	fmt.Printf("[*] Commitment Time (DB + DB\\I): %.2f ms\n", commitMs)
	if *proofMode == "trapdoor" {
		fmt.Println("[*] Warning: trapdoor mode is compatible with existing cmd_bench_* ZK calls, but it is not the slow honest non-membership witness generation path.")
	}

	fmt.Println("\n=== PROOF A: ZK-Membership for Correctness (I subset DB) ===")
	correct := proveCorrectness(&acc, digestDB, digestComplement, part.hitFr)
	if correct.skipped {
		fmt.Println("Status: true (empty returned set, vacuous)")
	} else {
		fmt.Printf("Proof time: %.2f ms\n", correct.proverMs)
		fmt.Printf("Verify time: %.2f ms\n", correct.verifierMs)
		fmt.Printf("Proof size: %.2f KB\n", correct.sizeKB)
		fmt.Printf("Status: %v\n", correct.ok)
	}

	fmt.Println("\n=== PROOF B: ZK-NonMembership for Full Completeness (E disjoint DB) ===")
	fmt.Printf("[*] E contains every query point not returned by I: |E|=%d\n", len(emptySet))
	complete := proveCompleteness(&acc, digestDB, part.dbFr, emptySet, *proofMode)
	if complete.skipped {
		fmt.Println("Status: true (query range has no empty points)")
	} else {
		fmt.Printf("Proof time: %.2f ms\n", complete.proverMs)
		fmt.Printf("Verify time: %.2f ms\n", complete.verifierMs)
		fmt.Printf("Proof size: %.2f KB\n", complete.sizeKB)
		fmt.Printf("Status: %v\n", complete.ok)
	}

	totalServerMs := emptyEnumMs + commitMs + correct.proverMs + complete.proverMs
	totalClientMs := correct.verifierMs + complete.verifierMs
	overallOK := partitionOK && correct.ok && complete.ok

	fmt.Println("\n=== FINAL NATIVE ZK-ACCUMULATOR REPORT ===")
	fmt.Println("Architecture: 2D Native ZK-Accumulator Full Correctness + Full Completeness Baseline")
	fmt.Printf("Query partition sanity |unique(I)| + |E| == |Q|: %v\n", partitionOK)
	fmt.Printf("Correctness (I subset DB): %v\n", correct.ok)
	fmt.Printf("Completeness (every point in Q\\I is non-member of DB): %v\n", complete.ok)
	fmt.Printf("Overall baseline status: %v\n", overallOK)
	fmt.Printf("Total server proving time: %.2f ms (%.2f s)\n", totalServerMs, totalServerMs/1000.0)
	fmt.Printf("Total client verification time: %.2f ms\n", totalClientMs)
	fmt.Printf("Total proof size: %.2f KB\n", correct.sizeKB+complete.sizeKB)
}
