//go:build ignore
// +build ignore

package main

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/accumulators-agg/bp/bpacc"
	"github.com/accumulators-agg/go-poly/fft"
	"github.com/alinush/go-mcl"
)

const (
	NumDims   = 3
	BitLength = 12
)

type Point struct{ Coords [NumDims]int64 }
type RangeQuery struct{ Bounds [NumDims][2]int64 }

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

func loadQueryPartition(query RangeQuery) (int, []mcl.Fr, []mcl.Fr, []mcl.Fr, error) {
	file, err := os.Open("/home/xing/poneglyphdb/src/data/lineitem_120K.tbl")
	if err != nil {
		return 0, nil, nil, nil, err
	}
	defer file.Close()

	var dbFr []mcl.Fr
	var I []mcl.Fr
	var X []mcl.Fr
	var totalRows int

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

		fr := bpacc.SeedToFr(FormatPointToBinary(p))
		dbFr = append(dbFr, fr)
		totalRows++

		if IsPointInQuery(p, query) {
			I = append(I, fr)
		} else {
			X = append(X, fr)
		}
	}

	if err := scanner.Err(); err != nil {
		return 0, nil, nil, nil, err
	}
	return totalRows, dbFr, I, X, nil
}

func main() {
	fmt.Println("[*] Starting Native ZK-Accumulator Baseline Benchmark...")
	fmt.Println("[*] Mode: No Prefix Cover / No Empty-Region Extraction")
	fmt.Println("[*] Completeness Baseline: Public complement partition (I and X) only")

	mcl.InitFromString("bls12-381")

	setupStart := time.Now()
	var acc bpacc.BpAcc
	acc.KeyGenLoad(8, 17, "my_secure_seed", "./pkvk-17")
	setupMs := float64(time.Since(setupStart).Nanoseconds()) / 1e6

	var query RangeQuery
	query.Bounds[0] = [2]int64{ParseDate("1994-01-01"), ParseDate("1994-12-31")}
	query.Bounds[1] = [2]int64{5, 7}
	query.Bounds[2] = [2]int64{0, 23}

	loadStart := time.Now()
	totalRows, dbFr, I, X, err := loadQueryPartition(query)
	if err != nil {
		panic(err)
	}
	loadMs := float64(time.Since(loadStart).Nanoseconds()) / 1e6

	if len(I) == 0 || len(X) == 0 {
		panic("benchmark expects both hit set I and complement set X to be non-empty")
	}

	fmt.Printf("[*] Global Setup Time: %.2f ms\n", setupMs)
	fmt.Printf("[*] Data Load + Direct Partition Time: %.2f ms\n", loadMs)
	fmt.Printf("[*] Loaded %d real TPC-H rows.\n", totalRows)
	fmt.Printf("[*] Query matched %d rows; complement contains %d rows.\n", len(I), len(X))

	commitStart := time.Now()
	digestDB, _ := acc.CommitFakeG1(dbFr)
	digestI, _ := acc.CommitFakeG1(I)
	digestX, _ := acc.CommitFakeG1(X)
	commitMs := float64(time.Since(commitStart).Nanoseconds()) / 1e6
	fmt.Printf("[*] Commitment Time (DB + I + X): %.2f ms\n", commitMs)

	// ========================================================
	// Proof A: Correctness
	// Prove the returned result set I is a subset of DB.
	// ========================================================
	fmt.Println("\n=== PROOF A: ZK-Membership for Correctness (I subset of DB) ===")

	var transcriptCorrect [32]byte
	var randI mcl.Fr
	randI.Random()

	Ipoly := fft.PolyTree(I)
	CI := bpacc.PedG2{
		Com: acc.PedersenG2(Ipoly, acc.VK, randI, acc.PedVK[0]),
		R:   randI,
	}

	correctStart := time.Now()
	zkMemProofI := acc.ZKMemProver(CI, digestX, transcriptCorrect)
	zkDegProofI := acc.ZKDegCheckProver(CI, Ipoly, zkMemProofI.HashProof(transcriptCorrect))
	correctProverMs := float64(time.Since(correctStart).Nanoseconds()) / 1e6

	correctVerifyStart := time.Now()
	correctOK1 := acc.ZKMemVerifier(zkMemProofI, digestDB, CI.Com, transcriptCorrect)
	correctOK2 := acc.ZKDegCheckVerifier(CI.Com, zkDegProofI, zkMemProofI.HashProof(transcriptCorrect))
	correctVerifyMs := float64(time.Since(correctVerifyStart).Nanoseconds()) / 1e6

	correctSizeKB := float64(zkMemProofI.ByteSize()+zkDegProofI.ByteSize()) / 1024.0
	fmt.Printf("Proof time: %.2f ms\n", correctProverMs)
	fmt.Printf("Verify time: %.2f ms\n", correctVerifyMs)
	fmt.Printf("Proof size: %.2f KB\n", correctSizeKB)
	fmt.Printf("Status: %v\n", correctOK1 && correctOK2)

	// ========================================================
	// Proof B: Completeness Baseline (Coverage)
	// Prove the public complement X is also a subset of DB.
	// ========================================================
	fmt.Println("\n=== PROOF B: ZK-Membership for Coverage (X subset of DB) ===")

	var transcriptCover [32]byte
	var randX mcl.Fr
	randX.Random()

	Xpoly := fft.PolyTree(X)
	CX := bpacc.PedG2{
		Com: acc.PedersenG2(Xpoly, acc.VK, randX, acc.PedVK[0]),
		R:   randX,
	}

	coverStart := time.Now()
	zkMemProofX := acc.ZKMemProver(CX, digestI, transcriptCover)
	zkDegProofX := acc.ZKDegCheckProver(CX, Xpoly, zkMemProofX.HashProof(transcriptCover))
	coverProverMs := float64(time.Since(coverStart).Nanoseconds()) / 1e6

	coverVerifyStart := time.Now()
	coverOK1 := acc.ZKMemVerifier(zkMemProofX, digestDB, CX.Com, transcriptCover)
	coverOK2 := acc.ZKDegCheckVerifier(CX.Com, zkDegProofX, zkMemProofX.HashProof(transcriptCover))
	coverVerifyMs := float64(time.Since(coverVerifyStart).Nanoseconds()) / 1e6

	coverSizeKB := float64(zkMemProofX.ByteSize()+zkDegProofX.ByteSize()) / 1024.0
	fmt.Printf("Proof time: %.2f ms\n", coverProverMs)
	fmt.Printf("Verify time: %.2f ms\n", coverVerifyMs)
	fmt.Printf("Proof size: %.2f KB\n", coverSizeKB)
	fmt.Printf("Status: %v\n", coverOK1 && coverOK2)

	// ========================================================
	// Proof C: Completeness Baseline (Disjointness)
	// Prove I and X are disjoint as sets.
	// ========================================================
	fmt.Println("\n=== PROOF C: ZK-NonMembership for Disjointness (I disjoint from X) ===")

	var transcriptDisjoint [32]byte

	disjointStart := time.Now()
	A, B := acc.ProveBatchNonMemFake(X, I)
	zkNonMemProof := acc.ZKNonMemProver(digestX, CI, A, B, transcriptDisjoint)
	zkDegNonMemProof := acc.ZKDegCheckProver(CI, Ipoly, zkNonMemProof.HashProof(transcriptDisjoint))
	disjointProverMs := float64(time.Since(disjointStart).Nanoseconds()) / 1e6

	disjointVerifyStart := time.Now()
	disjointOK1 := acc.ZKNonMemVerifier(zkNonMemProof, digestX, CI.Com, transcriptDisjoint)
	disjointOK2 := acc.ZKDegCheckVerifier(CI.Com, zkDegNonMemProof, zkNonMemProof.HashProof(transcriptDisjoint))
	disjointVerifyMs := float64(time.Since(disjointVerifyStart).Nanoseconds()) / 1e6

	disjointSizeKB := float64(zkNonMemProof.ByteSize()+zkDegNonMemProof.ByteSize()) / 1024.0
	fmt.Printf("Proof time: %.2f ms\n", disjointProverMs)
	fmt.Printf("Verify time: %.2f ms\n", disjointVerifyMs)
	fmt.Printf("Proof size: %.2f KB\n", disjointSizeKB)
	fmt.Printf("Status: %v\n", disjointOK1 && disjointOK2)

	partitionCountOK := len(I)+len(X) == len(dbFr)
	completenessBaselineOK := (coverOK1 && coverOK2) && (disjointOK1 && disjointOK2) && partitionCountOK
	overallOK := (correctOK1 && correctOK2) && completenessBaselineOK

	totalServerMs := commitMs + correctProverMs + coverProverMs + disjointProverMs
	totalClientMs := correctVerifyMs + coverVerifyMs + disjointVerifyMs

	fmt.Println("\n=== FINAL NATIVE ZK-ACCUMULATOR REPORT ===")
	fmt.Printf("No prefix cover / no empty-region extraction: true\n")
	fmt.Printf("Partition sanity check |I| + |X| == |DB|: %v\n", partitionCountOK)
	fmt.Printf("Correctness (I subset DB): %v\n", correctOK1 && correctOK2)
	fmt.Printf("Completeness baseline (X subset DB && I disjoint X): %v\n", completenessBaselineOK)
	fmt.Printf("Overall baseline status: %v\n", overallOK)
	fmt.Printf("Total prover time: %.2f ms\n", totalServerMs)
	fmt.Printf("Total verifier time: %.2f ms\n", totalClientMs)
	fmt.Println("[*] Note: This benchmark uses a public complement partition and does not implement private geometric completeness.")
}
