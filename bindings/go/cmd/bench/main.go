// Timing line for the Go binding, in the same shape as the native baseline:
//
//	go <op> <param> <milliseconds> <iterations>
//
// Run with `cd bindings/go && go run ./cmd/bench [iterations]`.
package main

import (
	"bytes"
	"fmt"
	"os"
	"strconv"
	"time"

	dreggsig "github.com/emberian/dregg-sig/bindings/go"
)

func bench(param uint32, label string, iters int) {
	n := dreggsig.PKBytes(param) / 2
	skSeed := bytes.Repeat([]byte{0x11}, n)
	skPrf := bytes.Repeat([]byte{0x22}, n)
	pkSeed := bytes.Repeat([]byte{0x33}, n)
	msg := []byte("dregg-sig binding timing")

	sk, pk, err := dreggsig.Keygen(param, skSeed, skPrf, pkSeed)
	if err != nil {
		panic(err)
	}
	sig, err := dreggsig.Sign(param, sk, msg, nil)
	if err != nil {
		panic(err)
	}
	if err := dreggsig.Verify(param, pk, msg, nil, sig); err != nil {
		panic(err)
	}

	t := time.Now()
	for i := 0; i < iters; i++ {
		if _, _, err := dreggsig.Keygen(param, skSeed, skPrf, pkSeed); err != nil {
			panic(err)
		}
	}
	fmt.Printf("go keygen %s %.3f %d\n", label, float64(time.Since(t).Microseconds())/1000.0, iters)

	t = time.Now()
	for i := 0; i < iters; i++ {
		if _, err := dreggsig.Sign(param, sk, msg, nil); err != nil {
			panic(err)
		}
	}
	fmt.Printf("go sign %s %.3f %d\n", label, float64(time.Since(t).Microseconds())/1000.0, iters)

	t = time.Now()
	for i := 0; i < iters; i++ {
		if err := dreggsig.Verify(param, pk, msg, nil, sig); err != nil {
			panic(err)
		}
	}
	fmt.Printf("go verify %s %.3f %d\n", label, float64(time.Since(t).Microseconds())/1000.0, iters)
}

func main() {
	iters := 3
	if len(os.Args) > 1 {
		if v, err := strconv.Atoi(os.Args[1]); err == nil {
			iters = v
		}
	}
	bench(dreggsig.Param128f, "128f", iters)
	bench(dreggsig.Param128s, "128s", iters)
}
