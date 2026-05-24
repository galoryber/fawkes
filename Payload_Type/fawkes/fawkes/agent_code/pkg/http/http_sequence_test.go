package http

import (
	"sync"
	"testing"
)

func TestNextSeq_StartsAtOne(t *testing.T) {
	profile := &HTTPProfile{}
	seq := profile.nextSeq()
	if seq != 1 {
		t.Errorf("first seq = %d, want 1", seq)
	}
}

func TestNextSeq_Monotonic(t *testing.T) {
	profile := &HTTPProfile{}
	prev := profile.nextSeq()
	for i := 0; i < 100; i++ {
		next := profile.nextSeq()
		if next <= prev {
			t.Fatalf("seq %d not greater than prev %d at iteration %d", next, prev, i)
		}
		prev = next
	}
}

func TestNextSeq_ConcurrentSafety(t *testing.T) {
	profile := &HTTPProfile{}
	const goroutines = 10
	const perGoroutine = 100

	seen := make(map[uint64]bool)
	var mu sync.Mutex
	var wg sync.WaitGroup

	for g := 0; g < goroutines; g++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perGoroutine; i++ {
				seq := profile.nextSeq()
				mu.Lock()
				if seen[seq] {
					t.Errorf("duplicate seq %d", seq)
				}
				seen[seq] = true
				mu.Unlock()
			}
		}()
	}
	wg.Wait()

	expected := goroutines * perGoroutine
	if len(seen) != expected {
		t.Errorf("got %d unique seqs, want %d", len(seen), expected)
	}
}

func TestNextSeq_NeverZero(t *testing.T) {
	profile := &HTTPProfile{}
	for i := 0; i < 50; i++ {
		if seq := profile.nextSeq(); seq == 0 {
			t.Fatal("seq should never be 0 (reserved for backward compat)")
		}
	}
}
