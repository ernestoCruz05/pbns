package time

import (
	"testing"
	stdtime "time"
)

func TestSystemClockConfiguration(t *testing.T) {
	clock, err := NewSystemClock(25*stdtime.Millisecond, "chrony-synchronized")
	if err != nil {
		t.Fatal(err)
	}
	if clock.Uncertainty() != 25*stdtime.Millisecond || clock.Quality() != "chrony-synchronized" {
		t.Fatal("clock metadata was not retained")
	}
	before := clock.MonotonicNow()
	_ = clock.Now()
	after := clock.MonotonicNow()
	if after < before {
		t.Fatal("monotonic clock regressed")
	}
	if _, err := NewSystemClock(-1, "chrony"); err == nil {
		t.Fatal("negative uncertainty accepted")
	}
	if _, err := NewSystemClock(0, ""); err == nil {
		t.Fatal("empty quality accepted")
	}
}
