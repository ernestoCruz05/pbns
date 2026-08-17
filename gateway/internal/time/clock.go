package time

import (
	"errors"
	stdtime "time"
	"unicode/utf8"
)

var ErrInvalidClock = errors.New("invalid trusted-time clock configuration")

type Clock interface {
	Now() stdtime.Time
	MonotonicNow() stdtime.Duration
	Uncertainty() stdtime.Duration
	Quality() string
}

type SystemClock struct {
	origin      stdtime.Time
	uncertainty stdtime.Duration
	quality     string
}

func NewSystemClock(uncertainty stdtime.Duration, quality string) (*SystemClock, error) {
	if uncertainty < 0 || quality == "" || len(quality) > 64 || !utf8.ValidString(quality) {
		return nil, ErrInvalidClock
	}
	return &SystemClock{origin: stdtime.Now(), uncertainty: uncertainty, quality: quality}, nil
}

func (clock *SystemClock) Now() stdtime.Time { return stdtime.Now().UTC() }

func (clock *SystemClock) MonotonicNow() stdtime.Duration { return stdtime.Since(clock.origin) }

func (clock *SystemClock) Uncertainty() stdtime.Duration { return clock.uncertainty }

func (clock *SystemClock) Quality() string { return clock.quality }
