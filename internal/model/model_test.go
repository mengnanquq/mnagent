package model

import (
	"testing"
	"time"
)

func TestJobTimeout(t *testing.T) {
	cases := []struct {
		name      string
		kind      string
		timeoutMS int64
		want      time.Duration
	}{
		{"less than min", "trace", 1000, JobMinTimeout},
		{"within normal", "trace", 30000, 30 * time.Second},
		{"exceed normal max", "trace", 1000000, JobMaxTimeout},
		{"miaospeed within range", "miaospeed", 3600000, 1 * time.Hour},
		{"miaospeed exceed max", "miaospeed", 20000000, JobMiaospeedMaxTimeout},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			j := Job{Kind: tc.kind, TimeoutMS: tc.timeoutMS}
			if got := j.Timeout(); got != tc.want {
				t.Errorf("Job.Timeout() = %v, want %v", got, tc.want)
			}
		})
	}
}
