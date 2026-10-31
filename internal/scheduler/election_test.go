package scheduler

import "testing"

func TestElectSender(t *testing.T) {
	now := int64(1_000_000_000)
	for _, tt := range []struct {
		name       string
		heartbeats map[string]Heartbeat
		want       string
	}{
		{name: "empty", heartbeats: nil, want: ""},
		{name: "single live", heartbeats: map[string]Heartbeat{"a": {Priority: 1, LastSeenUnixMilli: now}}, want: "a"},
		{name: "lowest priority wins", heartbeats: map[string]Heartbeat{
			"a": {Priority: 1, LastSeenUnixMilli: now},
			"b": {Priority: 2, LastSeenUnixMilli: now},
			"c": {Priority: 3, LastSeenUnixMilli: now},
		}, want: "a"},
		{name: "dead highest priority falls over to next", heartbeats: map[string]Heartbeat{
			"a": {Priority: 1, LastSeenUnixMilli: now - 151_000},
			"b": {Priority: 2, LastSeenUnixMilli: now},
			"c": {Priority: 3, LastSeenUnixMilli: now},
		}, want: "b"},
		{name: "all stale means no sender", heartbeats: map[string]Heartbeat{
			"a": {Priority: 1, LastSeenUnixMilli: now - 200_000},
		}, want: ""},
		{name: "staleness boundary is inclusive", heartbeats: map[string]Heartbeat{
			"a": {Priority: 1, LastSeenUnixMilli: now - 150_000},
		}, want: "a"},
		{name: "tie broken by smallest name", heartbeats: map[string]Heartbeat{
			"b": {Priority: 2, LastSeenUnixMilli: now},
			"a": {Priority: 2, LastSeenUnixMilli: now},
		}, want: "a"},
		{name: "slightly future heartbeat counts as live", heartbeats: map[string]Heartbeat{
			"a": {Priority: 1, LastSeenUnixMilli: now + 5_000},
		}, want: "a"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := ElectSender(tt.heartbeats, now); got != tt.want {
				t.Fatalf("ElectSender() = %q, want %q", got, tt.want)
			}
		})
	}
}
