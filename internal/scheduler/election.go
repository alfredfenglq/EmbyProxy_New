package scheduler

import (
	"context"
	"strings"
	"time"

	"embyproxy/internal/storage"
)

// Notification sender election.
//
// Every instance writes its own heartbeat into the shared key/value store
// every 30 seconds (see Scheduler.writeHeartbeat). The scheduler tick only
// sends the daily report and the keepalive reminders when this instance is
// the elected sender, so in a multi-machine deployment exactly one machine
// sends notifications while the priority order A > B > C is honoured:
// a lower priority number wins, and when machine A is alive it always wins
// over B and C. When A stops heartbeating, B takes over automatically, and
// A resumes sending once it is alive again. On a single machine the
// instance is its own only heartbeat, so behaviour is unchanged.
//
// The heartbeat keys live in proxy_kv, so the election works identically on
// SQLite and PostgreSQL with no extra tables.

const heartbeatKeyPrefix = "instance:heartbeat:"

// heartbeatInterval is how often an instance refreshes its own heartbeat.
const heartbeatInterval = 30 * time.Second

// heartbeatStaleWindowMillis is how old a heartbeat may be before its
// instance counts as dead. It is five heartbeat intervals, so a single
// missed write (for example during a brief database hiccup) does not
// immediately hand the sender role to another machine.
const heartbeatStaleWindowMillis = 150 * 1000

// Heartbeat is the value stored under instance:heartbeat:<INSTANCE_NAME>.
type Heartbeat struct {
	Priority          int   `json:"priority"`
	LastSeenUnixMilli int64 `json:"lastSeenUnixMilli"`
}

func heartbeatKey(name string) string {
	return heartbeatKeyPrefix + name
}

// ElectSender picks the notification sender from a set of heartbeats. It
// is a pure function so the rule is unit-testable without a database.
// Freshness: a heartbeat counts as live when it is at most
// heartbeatStaleWindowMillis old; a LastSeen slightly in the future
// (clock skew) yields a negative age and therefore also counts as live, so
// a fast clock cannot disqualify a live instance. Winner: smallest
// priority number, ties broken by the smallest instance name. With no live
// heartbeat the result is "" (no sender).
func ElectSender(heartbeats map[string]Heartbeat, nowUnixMilli int64) string {
	best := ""
	bestPriority := 0
	for name, hb := range heartbeats {
		if nowUnixMilli-hb.LastSeenUnixMilli > heartbeatStaleWindowMillis {
			continue
		}
		if best == "" || hb.Priority < bestPriority || (hb.Priority == bestPriority && name < best) {
			best = name
			bestPriority = hb.Priority
		}
	}
	return best
}

// ReadHeartbeats reads every instance heartbeat from the store.
func ReadHeartbeats(ctx context.Context, store *storage.Store) (map[string]Heartbeat, error) {
	out := map[string]Heartbeat{}
	cursor := 0
	for {
		res, err := store.KV().List(ctx, heartbeatKeyPrefix, cursor, 1000)
		if err != nil {
			return nil, err
		}
		for _, key := range res.Keys {
			name := strings.TrimPrefix(key, heartbeatKeyPrefix)
			var hb Heartbeat
			ok, err := store.KV().GetJSON(ctx, key, &hb)
			if err != nil {
				return nil, err
			}
			if ok {
				out[name] = hb
			}
		}
		if res.ListComplete {
			break
		}
		cursor = res.Cursor
	}
	return out, nil
}
