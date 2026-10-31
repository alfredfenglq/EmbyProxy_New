package scheduler

import (
	"context"
	"time"

	"embyproxy/internal/logging"
	"embyproxy/internal/storage"
	"embyproxy/internal/telegram"
)

type Scheduler struct {
	log              *logging.Logger
	tg               *telegram.Service
	cleanup          func()
	store            *storage.Store
	instanceName     string
	instancePriority int
}

func New(log *logging.Logger, tg *telegram.Service, cleanup func()) *Scheduler {
	return &Scheduler{log: log, tg: tg, cleanup: cleanup}
}

// SetInstanceHeartbeat enables notification sender election for this
// instance. It must be called before Start. When it is never called (the
// historical single-machine setup), the scheduler keeps its old behaviour
// and always sends. A lower instancePriority number means a higher
// priority: configure A=1, B=2, C=3. Instance names must be unique per
// machine; the default comes from the hostname via INSTANCE_NAME.
func (s *Scheduler) SetInstanceHeartbeat(store *storage.Store, name string, priority int) {
	if s == nil {
		return
	}
	if name == "" {
		name = "embyproxy"
	}
	s.store = store
	s.instanceName = name
	s.instancePriority = priority
}

func (s *Scheduler) Start(ctx context.Context) {
	ticker := time.NewTicker(time.Minute)
	go func() {
		defer ticker.Stop()
		s.log.Debug("scheduler", "started", map[string]any{"event": "schedulerStarted"})
		for {
			select {
			case <-ctx.Done():
				s.log.Debug("scheduler", "stopped", map[string]any{"event": "schedulerStopped"})
				return
			case <-ticker.C:
				s.tick(ctx)
			}
		}
	}()
	if s.store != nil {
		go s.heartbeatLoop(ctx)
	}
}

func (s *Scheduler) heartbeatLoop(ctx context.Context) {
	// Write immediately so this instance is electable from startup, then
	// refresh on the regular interval. A missed write or two is tolerated
	// by the staleness window in ElectSender.
	if err := s.writeHeartbeat(ctx); err != nil {
		s.log.Error("scheduler", "heartbeat error", map[string]any{"event": "heartbeatError", "error": err.Error()})
	}
	ticker := time.NewTicker(heartbeatInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.writeHeartbeat(ctx); err != nil {
				s.log.Error("scheduler", "heartbeat error", map[string]any{"event": "heartbeatError", "error": err.Error()})
			}
		}
	}
}

func (s *Scheduler) writeHeartbeat(ctx context.Context) error {
	if s == nil || s.store == nil {
		return nil
	}
	return s.store.KV().Put(ctx, heartbeatKey(s.instanceName), Heartbeat{
		Priority:          s.instancePriority,
		LastSeenUnixMilli: time.Now().UnixMilli(),
	})
}

// shouldSendNotifications reports whether this instance is the elected
// notification sender. Election is not configured (no store) on a single
// machine, which keeps the historical behaviour of always sending. On an
// election read failure it returns false: fail-closed, so a database
// hiccup can delay notifications but can never duplicate them.
func (s *Scheduler) shouldSendNotifications(ctx context.Context) bool {
	if s == nil || s.store == nil {
		return true
	}
	heartbeats, err := ReadHeartbeats(ctx, s.store)
	if err != nil {
		s.log.Error("scheduler", "sender election failed, skipping notifications", map[string]any{"event": "senderElectionFailed", "error": err.Error()})
		return false
	}
	sender := ElectSender(heartbeats, time.Now().UnixMilli())
	if sender != s.instanceName {
		s.log.Debug("scheduler", "not notification sender, skipping notifications", map[string]any{"event": "notificationSenderSkipped", "sender": sender, "instance": s.instanceName})
		return false
	}
	return true
}

func (s *Scheduler) tick(ctx context.Context) {
	if s.cleanup != nil {
		func() {
			defer func() {
				if recover() != nil {
					s.log.Error("scheduler", "cleanup panic", map[string]any{"event": "cleanupPanic"})
				}
			}()
			s.cleanup()
		}()
	}
	// Local cleanup always runs on every machine. Notifications, by
	// contrast, are gated on sender election so that in a multi-machine
	// deployment exactly one instance sends them.
	if !s.shouldSendNotifications(ctx) {
		return
	}
	if err := s.tg.CheckAndSendReport(ctx); err != nil {
		s.log.Error("scheduler", "report error", map[string]any{"event": "reportError", "error": err.Error()})
	}
	if err := s.tg.CheckKeepaliveAndNotify(ctx); err != nil {
		s.log.Error("scheduler", "keepalive error", map[string]any{"event": "keepaliveError", "error": err.Error()})
	}
}
