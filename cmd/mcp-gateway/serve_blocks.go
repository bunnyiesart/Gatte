// The end of a block with -until (design/adr/0046 item 3), as serve keeps
// the trail of it.
//
// The expiry itself needs nothing from here: the gateway's admission check
// (accesssqlite.Store.Blocked) stops refusing at the block's end, to the
// instant. What this adds is the record. Once per maintenance round, every
// block whose end has passed is written to the trail as one
// (access block expired) row, attributed to (gateway), and only then
// removed -- the row first, like an unblock (design/adr/0031), so a block
// can never leave the list without the trail saying so. A row that cannot
// be written leaves the block listed as expired, and the next round tries
// again.

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	accesssqlite "github.com/bunnyiesart/Gatte/internal/access/sqlite"
	"github.com/bunnyiesart/Gatte/internal/admin"
	"github.com/bunnyiesart/Gatte/internal/audit"
)

// expiringBlocks is what the round needs of the blocklist.
type expiringBlocks interface {
	Expired(ctx context.Context) ([]access.Block, error)
	RemoveExpired(ctx context.Context, subject string, until time.Time) (bool, error)
}

// expiredBlockReason is the (access block expired) row's reason: the
// subject and the end, then who placed the block, when, and their note.
func expiredBlockReason(b access.Block) string {
	note := fmt.Sprintf("placed by %s at %s", b.By, b.At.UTC().Format(time.RFC3339))
	if b.Reason != "" {
		note += ": " + b.Reason
	}
	return admin.BlockReasonUntil(b.Subject, b.Until, note)
}

// expireBlocks records and removes every expired block. It returns how
// many were removed.
func (s *serveStack) expireBlocks(ctx context.Context, logger *slog.Logger) int {
	if s.blocks == nil || s.audit == nil {
		return 0
	}
	expired, err := s.blocks.Expired(ctx)
	if err != nil {
		logger.Error("mcp-gateway: could not read the blocklist for expired blocks; they stay listed and are retried next round",
			slog.String("detail", err.Error()))
		return 0
	}
	removed := 0
	for _, b := range expired {
		rec := audit.Record{AnalystIdentity: signalActor, Tool: admin.AccessBlockExpired, TargetUpstream: admin.OperatorTarget,
			Timestamp: time.Now().UTC(), Outcome: audit.OutcomeAllowed, Reason: expiredBlockReason(b)}
		if err := retryBusy(ctx, func() error { return s.audit.Record(ctx, rec) }); err != nil {
			logger.Error("mcp-gateway: the expiry of a block could not be recorded; the block stays listed as expired and is retried next round",
				slog.String("subject", b.Subject), slog.String("detail", err.Error()))
			continue
		}
		ok, err := s.blocks.RemoveExpired(ctx, b.Subject, b.Until)
		switch {
		case err != nil:
			logger.Error("mcp-gateway: an expired block was recorded and could not be removed; the next round records it again",
				slog.String("subject", b.Subject), slog.String("detail", err.Error()))
		case ok:
			removed++
			logger.Info("mcp-gateway: a block reached its end and was removed", slog.String("subject", b.Subject),
				slog.String("until", b.Until.UTC().Format(time.RFC3339)))
		}
	}
	return removed
}

// blocklist is the store the Gateway asks, kept for the round's sweep.
func (s *serveStack) blocklist(db *sql.DB) *accesssqlite.Store {
	st := accesssqlite.New(db)
	s.blocks = st
	return st
}
