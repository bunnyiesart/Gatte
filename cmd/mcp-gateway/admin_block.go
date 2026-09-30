// Operator Console -- "admin -block-writer": the gateway block of an
// offboard, placed from the accounts socket (design/adr/0046 item 2).
//
// `admin -accounts` runs as root and never opens a file of the service
// account (design/adr/0040 §1). An offboard blocks the person's subject,
// and the blocklist lives in the service account's database, so the block
// is placed the way the rows are written: by a short-lived child running
// as the database's owner, which reads one block on standard input, places
// it, prints whether it did, and exits.

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/bunnyiesart/Gatte/internal/access"
	"github.com/bunnyiesart/Gatte/internal/admin/adminhttp"
)

// blockWriterInput is one block as the root process hands it to the child.
type blockWriterInput struct {
	Subject string    `json:"subject"`
	Reason  string    `json:"reason"`
	By      string    `json:"by"`
	At      time.Time `json:"at"`
	Until   time.Time `json:"until,omitzero"`
}

// blockWriterOutput is the child's answer.
type blockWriterOutput struct {
	Placed bool `json:"placed"`
}

// errNotOnAccountsSocket: the accounts backend places blocks (offboard)
// and does nothing else with the blocklist.
var errNotOnAccountsSocket = errors.New("the accounts socket only places blocks; read and lift them on the operator socket")

// childBlocks is the accounts backend's access.BlockStore: Block goes
// through the child, and nothing else is served.
type childBlocks struct {
	place func(ctx context.Context, b access.Block) (bool, error)
}

var _ access.BlockStore = childBlocks{}

func (c childBlocks) Block(ctx context.Context, b access.Block) (bool, error) { return c.place(ctx, b) }
func (childBlocks) Blocked(context.Context, string) (bool, error) {
	return false, errNotOnAccountsSocket
}
func (childBlocks) Unblock(context.Context, string) (bool, error) {
	return false, errNotOnAccountsSocket
}
func (childBlocks) Blocks(context.Context) ([]access.Block, error) {
	return nil, errNotOnAccountsSocket
}

// spawnBlockWriter places a block through `admin -block-writer` running as
// uid and gid.
func spawnBlockWriter(configPath string, uid, gid uint32) func(context.Context, access.Block) (bool, error) {
	return func(ctx context.Context, b access.Block) (bool, error) {
		body, err := json.Marshal(blockWriterInput{Subject: b.Subject, Reason: b.Reason, By: b.By, At: b.At, Until: b.Until})
		if err != nil {
			return false, err
		}
		out, err := runAdminChild(ctx, configPath, "-block-writer", uid, gid, body)
		if err != nil {
			return false, err
		}
		var res blockWriterOutput
		if err := json.Unmarshal(out, &res); err != nil {
			return false, fmt.Errorf("block writer: unreadable answer: %v", err)
		}
		return res.Placed, nil
	}
}

// runBlockWriter places one block read from stdin and prints whether it
// did. Like the audit writer it refuses to run as root, and it places only
// a block an operator action could have placed: validated, attributed, and
// carrying the actor's front tag.
func runBlockWriter(configPath string, stdin io.Reader, stdout, stderr io.Writer) int {
	if adminGeteuid() == 0 {
		fmt.Fprint(stderr, "admin -block-writer runs as the database's owner, never as root.\n")
		return exitCannotRun
	}
	data, err := io.ReadAll(io.LimitReader(stdin, adminhttp.MaxBody+1))
	if err != nil || len(data) > adminhttp.MaxBody {
		fmt.Fprint(stderr, "admin -block-writer: unreadable or oversized input\n")
		return exitCannotRun
	}
	var in blockWriterInput
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&in); err != nil {
		fmt.Fprintf(stderr, "admin -block-writer: %v\n", err)
		return exitCannotRun
	}
	b := access.Block{Subject: in.Subject, Reason: in.Reason, By: in.By, At: in.At, Until: in.Until}
	if err := access.ValidateBlock(b); err != nil || !strings.HasPrefix(in.Reason, "[") {
		fmt.Fprintf(stderr, "admin -block-writer: only an operator action's block is placed here: %v\n", err)
		return exitProblem
	}
	return opRun(configPath, io.Discard, stderr, func(e *opEnv) int {
		var placed bool
		if err := retryBusy(e.ctx(), func() (err error) {
			placed, err = e.blocks().Block(e.ctx(), b)
			return err
		}); err != nil {
			fmt.Fprintf(stderr, "blocklist: %v\n", err)
			return exitProblem
		}
		if err := json.NewEncoder(stdout).Encode(blockWriterOutput{Placed: placed}); err != nil {
			fmt.Fprintf(stderr, "admin -block-writer: %v\n", err)
			return exitProblem
		}
		return exitOK
	})
}
