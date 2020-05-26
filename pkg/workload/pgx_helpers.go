// Copyright 2018 The Cockroach Authors.
//
// Use of this software is governed by the Business Source License
// included in the file licenses/BSL.txt.
//
// As of the Change Date specified in that file, in accordance with
// the Business Source License, use of this software will be governed
// by the Apache License, Version 2.0, included in the file
// licenses/APL.txt.

package workload

import (
	"context"
	"sync"
	"sync/atomic"

	"github.com/cockroachdb/cockroach-go/crdb"
	"github.com/jackc/pgconn"
	"github.com/jackc/pgx/v4"
	"github.com/jackc/pgx/v4/pgxpool"
	"golang.org/x/sync/errgroup"
)

// MultiConnPool maintains a set of pgx ConnPools (to different servers).
type MultiConnPool struct {
	Pools []*pgxpool.Pool
	// Atomic counter used by Get().
	counter uint32
}

// MultiConnPoolCfg encapsulates the knobs passed to NewMultiConnPool.
type MultiConnPoolCfg struct {
	// MaxTotalConnections is the total maximum number of connections across all
	// pools.
	MaxTotalConnections int

	// MaxConnsPerPool is the maximum number of connections in any single pool.
	// Limiting this is useful especially for prepared statements, which are
	// prepared on each connection inside a pool (serially).
	// If 0, there is no per-pool maximum (other than the total maximum number of
	// connections which still applies).
	MaxConnsPerPool int
}

// NewMultiConnPool creates a new MultiConnPool.
//
// Each URL gets one or more pools, and each pool has at most MaxConnsPerPool
// connections.
//
// The pools have approximately the same number of max connections, adding up to
// MaxTotalConnections.
func NewMultiConnPool(
	ctx context.Context, cfg MultiConnPoolCfg, urls ...string,
) (*MultiConnPool, error) {
	m := &MultiConnPool{}
	connsPerURL := distribute(cfg.MaxTotalConnections, len(urls))
	maxConnsPerPool := cfg.MaxConnsPerPool
	if maxConnsPerPool == 0 {
		maxConnsPerPool = cfg.MaxTotalConnections
	}

	var warmupConns [][]*pgxpool.Conn
	for i := range urls {
		connCfg, err := pgxpool.ParseConfig(urls[i])
		if err != nil {
			return nil, err
		}

		connsPerPool := distributeMax(connsPerURL[i], maxConnsPerPool)
		for _, numConns := range connsPerPool {
			cfg := *connCfg
			cfg.MaxConns = int32(numConns)
			p, err := pgxpool.ConnectConfig(ctx, &cfg)
			if err != nil {
				return nil, err
			}

			warmupConns = append(warmupConns, make([]*pgxpool.Conn, numConns))
			m.Pools = append(m.Pools, p)
		}
	}

	// "Warm up" the pools so we don't have to establish connections later (which
	// would affect the observed latencies of the first requests, especially when
	// prepared statements are used). We do this by
	// acquiring connections (in parallel), then releasing them back to the
	// pool.
	var g errgroup.Group
	// Limit concurrent connection establishment. Allowing this to run
	// at maximum parallelism would trigger syn flood protection on the
	// host, which combined with any packet loss could cause Acquire to
	// return an error and fail the whole function. The value 100 is
	// chosen because it is less than the default value for SOMAXCONN
	// (128).
	sem := make(chan struct{}, 100)
	for i, p := range m.Pools {
		p := p
		conns := warmupConns[i]
		for j := range conns {
			j := j
			sem <- struct{}{}
			g.Go(func() error {
				var err error
				conns[j], err = p.Acquire(ctx)
				<-sem
				return err
			})
		}
	}
	if err := g.Wait(); err != nil {
		return nil, err
	}
	for i := range m.Pools {
		for _, c := range warmupConns[i] {
			c.Release()
		}
	}

	return m, nil
}

// Get returns one of the pools, in round-robin manner.
func (m *MultiConnPool) Get() *pgxpool.Pool {
	if len(m.Pools) == 1 {
		return m.Pools[0]
	}
	i := atomic.AddUint32(&m.counter, 1) - 1
	return m.Pools[i%uint32(len(m.Pools))]
}

// PrepareEx prepares the given statement on all the pools.
func (m *MultiConnPool) PrepareEx(
	ctx context.Context, name, sql string,
) (*pgconn.StatementDescription, error) {
	var res *pgconn.StatementDescription
	var once sync.Once
	var g errgroup.Group
	for _, p := range m.Pools {
		p := p
		g.Go(func() error {
			conns := p.AcquireAllIdle(ctx)
			defer func() {
				for i := range conns {
					conns[i].Release()
				}
			}()
			for _, conn := range conns {
				desc, err := conn.Conn().Prepare(ctx, name, sql)
				if err == nil {
					// It doesn't matter which PreparedStatement we return, they should
					// contain the same information.
					once.Do(func() { res = desc })
				}
				if err != nil {
					return err
				}
			}
			return nil
		})
	}
	err := g.Wait()
	return res, err
}

// Close closes all the pools.
func (m *MultiConnPool) Close() {
	for _, p := range m.Pools {
		p.Close()
	}
}

// PgxTx is a thin wrapper that implements the crdb.Tx interface, allowing pgx
// transactions to be used with ExecuteInTx. The cockroach-go library has native
// support for pgx in crdb/pgx, but only for pgx v4. CRDB is stuck for now using
// pgx v3, as v4 needs Go modules.
type PgxTx struct {
	pgx.Tx
}

// NewPgxTx returns a wrapped pg.Tx that implements the crdb.Tx interface.
func NewPgxTx(tx pgx.Tx) *PgxTx {
	return &PgxTx{Tx: tx}
}

var _ crdb.Tx = &PgxTx{}

// Exec is part of the crdb.Tx interface.
func (tx *PgxTx) Exec(ctx context.Context, sql string, args ...interface{}) error {
	_, err := tx.Tx.Exec(ctx, sql, args...)
	// crdb.ExecuteInTx doesn't actually care about the Result, just the error.
	return err
}

// Commit is part of the crdb.Tx interface.
func (tx *PgxTx) Commit(ctx context.Context) error {
	return tx.Tx.Commit(ctx)
}

// Rollback is part of the crdb.Tx interface.
func (tx *PgxTx) Rollback(ctx context.Context) error {
	return tx.Tx.Rollback(ctx)
}

// distribute returns a slice of <num> integers that add up to <total> and are
// within +/-1 of each other.
func distribute(total, num int) []int {
	res := make([]int, num)
	for i := range res {
		// Use the average number of remaining connections.
		div := len(res) - i
		res[i] = (total + div/2) / div
		total -= res[i]
	}
	return res
}

// distributeMax returns a slice of integers that are at most `max` and add up
// to <total>. The slice is as short as possible and the values are within +/-1
// of each other.
func distributeMax(total, max int) []int {
	return distribute(total, (total+max-1)/max)
}
