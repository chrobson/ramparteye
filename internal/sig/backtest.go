package sig

import (
	"context"

	"github.com/chrobson/ramparteye/internal/model"
)

// Observation is one stored service observation with its HTTP fingerprint
// (zero HTTPObs for a non-HTTP service).
type Observation struct {
	Service model.ServiceObs
	HTTP    model.HTTPObs
}

// BacktestMatch is one historical observation a signature matched.
type BacktestMatch struct {
	RunID     int64
	Key       model.AssetKey
	Detection model.Detection
}

// BacktestResult is the outcome of Backtest.
type BacktestResult struct {
	Checked int             // observations evaluated
	Matches []BacktestMatch // in history order
	// PathMatchers counts the signature's path matchers. They need a live
	// request, so they never match in a backtest.
	PathMatchers int
	// Err is the context error when the backtest stopped early.
	Err error
}

// Backtest evaluates s against stored observations without any network
// access: path matchers never match, everything else is read from history.
// The signature is evaluated on its own (enabled or not, no generic panel
// suppression).
func Backtest(ctx context.Context, s *Signature, history []Observation) BacktestResult {
	res := BacktestResult{}
	for i := range s.Matchers {
		if s.Matchers[i].Type == TypePath {
			res.PathMatchers++
		}
	}
	for _, o := range history {
		if err := ctx.Err(); err != nil {
			res.Err = err
			break
		}
		res.Checked++
		ev := newEvaluator(ctx, o.Service, o.HTTP, nil, nil)
		if d, ok := ev.detect(s); ok {
			res.Matches = append(res.Matches, BacktestMatch{RunID: o.Service.RunID, Key: o.Service.Key, Detection: d})
		}
	}
	return res
}

// Backtest is the package-level Backtest for callers holding a live engine:
// it never uses e.Fetcher or e.ProbeGate, so a backtest sends no requests
// and spends no probe budget.
func (e *Engine) Backtest(ctx context.Context, s *Signature, history []Observation) BacktestResult {
	return Backtest(ctx, s, history)
}
