package ticker

import "time"

// realTicker wraps a [time.Ticker] to satisfy the [ticker] interface.
type realTicker struct {
	*time.Ticker
}

func (r realTicker) Chan() <-chan time.Time {
	return r.C
}

func newRealTicker(d time.Duration) ticker {
	return realTicker{
		Ticker: time.NewTicker(d),
	}
}
