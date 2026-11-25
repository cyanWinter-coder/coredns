package file

import (
	"fmt"
	"math/rand"
	"time"

	"github.com/coredns/coredns/plugin/transfer"

	"github.com/miekg/dns"
)

// TransferInFunc transfers zone data into z.
type TransferInFunc func(z *Zone, t *transfer.Transfer) error

// TransferIn retrieves the zone from the masters, parses it and sets it live.
func (z *Zone) TransferIn(t *transfer.Transfer) error {
	return z.TransferInWithRecords(t, nil)
}

// shouldTransfer checks the primaries of zone, retrieves the SOA record, checks the current serial
// and the remote serial and will return true if the remote one is higher than the locally configured one.
func (z *Zone) shouldTransfer() (bool, error) {
	c := new(dns.Client)
	c.Net = "tcp" // do this query over TCP to minimize spoofing
	m := new(dns.Msg)
	m.SetQuestion(z.origin, dns.TypeSOA)

	var Err error
	serial := -1

Transfer:
	for _, tr := range z.TransferFrom {
		Err = nil
		ret, _, err := c.Exchange(m, tr)
		if err != nil {
			Err = err
			continue
		}
		if ret == nil {
			Err = fmt.Errorf("SOA query to %q returned no message", tr)
			continue
		}
		if ret.Rcode != dns.RcodeSuccess {
			Err = fmt.Errorf("SOA query to %q returned rcode %s", tr, dns.RcodeToString[ret.Rcode])
			continue
		}
		for _, a := range ret.Answer {
			if a.Header().Rrtype == dns.TypeSOA {
				serial = int(a.(*dns.SOA).Serial)
				break Transfer
			}
		}
		Err = fmt.Errorf("SOA query to %q contained no SOA record", tr)
	}
	if serial == -1 {
		return false, Err
	}
	soa := z.getSOA()
	if soa == nil {
		return true, Err
	}
	return less(soa.Serial, uint32(serial)), Err // #nosec G115 -- serial fits in uint32 per DNS RFC
}

// less returns true of a is smaller than b when taking RFC 1982 serial arithmetic into account.
func less(a, b uint32) bool {
	if a < b {
		return (b - a) <= MaxSerialIncrement
	}
	return (a - b) > MaxSerialIncrement
}

// Update updates the secondary zone according to its SOA. It will run for the life time of the server
// and uses the SOA parameters. Every refresh it will check for a new SOA number. If that fails (for all
// server) it will retry every retry interval. If the zone failed to transfer before the expire, the zone
// will be marked expired.
func (z *Zone) Update(updateShutdown chan bool, t *transfer.Transfer) error {
	return z.UpdateWithTransfer(updateShutdown, t, (*Zone).TransferIn)
}

// UpdateWithTransfer updates the secondary zone using transferIn for zone transfers.
func (z *Zone) UpdateWithTransfer(updateShutdown chan bool, t *transfer.Transfer, transferIn TransferInFunc) error {
	// If we don't have a SOA, we don't have a zone, wait for it to appear.
	for z.getSOA() == nil {
		if waitOrShutdown(updateShutdown, time.Second) {
			return nil
		}
	}
	retryActive := false

Restart:
	if updateStopped(updateShutdown) {
		return nil
	}
	soa := z.getSOA()
	refresh := time.Second * time.Duration(max(soa.Refresh, 1))
	retry := time.Second * time.Duration(max(soa.Retry, 1))
	expire := time.Second * time.Duration(max(soa.Expire, 1))

	refreshTicker := time.NewTicker(refresh)
	retryTicker := time.NewTicker(retry)
	expireTicker := time.NewTicker(expire)

	for {
		select {
		case <-expireTicker.C:
			if !retryActive {
				break
			}
			z.Lock()
			z.Expired = true
			z.Unlock()

		case <-retryTicker.C:
			if !retryActive {
				break
			}

			if waitOrShutdown(updateShutdown, jitter(2000)) { // 2s randomize
				stopUpdateTickers(refreshTicker, retryTicker, expireTicker)
				return nil
			}

			ok, err := z.shouldTransfer()
			if err != nil {
				recordTransfer(z.origin, "soa", "failure")
				log.Warningf("Failed retry check %s", err)
				continue
			}

			if ok {
				if err := transferIn(z, t); err != nil {
					// transfer failed, leave retryActive true
					break
				}
			}

			// no errors, stop timers and restart
			retryActive = false
			stopUpdateTickers(refreshTicker, retryTicker, expireTicker)
			goto Restart

		case <-refreshTicker.C:

			if waitOrShutdown(updateShutdown, jitter(5000)) { // 5s randomize
				stopUpdateTickers(refreshTicker, retryTicker, expireTicker)
				return nil
			}

			ok, err := z.shouldTransfer()
			if err != nil {
				recordTransfer(z.origin, "soa", "failure")
				log.Warningf("Failed refresh check %s", err)
				retryActive = true
				continue
			}

			if ok {
				if err := transferIn(z, t); err != nil {
					// transfer failed
					retryActive = true
					break
				}
			}

			// no errors, stop timers and restart
			retryActive = false
			stopUpdateTickers(refreshTicker, retryTicker, expireTicker)
			goto Restart

		case <-updateShutdown:
			stopUpdateTickers(refreshTicker, retryTicker, expireTicker)
			return nil
		}
	}
}

func waitOrShutdown(updateShutdown <-chan bool, d time.Duration) bool {
	if updateStopped(updateShutdown) {
		return true
	}
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-timer.C:
		return false
	case <-updateShutdown:
		return true
	}
}

func updateStopped(updateShutdown <-chan bool) bool {
	select {
	case <-updateShutdown:
		return true
	default:
		return false
	}
}

func stopUpdateTickers(tickers ...*time.Ticker) {
	for _, ticker := range tickers {
		ticker.Stop()
	}
}

// jitter returns a random duration between [0,n) * time.Millisecond
func jitter(n int) time.Duration {
	r := rand.Intn(n) // #nosec G404 -- non-cryptographic jitter to spread transfer attempts.
	return time.Duration(r) * time.Millisecond
}

// MaxSerialIncrement is the maximum difference between two serial numbers. If the difference between
// two serials is greater than this number, the smaller one is considered greater.
const MaxSerialIncrement uint32 = 2147483647
