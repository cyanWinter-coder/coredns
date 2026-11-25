package file

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/coredns/coredns/plugin/pkg/dnstest"
	"github.com/coredns/coredns/plugin/test"

	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

type hardening616Master struct {
	mu sync.Mutex

	serial uint32

	soaCalls  int
	ixfrCalls int
	axfrCalls int

	blockAXFR chan struct{}
	started   chan struct{}
	closeMid  bool
	ixfrStyle bool
}

func (m *hardening616Master) handler(w dns.ResponseWriter, req *dns.Msg) {
	if len(req.Question) == 0 {
		return
	}
	qtype := req.Question[0].Qtype
	origin := testZone

	m.mu.Lock()
	serial := m.serial
	switch qtype {
	case dns.TypeSOA:
		m.soaCalls++
	case dns.TypeIXFR:
		m.ixfrCalls++
	case dns.TypeAXFR:
		m.axfrCalls++
	}
	block := m.blockAXFR
	started := m.started
	closeMid := m.closeMid
	ixfrStyle := m.ixfrStyle
	m.mu.Unlock()

	msg := new(dns.Msg)
	msg.SetReply(req)
	msg.Authoritative = true

	soa := test.SOA(fmt.Sprintf("%s IN SOA ns.example. admin.example. %d 1 1 1 1", origin, serial))
	switch qtype {
	case dns.TypeSOA:
		msg.Answer = []dns.RR{soa}
		_ = w.WriteMsg(msg)
	case dns.TypeIXFR:
		// Tests that need a real delta install their own handler. The default
		// is an explicit not-implemented response so fallback is immediate.
		if ixfrStyle {
			msg.Answer = []dns.RR{
				soa,
				test.A(fmt.Sprintf("www.%s 300 IN A 192.0.2.10", origin)),
				soa,
			}
		} else {
			msg.Rcode = dns.RcodeNotImplemented
		}
		_ = w.WriteMsg(msg)
	case dns.TypeAXFR:
		if block != nil {
			if started != nil {
				select {
				case started <- struct{}{}:
				default:
				}
			}
			<-block
		}
		msg.Answer = []dns.RR{
			soa,
			test.A(fmt.Sprintf("www.%s 300 IN A 192.0.2.10", origin)),
		}
		if !closeMid {
			msg.Answer = append(msg.Answer, soa)
		}
		_ = w.WriteMsg(msg)
		if closeMid {
			_ = w.Close()
		}
	default:
		msg.Rcode = dns.RcodeNotImplemented
		_ = w.WriteMsg(msg)
	}
}

func (m *hardening616Master) counts() (soa, ixfr, axfr int) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.soaCalls, m.ixfrCalls, m.axfrCalls
}

func TestHardening616_SyncIfNeededSkipsEqualSerial(t *testing.T) {
	master := &hardening616Master{serial: 250}
	server := dnstest.NewServer(master.handler)
	defer server.Close()

	z := NewZone(testZone, "")
	z.TransferFrom = []string{server.Addr}
	z.SOA = test.SOA(fmt.Sprintf("%s IN SOA ns admin 250 1 1 1 1", testZone))

	changed, err := z.SyncIfNeeded(nil)
	if err != nil {
		t.Fatalf("SyncIfNeeded equal serial: %v", err)
	}
	if changed {
		t.Fatal("equal serial reported a change")
	}
	soaCalls, ixfrCalls, axfrCalls := master.counts()
	if soaCalls != 1 {
		t.Fatalf("expected one SOA check, got %d", soaCalls)
	}
	if ixfrCalls != 0 || axfrCalls != 0 {
		t.Fatalf("equal serial fetched zone: ixfr=%d axfr=%d", ixfrCalls, axfrCalls)
	}

	master.mu.Lock()
	master.serial = 251
	master.mu.Unlock()

	changed, err = z.SyncIfNeeded(nil)
	if err != nil {
		t.Fatalf("SyncIfNeeded newer serial: %v", err)
	}
	if !changed {
		t.Fatal("newer serial did not report a change")
	}
	if got := z.SOA.Serial; got != 251 {
		t.Fatalf("expected live serial 251, got %d", got)
	}
	_, ixfrCalls, axfrCalls = master.counts()
	if axfrCalls != 1 {
		t.Fatalf("expected AXFR fallback after IXFR not implemented, axfr=%d", axfrCalls)
	}
}

func TestHardening616_TransferInAppliesIXFRDelta(t *testing.T) {
	const origin = "ixfr-delta.example."
	oldAddress := test.A("host." + origin + " 300 IN A 192.0.2.1")
	newAddress := test.A("host." + origin + " 300 IN A 192.0.2.2")
	keep := test.A("keep." + origin + " 300 IN A 192.0.2.3")
	oldSOA := test.SOA(fmt.Sprintf("%s IN SOA ns.example. admin.example. 1 1 1 1 1", origin))
	newSOA := test.SOA(fmt.Sprintf("%s IN SOA ns.example. admin.example. 2 1 1 1 1", origin))

	server := dnstest.NewServer(func(w dns.ResponseWriter, req *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(req)
		if len(req.Question) == 0 {
			return
		}
		switch req.Question[0].Qtype {
		case dns.TypeIXFR:
			msg.Answer = []dns.RR{
				newSOA,
				oldSOA,
				oldAddress,
				newSOA,
				newAddress,
				newSOA,
			}
		case dns.TypeAXFR:
			msg.Answer = []dns.RR{newSOA, newAddress, keep, newSOA}
		default:
			msg.Rcode = dns.RcodeNotImplemented
		}
		_ = w.WriteMsg(msg)
	})
	defer server.Close()

	z := NewZone(origin, "")
	z.TransferFrom = []string{server.Addr}
	if err := z.Insert(oldSOA); err != nil {
		t.Fatal(err)
	}
	if err := z.Insert(oldAddress); err != nil {
		t.Fatal(err)
	}
	if err := z.Insert(keep); err != nil {
		t.Fatal(err)
	}

	if err := z.TransferIn(nil); err != nil {
		t.Fatalf("IXFR transfer: %v", err)
	}
	if z.SOA.Serial != 2 {
		t.Fatalf("serial = %d, want 2", z.SOA.Serial)
	}
	assertHardening616Address(t, z, "host."+origin, "192.0.2.2")
	assertHardening616Address(t, z, "keep."+origin, "192.0.2.3")
}

func TestHardening616_TransferInIXFRFailureFallsBackToAXFR(t *testing.T) {
	master := &hardening616Master{serial: 9}
	server := dnstest.NewServer(master.handler)
	defer server.Close()

	z := NewZone(testZone, "")
	z.TransferFrom = []string{server.Addr}
	z.SOA = test.SOA(fmt.Sprintf("%s IN SOA ns admin 8 1 1 1 1", testZone))

	if err := z.TransferIn(nil); err != nil {
		t.Fatalf("TransferIn should fall back to AXFR: %v", err)
	}
	if z.SOA.Serial != 9 {
		t.Fatalf("serial = %d, want 9", z.SOA.Serial)
	}
	_, ixfrCalls, axfrCalls := master.counts()
	if ixfrCalls != 1 || axfrCalls != 1 {
		t.Fatalf("expected one IXFR and one AXFR, got ixfr=%d axfr=%d", ixfrCalls, axfrCalls)
	}
}

func TestHardening616_AppliesMultiVersionIXFR(t *testing.T) {
	const origin = "ixfr-multi.example."
	soa1 := test.SOA(origin + " IN SOA ns admin 1 1 1 1 1")
	soa2 := test.SOA(origin + " IN SOA ns admin 2 1 1 1 1")
	soa3 := test.SOA(origin + " IN SOA ns admin 3 1 1 1 1")
	a1 := test.A("a." + origin + " 300 IN A 192.0.2.1")
	a2 := test.A("a." + origin + " 300 IN A 192.0.2.2")
	a3 := test.A("a." + origin + " 300 IN A 192.0.2.3")
	keep := test.A("keep." + origin + " 300 IN A 192.0.2.4")

	server := dnstest.NewServer(func(w dns.ResponseWriter, req *dns.Msg) {
		msg := new(dns.Msg)
		msg.SetReply(req)
		if len(req.Question) > 0 && req.Question[0].Qtype == dns.TypeIXFR {
			msg.Answer = []dns.RR{
				soa3,
				soa1,
				a1,
				soa2,
				a2,
				soa2,
				a2,
				soa3,
				a3,
				soa3,
			}
		} else {
			msg.Rcode = dns.RcodeNotImplemented
		}
		_ = w.WriteMsg(msg)
	})
	defer server.Close()

	z := NewZone(origin, "")
	z.TransferFrom = []string{server.Addr}
	for _, rr := range []dns.RR{soa1, a1, keep} {
		if err := z.Insert(rr); err != nil {
			t.Fatal(err)
		}
	}

	if err := z.TransferIn(nil); err != nil {
		t.Fatalf("multi-version IXFR: %v", err)
	}
	assertHardening616Address(t, z, "a."+origin, "192.0.2.3")
	assertHardening616Address(t, z, "keep."+origin, "192.0.2.4")
}

func TestHardening616_AXFRStyleIXFRDoesNotRequireAXFR(t *testing.T) {
	master := &hardening616Master{serial: 10, ixfrStyle: true}
	server := dnstest.NewServer(master.handler)
	defer server.Close()

	z := NewZone(testZone, "")
	z.TransferFrom = []string{server.Addr}
	z.SOA = test.SOA(fmt.Sprintf("%s IN SOA ns admin 9 1 1 1 1", testZone))

	if err := z.TransferIn(nil); err != nil {
		t.Fatalf("AXFR-style IXFR: %v", err)
	}
	if z.SOA.Serial != 10 {
		t.Fatalf("serial = %d, want 10", z.SOA.Serial)
	}
	assertHardening616Address(t, z, "www."+testZone, "192.0.2.10")
	_, ixfrCalls, axfrCalls := master.counts()
	if ixfrCalls != 1 {
		t.Fatalf("ixfr calls = %d, want 1", ixfrCalls)
	}
	if axfrCalls != 0 {
		t.Fatalf("AXFR-style IXFR unexpectedly fell back to AXFR %d times", axfrCalls)
	}
}

func TestHardening616_FailedTransferKeepsOldDataAvailable(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 1)
	master := &hardening616Master{serial: 2, blockAXFR: release, started: started, closeMid: true}
	server := dnstest.NewMultipleServer(master.handler)
	defer server.Close()

	z := NewZone(testZone, "")
	z.TransferFrom = []string{server.Addr}
	old := test.A(fmt.Sprintf("www.%s 300 IN A 192.0.2.1", testZone))
	if err := z.Insert(test.SOA(fmt.Sprintf("%s IN SOA ns admin 1 1 1 1 1", testZone))); err != nil {
		t.Fatal(err)
	}
	if err := z.Insert(old); err != nil {
		t.Fatal(err)
	}

	done := make(chan error, 1)
	go func() { done <- z.TransferIn(nil) }()

	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("AXFR server did not start")
	}

	// While the transfer is blocked, the old generation must remain visible
	// through the DNS handler, not just through direct tree access.
	req := new(dns.Msg)
	req.SetQuestion(dns.Fqdn("www."+testZone), dns.TypeA)
	rec := dnstest.NewRecorder(&test.ResponseWriter{})
	f := File{Zones: Zones{Z: map[string]*Zone{testZone: z}, Names: []string{testZone}}}
	if code, err := f.ServeDNS(context.Background(), rec, req); err != nil || code != dns.RcodeSuccess {
		t.Fatalf("query during transfer failed: code=%d err=%v", code, err)
	}
	if len(rec.Msg.Answer) != 1 {
		t.Fatalf("expected old answer during transfer, got %d answers", len(rec.Msg.Answer))
	}
	if got := rec.Msg.Answer[0].(*dns.A).A.String(); got != "192.0.2.1" {
		t.Fatalf("during transfer address = %s, want old 192.0.2.1", got)
	}
	assertHardening616Address(t, z, "www."+testZone, "192.0.2.1")
	close(release)

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected interrupted transfer to fail")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("TransferIn did not return after disconnect")
	}
	assertHardening616Address(t, z, "www."+testZone, "192.0.2.1")
	if _, found := z.Search("new." + testZone); found {
		t.Fatal("partial failed transfer published unexpected new node")
	}
}

func TestHardening616_TransferInAtomicallyReplacesZoneFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "db."+testZone)
	if err := os.WriteFile(path, []byte(fmt.Sprintf("$ORIGIN %s\n%s IN SOA ns admin 1 1 1 1 1\nwww 300 IN A 192.0.2.1\n", testZone, testZone)), 0o644); err != nil {
		t.Fatal(err)
	}

	master := &hardening616Master{serial: 7}
	server := dnstest.NewServer(master.handler)
	defer server.Close()

	z := NewZone(testZone, path)
	z.TransferFrom = []string{server.Addr}
	old, err := Parse(mustHardening616Open(t, path), testZone, path, -1)
	if err != nil {
		t.Fatal(err)
	}
	z.setData(old.Apex, old.Tree)

	if err := z.TransferIn(nil); err != nil {
		t.Fatalf("TransferIn: %v", err)
	}
	onDisk, err := Parse(mustHardening616Open(t, path), testZone, path, -1)
	if err != nil {
		t.Fatalf("replaced file is not valid: %v", err)
	}
	if onDisk.SOA.Serial != 7 {
		t.Fatalf("disk serial = %d, want 7", onDisk.SOA.Serial)
	}
	if z.SOA.Serial != 7 {
		t.Fatalf("live serial = %d, want 7", z.SOA.Serial)
	}
	tmp, err := filepath.Glob(filepath.Join(dir, ".zone-transfer-*.tmp"))
	if err != nil {
		t.Fatal(err)
	}
	if len(tmp) != 0 {
		t.Fatalf("temporary files left behind: %v", tmp)
	}
}

func TestHardening616_TransferInRepeatedLoadIsIdempotent(t *testing.T) {
	master := &hardening616Master{serial: 31}
	server := dnstest.NewServer(master.handler)
	defer server.Close()

	z := NewZone(testZone, "")
	z.TransferFrom = []string{server.Addr}
	z.SOA = test.SOA(fmt.Sprintf("%s IN SOA ns admin 30 1 1 1 1", testZone))

	for range 2 {
		if err := z.TransferIn(nil); err != nil {
			t.Fatalf("TransferIn: %v", err)
		}
	}
	elem, found := z.Search("www." + testZone)
	if !found {
		t.Fatal("www record missing")
	}
	if got := len(elem.Type(dns.TypeA)); got != 1 {
		t.Fatalf("expected one A after repeated replacement, got %d", got)
	}
}

func TestHardening616_TransferFailureMetricCounted(t *testing.T) {
	release := make(chan struct{})
	close(release)
	master := &hardening616Master{serial: 2, blockAXFR: release, closeMid: true}
	server := dnstest.NewMultipleServer(master.handler)
	defer server.Close()

	const zone = "metrics-failure.example."
	z := NewZone(zone, "")
	z.TransferFrom = []string{server.Addr}
	// Nil SOA forces AXFR and avoids IXFR metric noise.
	before := testutil.ToFloat64(zoneTransfers.WithLabelValues(zone, "axfr", "failure"))
	if err := z.TransferIn(nil); err == nil {
		t.Fatal("expected broken AXFR to fail")
	}
	after := testutil.ToFloat64(zoneTransfers.WithLabelValues(zone, "axfr", "failure"))
	if after <= before {
		t.Fatalf("failure counter did not increase: before=%v after=%v", before, after)
	}
}

func assertHardening616Address(t *testing.T, z *Zone, name, want string) {
	t.Helper()
	elem, found := z.Search(dns.Fqdn(name))
	if !found {
		t.Fatalf("record %q not found", name)
	}
	rrs := elem.Type(dns.TypeA)
	if len(rrs) == 0 {
		t.Fatalf("no A records for %q", name)
	}
	for _, rr := range rrs {
		if rr.(*dns.A).A.String() == want {
			return
		}
	}
	t.Fatalf("address %s not found among %d A records for %q", want, len(rrs), name)
}

func mustHardening616Open(t *testing.T, path string) *os.File {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}
