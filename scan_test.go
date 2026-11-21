package portscan

import (
	"context"
	"errors"
	"net"
	"runtime"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

func TestPortSetValidationAndDeduplication(t *testing.T) {
	set := Union(Ports(80, 22, 80), Range(21, 23))
	if set.err != nil {
		t.Fatal(set.err)
	}
	want := []uint16{21, 22, 23, 80}
	if len(set.ports) != len(want) {
		t.Fatalf("ports = %v, want %v", set.ports, want)
	}
	for i := range want {
		if set.ports[i] != want[i] {
			t.Fatalf("ports = %v, want %v", set.ports, want)
		}
	}
	for _, invalid := range []PortSet{Ports(), Ports(0), Ports(65536), Range(1000, 1)} {
		if _, err := NewScannerForTest(t).Scan(context.Background(), []string{"localhost"}, invalid); err == nil {
			t.Fatalf("Scan accepted invalid port set: %#v", invalid)
		}
	}
}

func TestScanOpenPortAndDuplicateTargets(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port

	scanner := NewScannerForTest(t)
	scan, err := scanner.Scan(context.Background(), []string{"127.0.0.1", "127.0.0.1"}, Ports(port))
	if err != nil {
		t.Fatal(err)
	}
	results := collect(t, scan)
	if len(results) != 1 {
		t.Fatalf("got %d results, want 1: %#v", len(results), results)
	}
	if results[0].State != StateOpen || results[0].IP.String() != "127.0.0.1" {
		t.Fatalf("result = %#v (error %v), want open IPv4 result", results[0], results[0].Err)
	}
}

func TestScanClosedPort(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}

	scan, err := NewScannerForTest(t).Scan(context.Background(), []string{"127.0.0.1"}, Ports(port))
	if err != nil {
		t.Fatal(err)
	}
	results := collect(t, scan)
	if len(results) != 1 {
		t.Fatalf("got %d results, want one: %#v", len(results), results)
	}
	if results[0].State != StateClosed {
		t.Fatalf("result = %#v, want closed", results[0])
	}
}

func TestScanRejectsInvalidHostsAndPorts(t *testing.T) {
	scanner := NewScannerForTest(t)
	if _, err := new(Scanner).Scan(context.Background(), []string{"localhost"}, Ports(80)); err == nil {
		t.Fatal("zero-value Scanner should fail instead of starting a stalled scan")
	}
	for _, hosts := range [][]string{nil, {""}, {"bad host"}, {"999.999.999.999"}} {
		if _, err := scanner.Scan(context.Background(), hosts, Ports(80)); err == nil {
			t.Errorf("Scan accepted hosts %q", hosts)
		}
	}
	if _, err := scanner.Scan(context.Background(), []string{"localhost"}, PortSet{}); err == nil {
		t.Fatal("Scan accepted empty port set")
	}
}

func TestClassifyStates(t *testing.T) {
	ctx := context.Background()
	refusedErr := error(syscall.ECONNREFUSED)
	unreachableErr := error(syscall.ENETUNREACH)
	if runtime.GOOS == "windows" {
		refusedErr = syscall.Errno(10061)     // WSAECONNREFUSED
		unreachableErr = syscall.Errno(10051) // WSAENETUNREACH
	}
	cases := []struct {
		name string
		err  error
		ctx  context.Context
		want State
	}{
		{name: "open", want: StateOpen},
		{name: "closed", err: &net.OpError{Op: "dial", Err: refusedErr}, want: StateClosed},
		{name: "unreachable", err: &net.OpError{Op: "dial", Err: unreachableErr}, want: StateUnreachable},
		{name: "timeout", err: timeoutError{}, want: StateTimeout},
		{name: "other", err: errors.New("other"), want: StateError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classify(tc.err, ctx); got != tc.want {
				t.Fatalf("classify = %q, want %q", got, tc.want)
			}
		})
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if got := classify(context.Canceled, canceled); got != StateCanceled {
		t.Fatalf("canceled classify = %q", got)
	}
}

func TestScanCancellationAndReusableScanner(t *testing.T) {
	scanner := NewScannerForTest(t)
	ctx, cancel := context.WithCancel(context.Background())
	scan, err := scanner.Scan(ctx, []string{"127.0.0.1"}, Range(1, 1000))
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	for range scan.Results() {
	}
	if err := scan.Wait(); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait error = %v, want context.Canceled", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	second, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, Ports(port))
	if err != nil {
		t.Fatal(err)
	}
	if results := collect(t, second); len(results) != 1 || results[0].State != StateOpen {
		t.Fatalf("second scan results = %#v", results)
	}
}

func TestConcurrentScansAndSlowResultReader(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := listener.Addr().(*net.TCPAddr).Port
	scanner := NewScannerForTest(t)

	first, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, Range(port, port+15))
	if err != nil {
		t.Fatal(err)
	}
	second, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, Ports(port))
	if err != nil {
		t.Fatal(err)
	}

	var results []Result
	for result := range first.Results() {
		results = append(results, result)
		time.Sleep(time.Millisecond) // exercise backpressure from a slow consumer
	}
	if err := first.Wait(); err != nil {
		t.Fatal(err)
	}
	if got, want := len(results), 16; got != want {
		t.Fatalf("slow reader received %d results, want %d", got, want)
	}
	if got := collect(t, second); len(got) != 1 || got[0].State != StateOpen {
		t.Fatalf("concurrent scan results = %#v", got)
	}
}

func TestConcurrencyLimitIsSharedAcrossConcurrentScans(t *testing.T) {
	scanner, err := New(WithConcurrency(1))
	if err != nil {
		t.Fatal(err)
	}
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var active, maximum atomic.Int32
	scanner.dialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		current := active.Add(1)
		for seen := maximum.Load(); current > seen; seen = maximum.Load() {
			if maximum.CompareAndSwap(seen, current) {
				break
			}
		}
		entered <- struct{}{}
		select {
		case <-release:
		case <-ctx.Done():
		}
		active.Add(-1)
		return nil, errors.New("test dial failure")
	}

	first, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, Ports(80))
	if err != nil {
		t.Fatal(err)
	}
	second, err := scanner.Scan(context.Background(), []string{"127.0.0.1"}, Ports(81))
	if err != nil {
		t.Fatal(err)
	}
	consume := func(scan *Scan) {
		for range scan.Results() {
		}
		if err := scan.Wait(); err != nil {
			t.Errorf("Wait() error = %v", err)
		}
	}
	completed := make(chan struct{}, 2)
	go func() { consume(first); completed <- struct{}{} }()
	go func() { consume(second); completed <- struct{}{} }()
	<-entered
	select {
	case <-entered:
		t.Fatal("second scan started a connection while the first held the only slot")
	case <-time.After(50 * time.Millisecond):
	}
	release <- struct{}{}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("second scan did not start after the first released its slot")
	}
	release <- struct{}{}
	for range 2 {
		select {
		case <-completed:
		case <-time.After(time.Second):
			t.Fatal("scans did not finish")
		}
	}
	if got := maximum.Load(); got != 1 {
		t.Fatalf("maximum concurrent dials = %d, want 1", got)
	}
}

func TestScanDNSFailureReturnsPerPortResults(t *testing.T) {
	scanner, err := New(WithConnectTimeout(100 * time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	scan, err := scanner.Scan(context.Background(), []string{"this-name-should-not-resolve.invalid"}, Ports(80, 443))
	if err != nil {
		t.Fatal(err)
	}
	results := collect(t, scan)
	if len(results) != 2 {
		t.Fatalf("got %d DNS results, want 2", len(results))
	}
	for _, result := range results {
		if result.State != StateUnreachable || result.Err == nil {
			t.Errorf("DNS result = %#v, want unreachable with error", result)
		}
	}
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func NewScannerForTest(t *testing.T) *Scanner {
	t.Helper()
	scanner, err := New(WithConcurrency(4), WithConnectTimeout(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return scanner
}

func collect(t *testing.T, scan *Scan) []Result {
	t.Helper()
	var results []Result
	for result := range scan.Results() {
		results = append(results, result)
	}
	if err := scan.Wait(); err != nil {
		t.Fatal(err)
	}
	return results
}
