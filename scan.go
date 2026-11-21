package portscan

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

// State describes the outcome of a TCP connection attempt.
type State string

const (
	StateOpen        State = "open"
	StateClosed      State = "closed"
	StateTimeout     State = "timeout"
	StateUnreachable State = "unreachable"
	StateCanceled    State = "canceled"
	StateError       State = "error"
)

// Result is the outcome of checking one host/IP and TCP port.
type Result struct {
	Host     string
	IP       net.IP
	Port     uint16
	State    State
	Duration time.Duration
	Err      error
}

// Scanner performs TCP Connect scans. A Scanner is safe for concurrent use.
type Scanner struct {
	config      scannerConfig
	slots       chan struct{}
	dialContext func(context.Context, string, string) (net.Conn, error)
}

// New constructs a scanner with defaults of 100 concurrent attempts and a
// 500ms connection timeout.
func New(options ...Option) (*Scanner, error) {
	cfg := scannerConfig{concurrency: defaultConcurrency, connectTimeout: defaultConnectTimeout}
	for _, option := range options {
		if option == nil {
			return nil, errors.New("portscan: nil option")
		}
		if err := option(&cfg); err != nil {
			return nil, err
		}
	}
	return &Scanner{
		config: cfg,
		slots:  make(chan struct{}, cfg.concurrency),
		dialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			return (&net.Dialer{Timeout: cfg.connectTimeout}).DialContext(ctx, network, address)
		},
	}, nil
}

// Scan starts a scan and returns a handle for consuming its results and waiting
// for completion. The caller should consume Results while the scan is running;
// result delivery applies backpressure. On cancellation, a blocked delivery is
// abandoned so the scan can terminate.
func (s *Scanner) Scan(ctx context.Context, hosts []string, ports PortSet) (*Scan, error) {
	if s == nil {
		return nil, errors.New("portscan: nil scanner")
	}
	if s.config.concurrency < 1 || s.config.connectTimeout <= 0 || s.slots == nil || s.dialContext == nil {
		return nil, errors.New("portscan: scanner must be created with New")
	}
	if ctx == nil {
		return nil, errors.New("portscan: nil context")
	}
	if ports.err != nil {
		return nil, ports.err
	}
	if len(ports.ports) == 0 {
		return nil, errors.New("portscan: port set is empty")
	}
	uniqueHosts, err := normalizeHosts(hosts)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	scan := &Scan{results: make(chan Result), done: make(chan struct{})}
	go s.run(ctx, uniqueHosts, append([]uint16(nil), ports.ports...), scan)
	return scan, nil
}

// Scan is one running scan operation.
type Scan struct {
	results chan Result
	done    chan struct{}
	err     error // written before done is closed
}

// Results returns the stream of completed port checks. The channel is closed
// when the scan has finished.
func (s *Scan) Results() <-chan Result { return s.results }

// Wait blocks until the scan finishes. It returns the context error on
// cancellation or deadline expiration.
func (s *Scan) Wait() error {
	<-s.done
	return s.err
}

type target struct {
	host string
	ip   net.IP
	zone string
}

type job struct {
	target target
	port   uint16
}

type resolvedIP struct {
	ip   net.IP
	zone string
}

func (s *Scanner) run(ctx context.Context, hosts []string, ports []uint16, scan *Scan) {
	defer close(scan.done)
	defer close(scan.results)

	jobs := make(chan job)
	var workers sync.WaitGroup
	workers.Add(s.config.concurrency)
	for i := 0; i < s.config.concurrency; i++ {
		go func() {
			defer workers.Done()
			for work := range jobs {
				result := s.check(ctx, work)
				select {
				case scan.results <- result:
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	for _, host := range hosts {
		if ctx.Err() != nil {
			break
		}
		ips, err := resolve(ctx, host)
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			for _, port := range ports {
				if !sendResult(ctx, scan.results, Result{Host: host, Port: port, State: StateUnreachable, Err: err}) {
					break
				}
			}
			continue
		}
		for _, ip := range ips {
			for _, port := range ports {
				select {
				case jobs <- job{target: target{host: host, ip: ip.ip, zone: ip.zone}, port: port}:
				case <-ctx.Done():
					break
				}
				if ctx.Err() != nil {
					break
				}
			}
			if ctx.Err() != nil {
				break
			}
		}
	}
	close(jobs)
	workers.Wait()
	if ctx.Err() != nil {
		scan.err = ctx.Err()
	}
}

func sendResult(ctx context.Context, out chan<- Result, result Result) bool {
	select {
	case out <- result:
		return true
	case <-ctx.Done():
		return false
	}
}

func (s *Scanner) check(ctx context.Context, work job) Result {
	started := time.Now()
	select {
	case s.slots <- struct{}{}:
	case <-ctx.Done():
		err := ctx.Err()
		return Result{
			Host:     work.target.host,
			IP:       append(net.IP(nil), work.target.ip...),
			Port:     work.port,
			State:    StateCanceled,
			Duration: time.Since(started),
			Err:      err,
		}
	}
	defer func() { <-s.slots }()

	ipHost := work.target.ip.String()
	if work.target.zone != "" {
		ipHost += "%" + work.target.zone
	}
	address := net.JoinHostPort(ipHost, strconv.Itoa(int(work.port)))
	conn, err := s.dialContext(ctx, "tcp", address)
	duration := time.Since(started)
	if conn != nil {
		_ = conn.Close()
	}
	return Result{
		Host:     work.target.host,
		IP:       append(net.IP(nil), work.target.ip...),
		Port:     work.port,
		State:    classify(err, ctx),
		Duration: duration,
		Err:      err,
	}
}

func classify(err error, ctx context.Context) State {
	if err == nil {
		return StateOpen
	}
	if ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return StateCanceled
	}
	var netErr net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &netErr) && netErr.Timeout()) {
		return StateTimeout
	}
	if isRefused(err) {
		return StateClosed
	}
	if isUnreachable(err) {
		return StateUnreachable
	}
	return StateError
}

func normalizeHosts(hosts []string) ([]string, error) {
	if len(hosts) == 0 {
		return nil, errors.New("portscan: at least one host is required")
	}
	seen := make(map[string]struct{}, len(hosts))
	unique := make([]string, 0, len(hosts))
	for _, host := range hosts {
		if host == "" || strings.TrimSpace(host) != host {
			return nil, errors.New("portscan: host must not be empty or contain surrounding whitespace")
		}
		key := strings.ToLower(host)
		if addr, err := netip.ParseAddr(host); err == nil {
			key = addr.String()
		} else if !validHostname(host) || looksLikeIPv4(host) {
			return nil, fmt.Errorf("portscan: invalid host %q", host)
		} else {
			key = strings.ToLower(strings.TrimSuffix(host, "."))
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, host)
	}
	return unique, nil
}

func looksLikeIPv4(host string) bool {
	parts := strings.Split(strings.TrimSuffix(host, "."), ".")
	if len(parts) != 4 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		for _, r := range part {
			if r < '0' || r > '9' {
				return false
			}
		}
	}
	return true
}

func validHostname(host string) bool {
	name := strings.TrimSuffix(host, ".")
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				return false
			}
		}
	}
	return true
}

func resolve(ctx context.Context, host string) ([]resolvedIP, error) {
	if addr, err := netip.ParseAddr(host); err == nil {
		ip := net.ParseIP(addr.WithZone("").String())
		return []resolvedIP{{ip: ip, zone: addr.Zone()}}, nil
	}
	// Use a per-call resolver instead of the process-wide mutable
	// net.DefaultResolver so embedding applications keep control of globals.
	resolver := &net.Resolver{}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]struct{}, len(ips))
	unique := make([]resolvedIP, 0, len(ips))
	for _, item := range ips {
		key := item.IP.String() + "%" + item.Zone
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, resolvedIP{ip: append(net.IP(nil), item.IP...), zone: item.Zone})
	}
	if len(unique) == 0 {
		return nil, errors.New("portscan: DNS returned no addresses")
	}
	return unique, nil
}
