# portscan

`portscan` is an embeddable TCP Connect scanner for Go applications. It uses
only the standard library and does not depend on a CLI, HTTP framework, or
external service.

## Usage

```go
scanner, err := portscan.New(
	portscan.WithConcurrency(100),
	portscan.WithConnectTimeout(500*time.Millisecond),
)
if err != nil {
	return err
}

scan, err := scanner.Scan(ctx,
	[]string{"192.168.1.10", "example.com"},
	portscan.Union(portscan.Ports(22, 80), portscan.Range(443, 445)),
)
if err != nil {
	return err
}

for result := range scan.Results() {
	fmt.Printf("%s (%s):%d %s\n", result.Host, result.IP, result.Port, result.State)
}
if err := scan.Wait(); err != nil {
	return err // context cancellation or deadline
}
```

Consume `Results` while the scan runs. Delivery applies backpressure, so a slow
reader slows scheduling. If the context is canceled while a result is blocked
on delivery, that result may be omitted and the scan terminates. `Wait` can be
called after the results channel closes, or concurrently with a reader that
drains it.

## Public API

- `New(options...)` creates a reusable, concurrency-safe `Scanner`. Defaults
  are 100 concurrent connection attempts and a 500ms per-connection timeout.
- `WithConcurrency` and `WithConnectTimeout` configure those limits. The
  connection limit is shared by concurrent scans using the same `Scanner`.
- `Ports`, `Range`, and `Union` construct a `PortSet`. Ports must be in
  `1..65535`; empty sets and reversed ranges are rejected by `Scan`. Repeated
  ports are deduplicated.
- `Scanner.Scan(ctx, hosts, ports)` validates the request and starts a scan.
  It returns a `Scan` handle with `Results() <-chan Result` and `Wait() error`.
- `Result` includes the supplied `Host`, the resolved `IP`, `Port`, `State`,
  connection `Duration`, and the underlying `Err` when one occurred.

IPv4, IPv6, and DNS names are supported. Empty or malformed names are rejected
before the scan starts. Duplicate host strings are collapsed case-insensitively
(IP addresses are normalized); DNS names that resolve to multiple addresses
are checked against every unique address. An unresolved DNS name yields an
`unreachable` result for each requested port and does not stop other targets.
The result stream is unordered. States are `open`, `closed`, `timeout`,
`unreachable`, `canceled`, and `error`; classification uses typed network
errors and system error codes, not error text.

## Development

```sh
go test -race ./...
```
