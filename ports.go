package portscan

import (
	"fmt"
	"sort"
)

// PortSet is an immutable set of TCP ports. Create one with Ports, Range, or Union.
// Invalid values are retained as an error and reported by Scanner.Scan.
type PortSet struct {
	ports []uint16
	err   error
}

// Ports creates a set from individual port numbers.
func Ports(values ...int) PortSet {
	ports := make([]uint16, 0, len(values))
	for _, p := range values {
		if p < 1 || p > 65535 {
			return PortSet{err: fmt.Errorf("portscan: port %d is outside 1..65535", p)}
		}
		ports = append(ports, uint16(p))
	}
	return makePortSet(ports)
}

// Range creates a set containing every port from first through last, inclusive.
func Range(first, last int) PortSet {
	if first < 1 || first > 65535 {
		return PortSet{err: fmt.Errorf("portscan: port %d is outside 1..65535", first)}
	}
	if last < 1 || last > 65535 {
		return PortSet{err: fmt.Errorf("portscan: port %d is outside 1..65535", last)}
	}
	if first > last {
		return PortSet{err: fmt.Errorf("portscan: reversed port range %d..%d", first, last)}
	}
	ports := make([]uint16, 0, last-first+1)
	for p := first; p <= last; p++ {
		ports = append(ports, uint16(p))
	}
	return PortSet{ports: ports}
}

// Union combines multiple port sets and removes duplicates.
func Union(sets ...PortSet) PortSet {
	var ports []uint16
	for _, set := range sets {
		if set.err != nil {
			return PortSet{err: set.err}
		}
		ports = append(ports, set.ports...)
	}
	return makePortSet(ports)
}

func makePortSet(ports []uint16) PortSet {
	if len(ports) == 0 {
		return PortSet{ports: []uint16{}}
	}
	sort.Slice(ports, func(i, j int) bool { return ports[i] < ports[j] })
	unique := ports[:1]
	for _, p := range ports[1:] {
		if p != unique[len(unique)-1] {
			unique = append(unique, p)
		}
	}
	return PortSet{ports: unique}
}
