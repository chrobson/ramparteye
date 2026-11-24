package sig

import "strings"

// parseVersion splits a dotted version ("4.7", "6.4.2", "2.0.18-beta") into
// its leading numeric parts.
func parseVersion(v string) ([]int, bool) {
	var out []int
	for _, part := range strings.Split(strings.TrimSpace(v), ".") {
		n, digits := 0, 0
		for _, r := range part {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
			digits++
			if digits > 9 {
				return nil, false
			}
		}
		if digits == 0 {
			break
		}
		out = append(out, n)
		if digits != len(part) {
			break // "18-beta": keep 18, ignore the suffix and later parts
		}
	}
	return out, len(out) > 0
}

// CompareVersions compares two dotted versions numerically (missing parts
// count as 0). ok is false when either is not a version.
func CompareVersions(a, b string) (cmp int, ok bool) {
	va, okA := parseVersion(a)
	vb, okB := parseVersion(b)
	if !okA || !okB {
		return 0, false
	}
	for i := 0; i < max(len(va), len(vb)); i++ {
		x, y := 0, 0
		if i < len(va) {
			x = va[i]
		}
		if i < len(vb) {
			y = vb[i]
		}
		if x != y {
			if x < y {
				return -1, true
			}
			return 1, true
		}
	}
	return 0, true
}
