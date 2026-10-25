package agenttrust

import (
	"math"
	"regexp"
	"strconv"
	"strings"
)

var (
	qubitRegexp = regexp.MustCompile(`qreg\s+([a-zA-Z0-9_]+)\[(\d+)\];`)
	qubit3Regexp = regexp.MustCompile(`qubit\[(\d+)\]\s+([a-zA-Z0-9_]+);`)
	measureRegexp = regexp.MustCompile(`(measure|->)`)
	twoQubitRegexp = regexp.MustCompile(`\b(cx|cz|swap|iswap|cphase|cp|ecr|crx|cry|crz)\b`)
	singleQubitRegexp = regexp.MustCompile(`\b(h|x|y|z|s|sdg|t|tdg|rx|ry|rz|u1|u2|u3|p|id)\b`)
)

// ParseQASM analyzes an OpenQASM 2.0 or 3.0 circuit string and returns structural metrics.
func ParseQASM(qasmCode string) QuantumCircuitMetrics {
	lines := strings.Split(qasmCode, "\n")
	qubitCount := 0
	totalGates := 0
	twoQubitGates := 0
	measurements := 0

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "//") || trimmed == "" {
			continue
		}

		// Detect qubit registers
		if match := qubitRegexp.FindStringSubmatch(trimmed); len(match) == 3 {
			if count, err := strconv.Atoi(match[2]); err == nil {
				qubitCount += count
			}
			continue
		}
		if match := qubit3Regexp.FindStringSubmatch(trimmed); len(match) == 3 {
			if count, err := strconv.Atoi(match[1]); err == nil {
				qubitCount += count
			}
			continue
		}

		// Measurements
		if measureRegexp.MatchString(trimmed) {
			measurements++
			continue
		}

		// Two-qubit gates
		if twoQubitRegexp.MatchString(trimmed) {
			twoQubitGates++
			totalGates++
			continue
		}

		// Single-qubit gates
		if singleQubitRegexp.MatchString(trimmed) {
			totalGates++
			continue
		}
	}

	// Calculate rough estimated fidelity assuming 99.9% 1Q and 99.0% 2Q gate fidelities
	oneQubitGates := totalGates - twoQubitGates
	fidelity := math.Pow(0.999, float64(oneQubitGates)) * math.Pow(0.990, float64(twoQubitGates))

	return QuantumCircuitMetrics{
		QubitCount:        qubitCount,
		TotalGateCount:    totalGates,
		TwoQubitGateCount: twoQubitGates,
		MeasurementCount:  measurements,
		EstimatedFidelity: math.Round(fidelity*10000) / 10000,
	}
}
