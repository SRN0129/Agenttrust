// ==============================================================================
// AgentTrust Quantum Circuit Benchmark: 8-Qubit Grover Unstructured Search
// OpenQASM 2.0 Specification
// Used for static gate depth, qubit quota, and circuit breaker compliance
// ==============================================================================
OPENQASM 2.0;
include "qelib1.inc";

qreg q[8];
creg c[8];

// State initialization: Uniform superposition via Hadamard layer
h q[0];
h q[1];
h q[2];
h q[3];
h q[4];
h q[5];
h q[6];
h q[7];

// Oracle layer: Phase inversion for target marked state |11111111>
cz q[0], q[1];
cz q[2], q[3];
cz q[4], q[5];
cz q[6], q[7];
cx q[1], q[2];
cx q[3], q[4];
cx q[5], q[6];

// Diffusion Operator (Inversion about the mean)
h q[0];
h q[1];
h q[2];
h q[3];
h q[4];
h q[5];
h q[6];
h q[7];

x q[0];
x q[1];
x q[2];
x q[3];
x q[4];
x q[5];
x q[6];
x q[7];

cz q[0], q[1];
cz q[2], q[3];
cz q[4], q[5];
cz q[6], q[7];

x q[0];
x q[1];
x q[2];
x q[3];
x q[4];
x q[5];
x q[6];
x q[7];

h q[0];
h q[1];
h q[2];
h q[3];
h q[4];
h q[5];
h q[6];
h q[7];

// Final measurement
measure q[0] -> c[0];
measure q[1] -> c[1];
measure q[2] -> c[2];
measure q[3] -> c[3];
measure q[4] -> c[4];
measure q[5] -> c[5];
measure q[6] -> c[6];
measure q[7] -> c[7];
