// ==============================================================================
// AgentTrust Quantum Circuit Benchmark: Variational Quantum Eigensolver (VQE)
// Hardware-efficient parameterized ansatz for molecular ground state simulation
// ==============================================================================
OPENQASM 2.0;
include "qelib1.inc";

qreg q[4];
creg c[4];

// Layer 1: Parameterized single-qubit rotations
ry(0.785398) q[0];
rz(1.570796) q[0];
ry(0.523598) q[1];
rz(3.141592) q[1];
ry(1.047197) q[2];
rz(0.0) q[2];
ry(2.094395) q[3];
rz(0.785398) q[3];

// Entanglement layer: Linear CNOT chain
cx q[0], q[1];
cx q[1], q[2];
cx q[2], q[3];
cx q[3], q[0];

// Layer 2: Second variational rotation layer
ry(0.392699) q[0];
rz(0.785398) q[0];
ry(1.178097) q[1];
rz(2.356194) q[1];
ry(0.196349) q[2];
rz(1.570796) q[2];
ry(2.748893) q[3];
rz(3.141592) q[3];

// Measurement in computational basis
measure q[0] -> c[0];
measure q[1] -> c[1];
measure q[2] -> c[2];
measure q[3] -> c[3];
