# AgentTrust Rust SDK

Official Rust bindings and middleware client for [AgentTrust](https://github.com/SRN0129/Agenttrust), an enterprise-grade autonomous agent security gateway and policy enforcement engine.

## Usage

Add to your `Cargo.toml`:

```toml
[dependencies]
agenttrust = { git = "https://github.com/SRN0129/Agenttrust", package = "agenttrust" }
```

## Example: Quantum Circuit Static Inspection

```rust
use agenttrust::QuantumCircuitParser;

fn main() {
    let qasm = r#"
        OPENQASM 2.0;
        include "qelib1.inc";
        qreg q[8];
        h q[0];
        cx q[0], q[1];
    "#;

    let metrics = QuantumCircuitParser::parse_qasm(qasm);
    println!("Qubit count: {}", metrics.qubit_count);
    println!("Gate count: {}", metrics.total_gate_count);
    println!("Estimated fidelity: {}", metrics.estimated_fidelity);
}
```
