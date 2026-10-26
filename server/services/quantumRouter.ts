import { QuantumCircuitInspectionResult } from "./quantumTrust.js";

export interface QuantumRoutingDecision {
  targetBackend: "IBM_QUANTUM_HERON" | "AWS_BRAKET_IONQ_ARIA" | "LOCAL_STATEVECTOR_SIM";
  maxPermittedShots: number;
  entanglementBudgetTier: "LOW" | "STANDARD" | "HIGH_DENSITY";
  estimatedCostUsd: number;
  routingReason: string;
}

/**
 * Dynamic Multi-QPU Workload Scheduler & Entanglement Budget Manager
 * Routes quantum circuits between IBM Quantum, AWS Braket, and local statevector simulators
 * based on two-qubit gate density and entanglement budgets.
 */
export class QuantumWorkloadRouter {
  public static routeCircuit(inspection: QuantumCircuitInspectionResult): QuantumRoutingDecision {
    const twoQubitCount = inspection.circuitMetrics?.twoQubitGateCount || 0;
    const qubitCount = inspection.circuitMetrics?.qubitCount || 0;

    // Small or shallow circuits route to local statevector simulator for zero financial cost
    if (qubitCount <= 12 && twoQubitCount <= 20) {
      return {
        targetBackend: "LOCAL_STATEVECTOR_SIM",
        maxPermittedShots: inspection.maxRecommendedShots,
        entanglementBudgetTier: "LOW",
        estimatedCostUsd: 0.0,
        routingReason: "Circuit fits within local statevector simulation boundaries; zero QPU cost applied.",
      };
    }

    // High two-qubit gate count (entangled) circuits route to high-fidelity trapped-ion backends
    if (twoQubitCount > 40) {
      return {
        targetBackend: "AWS_BRAKET_IONQ_ARIA",
        maxPermittedShots: Math.min(inspection.maxRecommendedShots, 1000),
        entanglementBudgetTier: "HIGH_DENSITY",
        estimatedCostUsd: inspection.estimatedQpuCostUsd * 1.25,
        routingReason: "Deep two-qubit gate chain routed to all-to-all trapped-ion topology for maximum fidelity.",
      };
    }

    // Standard intermediate circuits route to superconducting QPUs
    return {
      targetBackend: "IBM_QUANTUM_HERON",
      maxPermittedShots: inspection.maxRecommendedShots,
      entanglementBudgetTier: "STANDARD",
      estimatedCostUsd: inspection.estimatedQpuCostUsd,
      routingReason: "Routed to superconducting tunable-coupler architecture.",
    };
  }
}
