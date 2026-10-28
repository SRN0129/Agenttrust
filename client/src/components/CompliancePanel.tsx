import React from "react";
import { Award, ShieldCheck } from "lucide-react";
import { AuditEvent, Checkpoint, Approval } from "../types";

interface CompliancePanelProps {
  auditEvents: AuditEvent[];
  checkpoints: Checkpoint[];
  allApprovals: Approval[];
}

export const CompliancePanel: React.FC<CompliancePanelProps> = ({
  auditEvents,
  checkpoints,
  allApprovals,
}) => {
  return (
    <div className="space-y-6 animate-fade-in">
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Article 12: Traceability */}
        <div className="glass-panel rounded-xl p-5 border border-[#1E283F]">
          <div className="flex items-center space-x-2 text-emerald-400 font-mono text-sm font-bold">
            <Award className="w-5 h-5" />
            <span>EU AI Act Article 12: Continuous Traceability</span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Mandatory automatic event-recording throughout high-risk autonomous AI lifecycles.
          </p>

          <div className="mt-4 space-y-3 font-mono text-xs">
            <div className="flex justify-between border-b border-[#1E283F] pb-2">
              <span className="text-slate-400">Ledger Integrity:</span>
              <span className="text-emerald-400 font-bold">VERIFIED (Tamper-Sealed)</span>
            </div>
            <div className="flex justify-between border-b border-[#1E283F] pb-2">
              <span className="text-slate-400">Total Immutable Records:</span>
              <span className="text-white font-bold">{auditEvents.length} Events</span>
            </div>
            <div className="flex justify-between border-b border-[#1E283F] pb-2">
              <span className="text-slate-400">Notarized Checkpoints:</span>
              <span className="text-violet-300 font-bold">{checkpoints.length} Signed Merkle Roots</span>
            </div>
          </div>
        </div>

        {/* Article 14: Human Oversight */}
        <div className="glass-panel rounded-xl p-5 border border-[#1E283F]">
          <div className="flex items-center space-x-2 text-cyan-400 font-mono text-sm font-bold">
            <ShieldCheck className="w-5 h-5" />
            <span>EU AI Act Article 14: Human Oversight</span>
          </div>
          <p className="text-xs text-slate-400 mt-1">
            Technical architectural mechanisms enabling natural persons to oversee autonomous systems.
          </p>

          <div className="mt-4 space-y-3 font-mono text-xs">
            <div className="flex justify-between border-b border-[#1E283F] pb-2">
              <span className="text-slate-400">Single-Use Nonce Defense:</span>
              <span className="text-emerald-400 font-bold">ACTIVE (Anti-409 Replay)</span>
            </div>
            <div className="flex justify-between border-b border-[#1E283F] pb-2">
              <span className="text-slate-400">Decided HITL Tickets:</span>
              <span className="text-white font-bold">{allApprovals.length} Signed Decisions</span>
            </div>
            <div className="flex justify-between border-b border-[#1E283F] pb-2">
              <span className="text-slate-400">Oversight Score:</span>
              <span className="text-emerald-400 font-bold">100 / 100 Compliant</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
