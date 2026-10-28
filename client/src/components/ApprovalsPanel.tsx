import React from "react";
import { Clock, CheckCircle2, Lock } from "lucide-react";
import { Approval } from "../types";

interface ApprovalsPanelProps {
  pendingApprovals: Approval[];
  onDecideApproval: (id: string, decision: "APPROVED" | "REJECTED") => void;
}

export const ApprovalsPanel: React.FC<ApprovalsPanelProps> = ({
  pendingApprovals,
  onDecideApproval,
}) => {
  return (
    <div className="space-y-6 animate-fade-in">
      <div className="p-4 rounded-xl border border-amber-500/30 bg-amber-950/20 flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <Clock className="w-5 h-5 text-amber-400" />
          <div>
            <h4 className="text-xs font-bold font-mono text-white uppercase">EU AI Act Article 14 Human Oversight Gateway</h4>
            <p className="text-[11px] text-slate-300">
              High-impact agent operations are held in isolated execution stasis until authenticated operator approval is granted.
            </p>
          </div>
        </div>
        <span className="text-xs font-mono text-amber-400 font-bold">{pendingApprovals.length} Pending Actions</span>
      </div>

      {/* Pending Approvals List */}
      {pendingApprovals.length === 0 ? (
        <div className="glass-panel rounded-xl p-8 text-center text-slate-400 font-mono text-xs">
          <CheckCircle2 className="w-8 h-8 text-emerald-400 mx-auto mb-2" />
          <p>No actions pending operator review. All autonomous runs operating within authorized thresholds.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {pendingApprovals.map((appr) => (
            <div key={appr.id} className="glass-card p-5 rounded-xl border border-amber-500/40 relative">
              <div className="flex items-start justify-between">
                <div>
                  <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
                    HITL Ticket #{appr.id.substring(0, 8)}
                  </span>
                  <h4 className="text-sm font-bold font-mono text-white mt-2">{appr.action}</h4>
                  <p className="text-xs text-slate-400 font-mono">Resource: {appr.resource}</p>
                </div>
                <span className="text-xs font-mono font-bold text-amber-400">${appr.estimatedCostUsd} USD</span>
              </div>

              <div className="mt-3 p-3 rounded-lg bg-[#07090E] border border-[#1E283F] font-mono text-[11px] text-slate-300">
                <div className="text-slate-500 mb-1">Parameters:</div>
                <pre className="text-xs text-cyan-300 overflow-x-auto">{JSON.stringify(appr.parameters, null, 2)}</pre>
              </div>

              <div className="mt-4 flex items-center justify-between text-xs font-mono">
                <span className="text-[11px] text-slate-400 flex items-center space-x-1">
                  <Lock className="w-3 h-3 text-cyan-400" />
                  <span>Single-Use Nonce Guard Active</span>
                </span>

                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => onDecideApproval(appr.id, "REJECTED")}
                    className="px-3 py-1.5 bg-rose-950/60 hover:bg-rose-900 border border-rose-600 text-rose-200 rounded-lg transition"
                  >
                    Reject
                  </button>
                  <button
                    onClick={() => onDecideApproval(appr.id, "APPROVED")}
                    className="px-4 py-1.5 bg-emerald-600 hover:bg-emerald-500 text-white font-bold rounded-lg transition shadow-lg shadow-emerald-950/50"
                  >
                    Approve Action
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};
