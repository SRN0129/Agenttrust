import React from "react";
import { Fingerprint, ShieldCheck } from "lucide-react";
import { AuditEvent } from "../types";

interface AuditLedgerPanelProps {
  auditEvents: AuditEvent[];
  onVerifyPQC: () => void;
}

export const AuditLedgerPanel: React.FC<AuditLedgerPanelProps> = ({
  auditEvents,
  onVerifyPQC,
}) => {
  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
        <div>
          <h3 className="text-sm font-mono font-bold text-white flex items-center space-x-2">
            <Fingerprint className="w-4 h-4 text-emerald-400" />
            <span>Immutable SHA-256 Hash Chained Audit Black Box</span>
          </h3>
          <p className="text-xs text-slate-400 mt-1">
            NIST FIPS 204 (ML-DSA) Post-Quantum attestation anchored into cryptographic Merkle leaves.
          </p>
        </div>

        <button
          onClick={onVerifyPQC}
          className="px-4 py-2 bg-[#0E1528] hover:bg-[#131D36] border border-emerald-500/40 text-emerald-300 rounded-lg text-xs font-mono transition flex items-center space-x-2"
        >
          <ShieldCheck className="w-4 h-4 text-emerald-400" />
          <span>Verify Post-Quantum Merkle Tree</span>
        </button>
      </div>

      {/* Audit Events Table */}
      <div className="glass-panel rounded-xl overflow-hidden border border-[#1E283F]">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-[#0C1222] border-b border-[#1E283F] text-slate-400">
            <tr>
              <th className="px-4 py-3">Block #</th>
              <th className="px-4 py-3">Timestamp</th>
              <th className="px-4 py-3">Action / Event</th>
              <th className="px-4 py-3">Decision</th>
              <th className="px-4 py-3">SHA-256 Entry Hash</th>
              <th className="px-4 py-3">Prev Hash Link</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1E283F]">
            {auditEvents.slice(0, 15).map((evt) => (
              <tr key={evt.eventId} className="hover:bg-white/[0.02] transition">
                <td className="px-4 py-3 text-cyan-300 font-bold">#{evt.index}</td>
                <td className="px-4 py-3 text-slate-400">{new Date(evt.timestamp).toLocaleTimeString()}</td>
                <td className="px-4 py-3">
                  <span className="text-white font-semibold">{evt.action || evt.eventType}</span>
                  <div className="text-[10px] text-slate-500">{evt.resource}</div>
                </td>
                <td className="px-4 py-3">
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                      evt.decision === "ALLOWED" || evt.decision === "SUCCESS"
                        ? "bg-emerald-500/10 text-emerald-400"
                        : evt.decision === "BLOCKED" || evt.decision === "DENIED"
                        ? "bg-rose-500/10 text-rose-400"
                        : "bg-amber-500/10 text-amber-300"
                    }`}
                  >
                    {evt.decision}
                  </span>
                </td>
                <td className="px-4 py-3 text-emerald-400 truncate max-w-xs">{evt.entryHash}</td>
                <td className="px-4 py-3 text-slate-500 truncate max-w-xs">{evt.prevHash}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
