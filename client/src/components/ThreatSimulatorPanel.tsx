import React from "react";
import { Terminal, ShieldAlert, AlertTriangle, ShieldCheck, Clock, Flame, CheckCircle } from "lucide-react";

export interface SimLog {
  id: string;
  time: string;
  stage: string;
  message: string;
  status: "success" | "warning" | "denied" | "pending";
}

interface ThreatSimulatorPanelProps {
  simLogs: SimLog[];
}

export const ThreatSimulatorPanel: React.FC<ThreatSimulatorPanelProps> = ({ simLogs }) => {
  return (
    <div className="space-y-6 animate-fade-in">
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Left 2 Cols: Live Telemetry Terminal */}
        <div className="lg:col-span-2 glass-panel rounded-xl p-5 border border-[#1E283F] flex flex-col">
          <div className="flex items-center justify-between pb-3 border-b border-[#1E283F]">
            <div className="flex items-center space-x-2">
              <Terminal className="w-4 h-4 text-emerald-400" />
              <span className="text-xs font-mono font-bold text-white tracking-wide">LIVE POLICY INTERCEPTION LOGS</span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-500/10 text-emerald-400 border border-emerald-500/30">
                Sub-1.3ms Interceptor
              </span>
            </div>
            <span className="text-xs font-mono text-slate-400">Stream: Active</span>
          </div>

          <div className="mt-4 flex-1 font-mono text-xs space-y-2 max-h-[420px] overflow-y-auto pr-2">
            {simLogs.map((log) => (
              <div
                key={log.id}
                className={`p-2.5 rounded-lg border flex items-start space-x-3 transition ${
                  log.status === "denied"
                    ? "bg-rose-950/20 border-rose-500/30 text-rose-200"
                    : log.status === "warning"
                    ? "bg-amber-950/20 border-amber-500/30 text-amber-200"
                    : log.status === "success"
                    ? "bg-emerald-950/20 border-emerald-500/30 text-emerald-200"
                    : "bg-slate-900 border-slate-700 text-slate-300"
                }`}
              >
                <span className="text-[10px] text-slate-400 shrink-0">{log.time}</span>
                <div className="shrink-0">
                  {log.status === "denied" && <ShieldAlert className="w-4 h-4 text-rose-400" />}
                  {log.status === "warning" && <AlertTriangle className="w-4 h-4 text-amber-400" />}
                  {log.status === "success" && <ShieldCheck className="w-4 h-4 text-emerald-400" />}
                  {log.status === "pending" && <Clock className="w-4 h-4 text-cyan-400" />}
                </div>
                <div className="flex-1">
                  <span className="font-bold uppercase tracking-wider text-[11px] block">{log.stage}</span>
                  <p className="text-[11px] opacity-90">{log.message}</p>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right Col: Threat Landscape & Blast Radius Stats */}
        <div className="space-y-6">
          <div className="glass-panel rounded-xl p-5 border border-[#1E283F]">
            <h3 className="text-xs font-mono font-bold text-white uppercase tracking-wider flex items-center space-x-2">
              <Flame className="w-4 h-4 text-amber-400" />
              <span>Real-Time Blast Radius Matrix</span>
            </h3>
            <p className="text-[11px] text-slate-400 mt-1">
              Continuous evaluation of agent reversibility, spend, and credential scope.
            </p>

            <div className="mt-4 space-y-3 font-mono text-xs">
              <div>
                <div className="flex justify-between text-[11px] mb-1">
                  <span className="text-slate-300">Read Actions (Tier 1: Safe)</span>
                  <span className="text-emerald-400">Score 0.10 (Auto-Allowed)</span>
                </div>
                <div className="w-full bg-[#0E1528] rounded-full h-2">
                  <div className="bg-emerald-500 h-2 rounded-full w-[15%]"></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-[11px] mb-1">
                  <span className="text-slate-300">Write / Mutate (Tier 2: Monitored)</span>
                  <span className="text-cyan-400">Score 0.45 (Rate-Governed)</span>
                </div>
                <div className="w-full bg-[#0E1528] rounded-full h-2">
                  <div className="bg-cyan-500 h-2 rounded-full w-[45%]"></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-[11px] mb-1">
                  <span className="text-slate-300">Financial / Cloud Deploy (Tier 3)</span>
                  <span className="text-amber-400">Score 0.78 (HITL Required)</span>
                </div>
                <div className="w-full bg-[#0E1528] rounded-full h-2">
                  <div className="bg-amber-500 h-2 rounded-full w-[78%]"></div>
                </div>
              </div>

              <div>
                <div className="flex justify-between text-[11px] mb-1">
                  <span className="text-slate-300">Drop Table / IAM Metadata (Tier 4)</span>
                  <span className="text-rose-400">Score 0.99 (Trapped & Denied)</span>
                </div>
                <div className="w-full bg-[#0E1528] rounded-full h-2">
                  <div className="bg-rose-500 h-2 rounded-full w-[99%]"></div>
                </div>
              </div>
            </div>
          </div>

          {/* Direct Gateway Notice */}
          <div className="p-4 rounded-xl border border-emerald-500/30 bg-emerald-950/20 text-xs">
            <div className="flex items-center space-x-2 text-emerald-400 font-semibold mb-1">
              <CheckCircle className="w-4 h-4" />
              <span>Direct Authenticated Gateway</span>
            </div>
            <p className="text-slate-300 text-[11px] leading-relaxed">
              AgentTrust strictly prohibits unauthenticated pass-through proxies. All agent tool calls and operator commands must provide a valid API Key and pass hardware-backed capability verification.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
};
