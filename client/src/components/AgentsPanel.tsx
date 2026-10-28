import React, { useState } from "react";
import { Search, GitBranch, Shield, Copy, Check } from "lucide-react";
import { Agent } from "../types";

interface AgentsPanelProps {
  agents: Agent[];
  onOpenRegisterModal: () => void;
  onOpenDelegateModal: () => void;
}

export const AgentsPanel: React.FC<AgentsPanelProps> = ({
  agents,
  onOpenRegisterModal,
  onOpenDelegateModal,
}) => {
  const [search, setSearch] = useState("");
  const [copiedKey, setCopiedKey] = useState<string | null>(null);

  const handleCopy = (keyText: string, agentId: string) => {
    navigator.clipboard.writeText(keyText);
    setCopiedKey(agentId);
    setTimeout(() => setCopiedKey(null), 2000);
  };

  const filtered = agents.filter(
    (a) =>
      a.name.toLowerCase().includes(search.toLowerCase()) ||
      a.framework.toLowerCase().includes(search.toLowerCase()) ||
      a.operatorEmail.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 absolute left-3 top-3 text-slate-400" />
          <input
            type="text"
            placeholder="Filter agents by name, framework..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-[#0E1528] border border-[#1E283F] rounded-lg text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
          />
        </div>

        <div className="flex items-center space-x-3 w-full sm:w-auto">
          <button
            onClick={onOpenDelegateModal}
            className="px-3.5 py-2 bg-[#0E1528] hover:bg-[#131D36] border border-cyan-500/40 text-cyan-300 rounded-lg text-xs font-mono transition flex items-center space-x-2"
          >
            <GitBranch className="w-3.5 h-3.5" />
            <span>Spawn Subagent Swarm</span>
          </button>

          <button
            onClick={onOpenRegisterModal}
            className="px-4 py-2 bg-gradient-to-r from-emerald-600 to-teal-600 hover:from-emerald-500 hover:to-teal-500 text-white rounded-lg text-xs font-semibold font-mono transition flex items-center space-x-2 shadow-lg shadow-emerald-950/40"
          >
            <Shield className="w-3.5 h-3.5" />
            <span>Register Autonomous Agent</span>
          </button>
        </div>
      </div>

      {/* Agent Cards Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {filtered.map((agent) => (
          <div key={agent.id} className="glass-card p-5 rounded-xl border border-[#1E283F] flex flex-col justify-between">
            <div>
              <div className="flex items-start justify-between">
                <div>
                  <div className="flex items-center space-x-2">
                    <h4 className="text-sm font-bold text-white font-mono">{agent.name}</h4>
                    <span
                      className={`text-[10px] font-mono px-2 py-0.5 rounded-full ${
                        agent.status === "ACTIVE"
                          ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                          : "bg-rose-500/10 text-rose-400 border border-rose-500/30"
                      }`}
                    >
                      {agent.status}
                    </span>
                  </div>
                  <p className="text-xs text-slate-400 mt-1">{agent.description}</p>
                </div>
                <span className="text-[10px] font-mono bg-[#1E283F] text-slate-300 px-2 py-0.5 rounded">
                  {agent.framework}
                </span>
              </div>

              {/* Spend & Rate Limit Gauge */}
              <div className="mt-4 pt-3 border-t border-[#1E283F] space-y-2 font-mono text-xs">
                <div>
                  <div className="flex justify-between text-[11px] mb-1">
                    <span className="text-slate-400">Micro-Budget Spend:</span>
                    <span className="text-emerald-300 font-semibold">
                      ${agent.currentSpendUsd.toFixed(2)} / ${agent.spendLimitUsd.toFixed(2)} USD
                    </span>
                  </div>
                  <div className="w-full bg-[#0E1528] rounded-full h-1.5">
                    <div
                      className="bg-emerald-500 h-1.5 rounded-full"
                      style={{
                        width: `${Math.min(100, (agent.currentSpendUsd / (agent.spendLimitUsd || 1)) * 100)}%`,
                      }}
                    ></div>
                  </div>
                </div>

                <div className="flex justify-between text-[11px] text-slate-400">
                  <span>Velocity Cap:</span>
                  <span className="text-cyan-300">{agent.rateLimitRpm} RPM</span>
                </div>

                {agent.parentAgentId && (
                  <div className="flex items-center space-x-1 text-[11px] text-violet-400 bg-violet-950/30 p-1.5 rounded border border-violet-500/20">
                    <GitBranch className="w-3 h-3" />
                    <span>Child of: {agent.parentAgentId.substring(0, 10)}... (Attenuated)</span>
                  </div>
                )}
              </div>

              {/* Capabilities Chips */}
              <div className="mt-3 flex flex-wrap gap-1">
                {agent.allowedCapabilities.slice(0, 3).map((cap, i) => (
                  <span key={i} className="text-[10px] font-mono bg-[#0E1528] text-slate-300 border border-[#1E283F] px-1.5 py-0.5 rounded">
                    {cap}
                  </span>
                ))}
                {agent.allowedCapabilities.length > 3 && (
                  <span className="text-[10px] font-mono text-slate-500">
                    +{agent.allowedCapabilities.length - 3} more
                  </span>
                )}
              </div>
            </div>

            <div className="mt-4 pt-3 border-t border-[#1E283F] flex items-center justify-between text-xs font-mono">
              <span className="text-[11px] text-slate-500">Key: at_live_{agent.apiKeyPrefix}***</span>
              <button
                onClick={() => handleCopy(`at_live_${agent.apiKeyPrefix}demo_token`, agent.id)}
                className="text-cyan-400 hover:text-cyan-300 flex items-center space-x-1"
              >
                {copiedKey === agent.id ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                <span className="text-[11px]">Copy API Key</span>
              </button>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
};
