import React, { useState } from "react";
import { Search, Sliders } from "lucide-react";
import { Policy } from "../types";

interface PoliciesPanelProps {
  policies: Policy[];
  onOpenPolicyModal: () => void;
}

export const PoliciesPanel: React.FC<PoliciesPanelProps> = ({
  policies,
  onOpenPolicyModal,
}) => {
  const [search, setSearch] = useState("");

  const filtered = policies.filter(
    (p) =>
      p.name.toLowerCase().includes(search.toLowerCase()) ||
      p.action_pattern.toLowerCase().includes(search.toLowerCase()) ||
      p.resource_pattern.toLowerCase().includes(search.toLowerCase()) ||
      p.effect.toLowerCase().includes(search.toLowerCase())
  );

  return (
    <div className="space-y-6 animate-fade-in">
      <div className="flex flex-col sm:flex-row items-center justify-between gap-4">
        <div className="relative w-full sm:w-72">
          <Search className="w-4 h-4 absolute left-3 top-3 text-slate-400" />
          <input
            type="text"
            placeholder="Search policies by action, effect..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            className="w-full pl-9 pr-4 py-2 bg-[#0E1528] border border-[#1E283F] rounded-lg text-xs font-mono text-white focus:outline-none focus:border-cyan-500"
          />
        </div>

        <button
          onClick={onOpenPolicyModal}
          className="px-4 py-2 bg-gradient-to-r from-cyan-600 to-blue-600 hover:from-cyan-500 hover:to-blue-500 text-white rounded-lg text-xs font-semibold font-mono transition flex items-center space-x-2"
        >
          <Sliders className="w-3.5 h-3.5" />
          <span>Create Zero-Trust Policy</span>
        </button>
      </div>

      {/* Policy Table */}
      <div className="glass-panel rounded-xl overflow-hidden border border-[#1E283F]">
        <table className="w-full text-left text-xs font-mono">
          <thead className="bg-[#0C1222] border-b border-[#1E283F] text-slate-400">
            <tr>
              <th className="px-4 py-3">Policy Rule</th>
              <th className="px-4 py-3">Action Pattern</th>
              <th className="px-4 py-3">Target Resource</th>
              <th className="px-4 py-3">Effect</th>
              <th className="px-4 py-3">Spend Ceiling</th>
              <th className="px-4 py-3">Priority</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1E283F]">
            {filtered.map((p) => (
              <tr key={p.id} className="hover:bg-white/[0.02] transition">
                <td className="px-4 py-3">
                  <div className="font-bold text-white">{p.name}</div>
                  <div className="text-[10px] text-slate-400">{p.description}</div>
                </td>
                <td className="px-4 py-3 text-cyan-300">{p.action_pattern}</td>
                <td className="px-4 py-3 text-slate-300">{p.resource_pattern}</td>
                <td className="px-4 py-3">
                  <span
                    className={`text-[10px] px-2 py-0.5 rounded font-bold ${
                      p.effect === "ALLOW"
                        ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/30"
                        : p.effect === "DENY"
                        ? "bg-rose-500/10 text-rose-400 border border-rose-500/30"
                        : "bg-amber-500/10 text-amber-300 border border-amber-500/30"
                    }`}
                  >
                    {p.effect}
                  </span>
                </td>
                <td className="px-4 py-3 text-slate-300">${p.max_cost_usd} USD</td>
                <td className="px-4 py-3 text-slate-400">{p.priority}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
};
