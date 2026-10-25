import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";

const ruleset = {
  name: "Enterprise Production Branch Protection",
  target: "branch",
  enforcement: "active",
  conditions: {
    ref_name: {
      include: ["refs/heads/main"],
      exclude: []
    }
  },
  rules: [
    { type: "deletion" },
    { type: "non_fast_forward" }
  ]
};

const tmpFile = path.resolve("ruleset.json");
fs.writeFileSync(tmpFile, JSON.stringify(ruleset, null, 2));

try {
  const result = execSync(
    `cmd.exe /c "C:\\Users\\soumy\\.tools\\gh\\gh.exe api -X POST repos/SRN0129/Agenttrust/rulesets --input ruleset.json"`,
    { encoding: "utf-8" }
  );
  console.log("✅ Successfully created GitHub Ruleset:", result);
} catch (err: any) {
  console.error("Ruleset error:", err.stdout || err.stderr || err.message);
} finally {
  if (fs.existsSync(tmpFile)) fs.unlinkSync(tmpFile);
}
