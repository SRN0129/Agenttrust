import { execSync } from "node:child_process";
import { commitChanges, pushToGitHub } from "./git_manager.js";

async function main() {
  console.log("🔍 Getting GitHub CLI token...");
  const token = execSync('cmd.exe /c "C:\\Users\\soumy\\.tools\\gh\\gh.exe auth token"', { encoding: "utf-8" }).trim();
  const repoUrl = "https://github.com/SRN0129/Agenttrust.git";

  console.log("📦 Staging & Committing enterprise roadmap implementations...");
  await commitChanges(
    "feat(enterprise): cloud egress connectors, nitro enclaves, TPM2 notary, multi-QPU routing, and NIST FIPS 204 PQC attestation (closes #15, #16, #17, #18, #19, #20, #21)"
  );

  console.log("🚀 Pushing all updates to remote repository...");
  await pushToGitHub(repoUrl, token, true);
  console.log("🌟 Synchronized successfully with GitHub!");
}

main().catch(console.error);
