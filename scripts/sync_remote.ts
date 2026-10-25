import { execSync } from "node:child_process";
import { commitChanges, pushToGitHub } from "./git_manager.js";

async function main() {
  console.log("🔍 Getting GitHub CLI token...");
  const token = execSync('cmd.exe /c "C:\\Users\\soumy\\.tools\\gh\\gh.exe auth token"', { encoding: "utf-8" }).trim();
  const repoUrl = "https://github.com/SRN0129/Agenttrust.git";

  console.log("📦 Staging & Committing repository hardening & viral launch suite...");
  await commitChanges(
    "feat: harden DNS rebinding, offline vector embeddings, subprocess sandboxing, academic whitepaper, and zero-dollar launch kit"
  );

  console.log("🚀 Pushing all updates to remote repository...");
  await pushToGitHub(repoUrl, token);
  console.log("🌟 Synchronized successfully with GitHub!");
}

main().catch(console.error);
