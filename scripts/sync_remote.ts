import { execSync } from "node:child_process";
import { commitChanges, pushToGitHub } from "./git_manager.js";

async function main() {
  console.log("🔍 Getting GitHub CLI token...");
  const token = execSync('cmd.exe /c "C:\\Users\\soumy\\.tools\\gh\\gh.exe auth token"', { encoding: "utf-8" }).trim();
  const repoUrl = "https://github.com/SRN0129/Agenttrust.git";

  console.log("📦 Staging & Committing CodeQL security fixes & CI workflow repairs...");
  await commitChanges(
    "fix(security): resolve CodeQL alerts, add HMAC salt, fix CI unittest discovery, and update security policy"
  );

  console.log("🚀 Pushing all updates to remote repository...");
  await pushToGitHub(repoUrl, token);
  console.log("🌟 Synchronized successfully with GitHub!");
}

main().catch(console.error);
