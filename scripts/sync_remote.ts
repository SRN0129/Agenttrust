import { execSync } from "node:child_process";
import { commitChanges, pushToGitHub } from "./git_manager.js";

async function main() {
  console.log("🔍 Getting GitHub CLI token...");
  const token = execSync('cmd.exe /c "C:\\Users\\soumy\\.tools\\gh\\gh.exe auth token"', { encoding: "utf-8" }).trim();
  const repoUrl = "https://github.com/SRN0129/Agenttrust.git";

  console.log("📦 Staging & Committing UI/UX overhaul, authenticated gateway, and GitHub README...");
  await commitChanges(
    "feat(ui/ux): overhaul dashboard to advanced secops aesthetic, direct authenticated gateway, interactive threat simulator, and updated README"
  );

  console.log("🚀 Pushing all updates to remote repository on GitHub...");
  await pushToGitHub(repoUrl, token, true);
  console.log("🎉 Synchronized and pushed successfully to GitHub!");
}

main().catch(console.error);
