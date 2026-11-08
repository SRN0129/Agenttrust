import { execSync } from "node:child_process";

async function main() {
  console.log("🔍 Fetching GitHub token and branches...");
  const token = execSync('cmd.exe /c "C:\\Users\\soumy\\.tools\\gh\\gh.exe auth token"', { encoding: "utf-8" }).trim();
  const repo = "SRN0129/Agenttrust";

  // 1. Get latest commit on main
  const mainSha = execSync(`cmd.exe /c "C:\\Users\\soumy\\.tools\\gh\\gh.exe api repos/${repo}/git/ref/heads/main --jq .object.sha"`, { encoding: "utf-8" }).trim();
  console.log(`📌 Target main commit SHA: ${mainSha}`);

  // 2. Get list of all branches
  const branchesJson = execSync(`cmd.exe /c "C:\\Users\\soumy\\.tools\\gh\\gh.exe api repos/${repo}/branches --paginate"`, { encoding: "utf-8" });
  const branches: Array<{ name: string; commit: { sha: string } }> = JSON.parse(branchesJson);

  console.log(`📋 Found ${branches.length} branches on remote repository:`);
  for (const b of branches) {
    console.log(` - ${b.name} (current sha: ${b.commit.sha.substring(0, 8)})`);
  }

  // 3. Update each branch to point to main's commit
  for (const b of branches) {
    if (b.name === "main") continue;

    console.log(`🚀 Updating branch '${b.name}' to ${mainSha.substring(0, 8)}...`);
    try {
      execSync(`cmd.exe /c "C:\\Users\\soumy\\.tools\\gh\\gh.exe api -X PATCH repos/${repo}/git/refs/heads/${encodeURIComponent(b.name)} -f sha=${mainSha} -F force=true"`, {
        encoding: "utf-8",
        stdio: "pipe",
      });
      console.log(`  ✅ Successfully updated '${b.name}'!`);
    } catch (err: any) {
      console.error(`  ❌ Failed to update '${b.name}':`, err.message);
    }
  }

  console.log("🎉 All remote branches have been synchronized to main!");
}

main().catch(console.error);
