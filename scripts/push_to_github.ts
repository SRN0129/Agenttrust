import { pushToGitHub } from "./git_manager.js";

async function main() {
  const args = process.argv.slice(2);
  let repoUrl = process.env.GITHUB_REPO_URL || "";
  let token = process.env.GITHUB_TOKEN || "";

  for (let i = 0; i < args.length; i++) {
    if (args[i] === "--repo" && args[i + 1]) repoUrl = args[i + 1];
    if (args[i] === "--token" && args[i + 1]) token = args[i + 1];
  }

  if (!repoUrl || !token) {
    console.error("Usage: npx tsx scripts/push_to_github.ts --repo <https://github.com/USERNAME/REPO.git> --token <GITHUB_PERSONAL_ACCESS_TOKEN>");
    process.exit(1);
  }

  await pushToGitHub(repoUrl, token);
}

main().catch(console.error);
