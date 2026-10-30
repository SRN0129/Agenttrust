import git from "isomorphic-git";
import http from "isomorphic-git/http/node";
import fs from "node:fs";
import path from "node:path";
import { execSync } from "node:child_process";
import { stageAllFiles } from "./git_manager.js";

const projectDir = path.resolve(process.cwd());

async function main() {
  console.log("🔍 Fetching token...");
  const token = execSync('cmd.exe /c "C:\\Users\\soumy\\.tools\\gh\\gh.exe auth token"', { encoding: "utf-8" }).trim();
  const repoUrl = "https://github.com/SRN0129/Agenttrust.git";

  console.log("📥 Fetching remote main...");
  await git.fetch({
    fs,
    http,
    dir: projectDir,
    url: repoUrl,
    ref: "main",
    onAuth: () => ({ username: token, password: "" }),
  });

  // Get remote HEAD sha
  const remoteRef = await git.resolveRef({
    fs,
    dir: projectDir,
    ref: "refs/remotes/origin/main",
  }).catch(async () => {
    // If not in remotes/origin/main, query directly from GitHub API
    const sha = execSync('cmd.exe /c "C:\\Users\\soumy\\.tools\\gh\\gh.exe api repos/SRN0129/Agenttrust/git/ref/heads/main --jq .object.sha"', { encoding: "utf-8" }).trim();
    return sha;
  });

  console.log(`📌 Remote main is at: ${remoteRef}`);

  // Stage all current files
  await stageAllFiles(projectDir);

  // Create commit with remoteRef as parent (clean fast-forward!)
  const commitMsg = "feat(demo): enable live interactive GitHub Pages SOC dashboard with mock fallback & automated deployment";
  
  const commitSha = await git.commit({
    fs,
    dir: projectDir,
    message: commitMsg,
    parent: [remoteRef],
    author: {
      name: "SRN0129",
      email: "156065436+SRN0129@users.noreply.github.com",
    },
  });
  console.log(`✅ Created fast-forward commit on top of remote: ${commitSha}`);

  // Update local ref to point to new commit
  await git.writeRef({
    fs,
    dir: projectDir,
    ref: "refs/heads/main",
    value: commitSha,
    force: true,
  });

  // Push to remote main
  console.log("🚀 Pushing fast-forward commit to remote...");
  const pushRes = await git.push({
    fs,
    http,
    dir: projectDir,
    url: repoUrl,
    ref: "main",
    onAuth: () => ({ username: token, password: "" }),
  });

  console.log("🎉 Successfully pushed to remote main!", pushRes);
}

main().catch(console.error);
