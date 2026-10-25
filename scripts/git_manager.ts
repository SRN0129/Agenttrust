import git from "isomorphic-git";
import http from "isomorphic-git/http/node";
import fs from "node:fs";
import path from "node:path";

const projectDir = path.resolve(process.cwd());

export async function initAndCommitRepo(authorName = "AgentTrust Architect", authorEmail = "architect@agenttrust.security") {
  console.log("📦 Initializing Git repository in:", projectDir);
  await git.init({ fs, dir: projectDir, defaultBranch: "main" });

  console.log("📄 Staging tracked files according to .gitignore...");
  
  // Recursively add files
  async function stageDirectory(dir: string, baseDir: string) {
    const entries = fs.readdirSync(dir, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dir, entry.name);
      const relativePath = path.relative(baseDir, fullPath).replace(/\\/g, "/");

      // Skip ignored directories
      if (
        relativePath.startsWith("node_modules") ||
        relativePath.startsWith("client/node_modules") ||
        relativePath.startsWith("dist") ||
        relativePath.startsWith("client/dist") ||
        relativePath.startsWith("data") ||
        relativePath === ".git" ||
        relativePath.startsWith(".git/") ||
        relativePath.startsWith(".git\\") ||
        entry.name.endsWith(".db") ||
        entry.name.endsWith(".log")
      ) {
        continue;
      }

      if (entry.isDirectory()) {
        await stageDirectory(fullPath, baseDir);
      } else {
        try {
          await git.add({ fs, dir: baseDir, filepath: relativePath });
        } catch (err: any) {
          console.warn(`Could not stage ${relativePath}:`, err.message);
        }
      }
    }
  }

  await stageDirectory(projectDir, projectDir);

  console.log("✍️ Creating initial commit...");
  const sha = await git.commit({
    fs,
    dir: projectDir,
    message: "feat: AgentTrust - Enterprise AI Agent Trust & Zero-Trust Security Infrastructure\n\n- Deny-by-default policy enforcement\n- Cascading multi-agent delegation & capability attenuation\n- Semantic blast radius & reversibility scoring\n- Human-in-the-loop approvals with 1-click mobile push callback\n- Single-use execution nonces & atomic replay defense\n- Hash-linked verifiable audit ledger\n- ECDSA P-256 digital signature checkpoint notarization\n- Emergency air-gap global killswitch\n- Transparent egress proxy & prompt injection/data leak scanner\n- EU AI Act Art. 12/14 & NIST AI RMF compliance dashboard\n- 41 automated security tests passing",
    author: {
      name: authorName,
      email: authorEmail,
    },
  });

  console.log(`✅ Git commit created successfully! Commit SHA: ${sha}`);
  return sha;
}

export async function pushToGitHub(remoteUrl: string, personalAccessToken: string) {
  console.log(`🚀 Pushing main branch to: ${remoteUrl}`);
  
  // Add or update remote origin
  try {
    await git.deleteRemote({ fs, dir: projectDir, remote: "origin" });
  } catch {
    // Ignore if not present
  }

  await git.addRemote({
    fs,
    dir: projectDir,
    remote: "origin",
    url: remoteUrl,
  });

  const pushResult = await git.push({
    fs,
    http,
    dir: projectDir,
    remote: "origin",
    ref: "main",
    onAuth: () => ({
      username: personalAccessToken,
      password: "",
    }),
  });

  console.log("🎉 Successfully pushed to GitHub!", pushResult);
  return pushResult;
}

// Direct CLI execution
initAndCommitRepo().catch(console.error);
