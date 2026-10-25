import git from "isomorphic-git";
import http from "isomorphic-git/http/node";
import fs from "node:fs";
import path from "node:path";

const projectDir = path.resolve(process.cwd());

export async function stageAllFiles(baseDir = projectDir) {
  console.log("📄 Staging files recursively...");
  let count = 0;

  async function stageDirectory(dir: string) {
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
        await stageDirectory(fullPath);
      } else {
        try {
          await git.add({ fs, dir: baseDir, filepath: relativePath });
          count++;
          if (relativePath.startsWith(".github") || relativePath.endsWith(".md") || relativePath === "LICENSE") {
            console.log(`  [+] Staged: ${relativePath}`);
          }
        } catch (err: any) {
          console.warn(`Could not stage ${relativePath}:`, err.message);
        }
      }
    }
  }

  await stageDirectory(baseDir);
  console.log(`✅ Staged total of ${count} files.`);
}

export async function commitChanges(
  message = "feat(automation): add automated repo keepalive pulse, community standards, security policies, and buyer triage",
  authorName = "SRN0129",
  authorEmail = "architect@agenttrust.security"
) {
  await stageAllFiles(projectDir);

  try {
    const sha = await git.commit({
      fs,
      dir: projectDir,
      message,
      author: {
        name: authorName,
        email: authorEmail,
      },
    });
    console.log(`✅ Created commit: ${sha}`);
    return sha;
  } catch (err: any) {
    console.log(`Commit result: ${err.message}`);
    return null;
  }
}

export async function pushToGitHub(remoteUrl: string, personalAccessToken: string) {
  console.log(`🚀 Pushing main branch to: ${remoteUrl}`);

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

async function run() {
  await commitChanges();
}

if (process.argv[1]?.endsWith("git_manager.ts")) {
  run().catch(console.error);
}
