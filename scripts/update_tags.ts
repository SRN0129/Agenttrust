import { execSync } from "node:child_process";
import https from "node:https";

const token = execSync('cmd.exe /c "C:\\Users\\soumy\\.tools\\gh\\gh.exe auth token"', { encoding: "utf-8" }).trim();
const latestSha = "90533fd5f75ecefed4da59dcd1da25a793d8521c";
const tags = [
  "orbital-notary-v1.0.0",
  "space-killswitch-v1.0.0",
  "doppler-ephemeris-v1.0.0",
  "qkd-witness-v1.0.0",
  "v2.0.0",
];

async function updateTag(tag: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const postData = JSON.stringify({ sha: latestSha, force: true });
    const req = https.request(
      {
        hostname: "api.github.com",
        port: 443,
        path: `/repos/SRN0129/Agenttrust/git/refs/tags/${encodeURIComponent(tag)}`,
        method: "PATCH",
        headers: {
          "User-Agent": "AgentTrust-Bot",
          Authorization: `token ${token}`,
          Accept: "application/vnd.github.v3+json",
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(postData),
        },
      },
      (res) => {
        let data = "";
        res.on("data", (c) => (data += c));
        res.on("end", () => {
          if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
            console.log(`✅ Updated tag ${tag} -> ${latestSha}`);
            resolve();
          } else {
            console.error(`❌ Failed tag ${tag}: ${res.statusCode}`);
            reject(new Error(`Failed with ${res.statusCode}`));
          }
        });
      }
    );
    req.on("error", reject);
    req.write(postData);
    req.end();
  });
}

async function main() {
  for (const t of tags) {
    try {
      await updateTag(t);
    } catch (e) {
      console.error(e);
    }
  }
}

main();
