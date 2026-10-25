import { createApp } from "./app.js";
import { seedDatabase } from "./db/seed.js";
import dotenv from "dotenv";

dotenv.config();

const PORT = Number(process.env.PORT) || 4000;

const { app } = createApp();

// Seed initial environment if empty
try {
  seedDatabase();
} catch (err) {
  console.error("Seeding warning:", err);
}

const server = app.listen(PORT, () => {
  console.log(`=======================================================`);
  console.log(`🛡️  AgentTrust AI Agent Trust Infrastructure (Active)`);
  console.log(`📍 API Gateway running on: http://localhost:${PORT}`);
  console.log(`🔍 Health Check:          http://localhost:${PORT}/health`);
  console.log(`📜 Audit Verification:   http://localhost:${PORT}/api/v1/audit/verify`);
  console.log(`=======================================================`);
});

process.on("SIGTERM", () => {
  server.close(() => {
    console.log("AgentTrust server gracefully terminated");
  });
});
