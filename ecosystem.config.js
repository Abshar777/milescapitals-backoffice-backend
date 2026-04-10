module.exports = {
  apps: [
    // ─────────────────────────────────────────────
    // Miles AC — Backend (FastAPI / Uvicorn)
    // Env loaded from: .env
    // ─────────────────────────────────────────────
    {
      name: "miles-backend",
      script: "venv/bin/uvicorn",
      args: "server:app --host 0.0.0.0 --port 8000 --workers 1",
      cwd: __dirname,
      interpreter: "none",
      watch: false,
      autorestart: true,
      max_restarts: 10,
      restart_delay: 3000,
      max_memory_restart: "512M",
      log_date_format: "YYYY-MM-DD HH:mm:ss",
      error_file: "./logs/error.log",
      out_file: "./logs/out.log",
      merge_logs: true,
    },
  ],
};
