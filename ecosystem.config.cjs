// PM2 process config for fed-oidfed-com.
// Naming: `.cjs` is mandatory because package.json sets "type": "module" —
// PM2 reads the file as CommonJS regardless of the ESM context.
//
// Usage:
//
//   First-time start (production env block):
//     pm2 start ecosystem.config.cjs --env production
//     pm2 save
//
//   Zero-downtime reload after a rebuild:
//     pm2 reload ecosystem.config.cjs --env production
//
//   Idempotent form for redeploy scripts:
//     pm2 startOrReload ecosystem.config.cjs --env production
//
//   Boot-on-restart (one-time, generates a systemd unit owned by pm2):
//     pm2 startup systemd
//     # paste back the command it prints, then:
//     pm2 save

module.exports = {
	apps: [
		{
			name: "fed-oidfed-com",
			script: "./dist/index.js",
			cwd: __dirname,

			// One Node process — the in-process vhost dispatcher serves all 36 hostnames.
			// Cluster mode would shard the listener but in-memory stores would diverge per worker.
			instances: 1,
			exec_mode: "fork",

			// Hard guardrails
			autorestart: true,
			watch: false,
			max_memory_restart: "512M",
			min_uptime: "10s",
			max_restarts: 10,

			// Graceful shutdown — give the HTTP server time to drain in-flight requests.
			kill_timeout: 10_000,
			listen_timeout: 5_000,
			wait_ready: false,

			// Logs land at PM2's defaults: ~/.pm2/logs/fed-oidfed-com-{out,error}.log
			merge_logs: true,
			time: true,

			// Local dev (`pm2 start ecosystem.config.cjs` with no --env flag)
			env: {
				NODE_ENV: "development",
				PORT: 3000,
				HOST: "127.0.0.1",
			},

			// Production (`pm2 start ecosystem.config.cjs --env production`)
			env_production: {
				NODE_ENV: "production",
				PORT: 3000,
				HOST: "127.0.0.1",
				// FED_OIDFED_KEYS_DIR defaults to ~/.fed-oidfed via os.homedir() —
				// set explicitly here only if you want a non-home location.
			},
		},
	],
};
