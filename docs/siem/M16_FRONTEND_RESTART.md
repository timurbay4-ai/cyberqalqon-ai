# M16 frontend restart

Root cause: the local frontend is a Vite development server and had no existing
Windows service, scheduled task or repository startup supervisor. A host restart
therefore terminated it, while the backend/WSL services recovered independently.
No frontend source or proxy defect was required to explain the missing listener.

M16 adds two non-privileged application-level scripts:

- `scripts/Start-CyberQalqonFrontend.ps1` validates the repository, refuses a
  privileged port, requires backend health, avoids a duplicate healthy listener,
  starts Vite on `127.0.0.1:5173` with `strictPort`, and uses a bounded 30-second
  health wait. It writes ignored runtime status/log files and terminates only the
  process it created when startup fails.
- `scripts/Test-CyberQalqonFrontend.ps1` verifies backend, frontend root and proxy
  health plus the loopback listener without using a browser.

The recovered frontend, proxy and backend returned HTTP 200. The recorded Vite
listener was the actual Node process rather than only its launcher. Re-running
the start script against a healthy listener is idempotent.

No scheduled task or privileged Windows service was created. If automatic
post-reboot startup is required, the exact Task Scheduler change needs a separate
approval and should depend on backend readiness. Real Chrome/Edge UAT is
`DEFERRED_BY_USER`.
