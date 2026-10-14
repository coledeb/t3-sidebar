# T3 Sidebar

The T3 Code web app in a Cursor/VS Code sidebar, with working copy and paste.

- Opens on startup in its own activity-bar view. Drag it to the secondary sidebar once; Cursor remembers.
- Signs in automatically the first time by issuing a 5-minute pairing token with the `t3` CLI.
- Paste: Cmd+V inside the view is routed through the extension's clipboard access.
  Plain text only; pasting images is not supported.

A local relay on `127.0.0.1:37730` serves the page, keeps the T3 session cookie,
and injects `shim.js`. It only answers requests from the sidebar itself.

Commands: **T3 Sidebar: Reload**, **T3 Sidebar: Pair Again**, **T3 Sidebar: Show Log**.

Build: `npx @vscode/vsce package --skip-license --allow-missing-repository`
