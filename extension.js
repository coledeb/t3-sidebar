"use strict";

const vscode = require("vscode");
const http = require("node:http");
const fs = require("node:fs");
const os = require("node:os");
const path = require("node:path");
const crypto = require("node:crypto");
const { execFile } = require("node:child_process");
const { CookieJar, Relay } = require("./proxy.js");

const VIEW_ID = "t3Sidebar.view";
const JAR_SECRET = "t3Sidebar.cookieJar";
const DEFAULT_SERVER_URL = "http://127.0.0.1:3773";
// Every scope the t3 CLI can grant; its default set omits access:* and relay:write.
const PAIRING_SCOPES = [
  "orchestration:read",
  "orchestration:operate",
  "settings:write",
  "providers:manage",
  "environment:maintain",
  "preview:operate",
  "diagnostics:read",
  "terminal:read",
  "terminal:operate",
  "filesystem:read",
  "filesystem:write",
  "source-control:write",
  "access:read",
  "access:write",
  "relay:read",
  "relay:write",
];

/** @type {vscode.OutputChannel} */
let output;
const log = (line) => output?.appendLine(`${new Date().toISOString()} ${line}`);

const config = () => vscode.workspace.getConfiguration("t3Sidebar");

/** Shortcut ("cmd+shift+p") to editor command id, normalized to lowercase. */
function editorShortcuts() {
  const configured = config().get("editorShortcuts", {});
  return Object.fromEntries(
    Object.entries(configured).map(([shortcut, command]) => [
      shortcut.toLowerCase().replace(/\s+/g, ""),
      command,
    ]),
  );
}

function resolveTarget() {
  const configured = config().get("serverUrl", "").trim();
  if (configured !== "") return new URL(configured);
  try {
    const runtimePath = path.join(os.homedir(), ".t3", "userdata", "server-runtime.json");
    const runtime = JSON.parse(fs.readFileSync(runtimePath, "utf8"));
    if (typeof runtime.origin === "string" && runtime.origin !== "") {
      return new URL(runtime.origin);
    }
  } catch {
    // Fall back to the default port.
  }
  return new URL(DEFAULT_SERVER_URL);
}

function resolveCli() {
  const configured = config().get("cliPath", "").trim();
  if (configured !== "") return configured.replace(/^~/, os.homedir());
  const candidates = [
    path.join(os.homedir(), ".t3", "bin", "t3"),
    "/opt/homebrew/bin/t3",
    "/usr/local/bin/t3",
  ];
  return candidates.find((candidate) => fs.existsSync(candidate)) ?? "t3";
}

/**
 * Whether the stored session cookie is accepted by the server: true, false,
 * or null when the server can't be reached.
 */
function isSignedIn(target, jar) {
  return new Promise((resolve) => {
    const cookie = jar.header();
    const request = http.get(
      new URL("/api/auth/session", target),
      { headers: cookie ? { cookie } : {}, timeout: 5000 },
      (response) => {
        let body = "";
        response.on("data", (chunk) => (body += chunk));
        response.on("end", () => {
          try {
            resolve(JSON.parse(body).authenticated === true);
          } catch {
            resolve(null);
          }
        });
      },
    );
    request.on("timeout", () => request.destroy());
    request.on("error", () => resolve(null));
  });
}

function issuePairingToken() {
  const cli = resolveCli();
  log(`issuing pairing token with ${cli}`);
  return new Promise((resolve, reject) => {
    execFile(
      cli,
      [
        "auth",
        "pairing",
        "create",
        "--json",
        "--ttl",
        "5m",
        "--label",
        "T3 Sidebar (Cursor)",
        ...PAIRING_SCOPES.flatMap((scope) => ["--scope", scope]),
      ],
      { timeout: 30000 },
      (error, stdout, stderr) => {
        if (error) return reject(new Error(`t3 CLI failed: ${stderr.trim() || error.message}`));
        try {
          const json = stdout.slice(stdout.indexOf("{"), stdout.lastIndexOf("}") + 1);
          const { credential } = JSON.parse(json);
          if (typeof credential !== "string" || credential === "") throw new Error("no credential");
          resolve(credential);
        } catch {
          reject(new Error(`Unexpected t3 CLI output: ${stdout.slice(0, 200)}`));
        }
      },
    );
  });
}

class T3ViewProvider {
  constructor(relay, jar) {
    this.relay = relay;
    this.jar = jar;
    /** @type {vscode.WebviewView | undefined} */
    this.view = undefined;
  }

  resolveWebviewView(view) {
    this.view = view;
    view.webview.options = { enableScripts: true };
    view.webview.html = this.#html();
    view.webview.onDidReceiveMessage((message) => this.#onMessage(message));
    void this.load();
  }

  /** Point the iframe at T3, signing in first if needed. */
  async load({ forcePair = false } = {}) {
    if (!this.view) return;
    const target = resolveTarget();
    let page = "/";
    if (forcePair || (config().get("autoPair", true) && (await isSignedIn(target, this.jar)) === false)) {
      try {
        const token = await issuePairingToken();
        page = `/pair#${new URLSearchParams({ token })}`;
        log("signing in with a fresh pairing token");
      } catch (cause) {
        log(String(cause.message ?? cause));
        void vscode.window.showWarningMessage(
          `T3 Sidebar couldn't sign in automatically: ${cause.message}`,
        );
      }
    }
    this.view.webview.postMessage({ type: "host:navigate", url: this.relay.launchUrl(page) });
  }

  async #onMessage(message) {
    if (message?.type === "t3sb:clipboard-read") {
      const text = await vscode.env.clipboard.readText();
      this.view?.webview.postMessage({ type: "host:clipboard-text", id: message.id, text });
    } else if (message?.type === "t3sb:clipboard-write" && typeof message.text === "string") {
      await vscode.env.clipboard.writeText(message.text);
    } else if (message?.type === "t3sb:shortcut" && typeof message.shortcut === "string") {
      const command = editorShortcuts()[message.shortcut];
      if (typeof command === "string" && command !== "") {
        await vscode.commands.executeCommand(command);
      }
    }
  }

  #html() {
    const nonce = crypto.randomBytes(16).toString("base64");
    const origin = this.relay.origin;
    return `<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; frame-src ${origin}; style-src 'unsafe-inline'; script-src 'nonce-${nonce}';">
<style>
  html, body { margin: 0; padding: 0; height: 100%; overflow: hidden; }
  iframe { border: 0; width: 100%; height: 100%; display: block; }
</style>
</head>
<body>
<iframe id="t3" allow="clipboard-read; clipboard-write"></iframe>
<script nonce="${nonce}">
  const vscode = acquireVsCodeApi();
  const frame = document.getElementById("t3");
  const ORIGIN = ${JSON.stringify(origin)};
  window.addEventListener("message", (event) => {
    const data = event.data || {};
    if (event.source === frame.contentWindow) {
      if (event.origin !== ORIGIN) return;
      if (data.type === "t3sb:clipboard-read" || data.type === "t3sb:clipboard-write" || data.type === "t3sb:shortcut") {
        vscode.postMessage(data);
      }
      return;
    }
    if (data.type === "host:navigate") {
      frame.src = data.url;
    } else if (data.type === "host:clipboard-text") {
      frame.contentWindow.postMessage(
        { type: "t3sb:clipboard-text", id: data.id, text: data.text },
        ORIGIN,
      );
    }
  });
</script>
</body>
</html>`;
  }
}

async function activate(context) {
  output = vscode.window.createOutputChannel("T3 Sidebar");
  context.subscriptions.push(output);

  const jar = new CookieJar(await context.secrets.get(JAR_SECRET), (serialized) => {
    void context.secrets.store(JAR_SECRET, serialized);
  });
  const shimSource = fs.readFileSync(path.join(context.extensionPath, "shim.js"), "utf8");
  // Read per request so shortcut changes apply on the next reload.
  const shim = () =>
    shimSource.replace("__T3SB_EDITOR_SHORTCUTS__", JSON.stringify(Object.keys(editorShortcuts())));
  const relay = new Relay({ getTarget: resolveTarget, jar, shim, log });
  try {
    await relay.start(config().get("proxyPort", 37730));
  } catch (cause) {
    log(`relay failed to start: ${cause.message}`);
    void vscode.window.showErrorMessage(`T3 Sidebar couldn't start: ${cause.message}`);
    return;
  }
  context.subscriptions.push({ dispose: () => relay.dispose() });

  const provider = new T3ViewProvider(relay, jar);
  context.subscriptions.push(
    vscode.window.registerWebviewViewProvider(VIEW_ID, provider, {
      webviewOptions: { retainContextWhenHidden: true },
    }),
    vscode.commands.registerCommand("t3Sidebar.reload", () => provider.load()),
    vscode.commands.registerCommand("t3Sidebar.pair", () => provider.load({ forcePair: true })),
    vscode.commands.registerCommand("t3Sidebar.showLog", () => output.show()),
  );

  if (config().get("openOnStartup", true)) {
    await vscode.commands.executeCommand(`${VIEW_ID}.focus`);
    await vscode.commands.executeCommand("workbench.action.focusActiveEditorGroup");
  } else if (config().get("selectOnStartup", true)) {
    await selectViewIfAlreadyShowing(context);
  }
}

// Where a view container sits: Cursor's ViewContainerLocation values.
const PARTS = {
  0: { name: "sidebar", hiddenKey: "workbench.sideBar.hidden" },
  1: { name: "panel", hiddenKey: "workbench.panel.hidden" },
  2: { name: "secondary sidebar", hiddenKey: "workbench.auxiliaryBar.hidden" },
};
const DEFAULT_CONTAINER_ID = "workbench.view.extension.t3Sidebar";

/** Reads keys from one of Cursor's state databases; {} if unreadable. */
function readCursorState(dbPath, keys) {
  return new Promise((resolve) => {
    if (!dbPath || !fs.existsSync(dbPath)) return resolve({});
    const list = keys.map((key) => `'${key.replaceAll("'", "''")}'`).join(",");
    execFile(
      "/usr/bin/sqlite3",
      ["-readonly", "-json", dbPath, `select key, value from ItemTable where key in (${list});`],
      { timeout: 5000 },
      (error, stdout) => {
        if (error) {
          log(`couldn't read ${dbPath}: ${error.message}`);
          return resolve({});
        }
        try {
          const rows = stdout.trim() === "" ? [] : JSON.parse(stdout);
          resolve(Object.fromEntries(rows.map((row) => [row.key, row.value])));
        } catch {
          resolve({});
        }
      },
    );
  });
}

/** Which layout part holds the T3 view, per Cursor's saved view customizations. */
function viewPart(customizationsJson) {
  let customizations = {};
  try {
    customizations = JSON.parse(customizationsJson ?? "{}");
  } catch {
    // Treat unreadable customizations as none.
  }
  const containerId = customizations.viewLocations?.[VIEW_ID] ?? DEFAULT_CONTAINER_ID;
  const moved = customizations.viewContainerLocations?.[containerId];
  if (typeof moved === "number") return PARTS[moved];
  if (containerId.startsWith("workbench.views.service.auxiliarybar.")) return PARTS[2];
  if (containerId.startsWith("workbench.views.service.panel.")) return PARTS[1];
  return PARTS[0];
}

/**
 * If the sidebar (or panel) holding T3 was open when Cursor last quit, it is
 * open again now, and Cursor will have switched it to its own agent view on
 * the way out. Switch it back to T3. A closed sidebar is left alone: Cursor
 * keeps T3 selected in that case, and focusing would open it.
 *
 * Reads Cursor's saved layout from its state databases (state at last quit).
 */
async function selectViewIfAlreadyShowing(context) {
  const globalDb = path.join(path.dirname(context.globalStorageUri.fsPath), "state.vscdb");
  const workspaceDb = context.storageUri
    ? path.join(path.dirname(context.storageUri.fsPath), "state.vscdb")
    : null;
  if (workspaceDb === null) {
    log("no workspace layout to read, so not selecting the T3 view at startup");
    return;
  }
  const keys = ["views.customizations", ...Object.values(PARTS).map((part) => part.hiddenKey)];
  const [globalState, workspaceState] = await Promise.all([
    readCursorState(globalDb, keys),
    readCursorState(workspaceDb, keys),
  ]);
  const part = viewPart(
    workspaceState["views.customizations"] ?? globalState["views.customizations"],
  );
  const hidden = workspaceState[part.hiddenKey];
  if (hidden !== "false") {
    log(`T3 is in the ${part.name}, which is ${hidden === "true" ? "closed" : "unknown"}; leaving it`);
    return;
  }
  await vscode.commands.executeCommand(`${VIEW_ID}.focus`);
  await vscode.commands.executeCommand("workbench.action.focusActiveEditorGroup");
  log(`T3 is in the ${part.name}, which is open; selected the T3 view`);
}

function deactivate() {}

module.exports = { activate, deactivate };
