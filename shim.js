// Injected into every T3 Code page served through the relay.
//
// Inside a webview iframe, Cmd/Ctrl+V never reaches the page and the async
// Clipboard API is blocked. This routes clipboard access through the
// extension (vscode.env.clipboard) via the parent webview.
(() => {
  "use strict";
  if (window.top === window) return;

  // Drop the relay's launch token from the address before the app reads it.
  try {
    const url = new URL(location.href);
    if (url.searchParams.has("__t3sidebar")) {
      url.searchParams.delete("__t3sidebar");
      history.replaceState(history.state, "", url.pathname + url.search + url.hash);
    }
  } catch {
    // Leave the URL alone if it can't be parsed.
  }

  // T3 treats a viewport under 640px as a phone: Enter inserts a newline and
  // nothing sends from the keyboard. A narrow sidebar is still a desktop, so
  // answer "no" to that one query. Layout uses CSS media queries, unaffected.
  const PHONE_QUERIES = new Set(["(max-width: 639px)"]);
  const realMatchMedia = window.matchMedia.bind(window);
  window.matchMedia = (query) => {
    if (!PHONE_QUERIES.has(String(query).trim())) return realMatchMedia(query);
    return {
      matches: false,
      media: String(query),
      onchange: null,
      addEventListener() {},
      removeEventListener() {},
      addListener() {},
      removeListener() {},
      dispatchEvent: () => false,
    };
  };

  // T3 focuses its composer on load and on thread changes. Inside the
  // sidebar that pulls focus out of the editor, so only allow programmatic
  // focus once the user has put focus in this page (by clicking into it).
  const realFocus = HTMLElement.prototype.focus;
  HTMLElement.prototype.focus = function (options) {
    if (!document.hasFocus()) return;
    return realFocus.call(this, options);
  };
  const realWindowFocus = window.focus.bind(window);
  window.focus = () => {
    if (document.hasFocus()) realWindowFocus();
  };

  let nextId = 0;
  const pending = new Map();

  function readClipboard() {
    return new Promise((resolve) => {
      const id = ++nextId;
      pending.set(id, resolve);
      window.parent.postMessage({ type: "t3sb:clipboard-read", id }, "*");
      setTimeout(() => {
        if (pending.delete(id)) resolve(null);
      }, 3000);
    });
  }

  function writeClipboard(text) {
    window.parent.postMessage({ type: "t3sb:clipboard-write", text: String(text) }, "*");
  }

  window.addEventListener("message", (event) => {
    if (event.source !== window.parent) return;
    const data = event.data;
    if (data && data.type === "t3sb:clipboard-text") {
      const resolve = pending.get(data.id);
      if (resolve) {
        pending.delete(data.id);
        resolve(typeof data.text === "string" ? data.text : null);
      }
    }
  });

  function selectedText() {
    const active = document.activeElement;
    if (
      active &&
      (active.tagName === "TEXTAREA" || active.tagName === "INPUT") &&
      typeof active.selectionStart === "number"
    ) {
      return active.value.slice(active.selectionStart, active.selectionEnd);
    }
    return String(window.getSelection() ?? "");
  }

  function insertText(target, text) {
    if (target && typeof target.focus === "function" && document.activeElement !== target) {
      target.focus();
    }
    // Rich editors handle paste events themselves; plain fields need insertText.
    const data = new DataTransfer();
    data.setData("text/plain", text);
    let pasteEvent = null;
    try {
      pasteEvent = new ClipboardEvent("paste", {
        clipboardData: data,
        bubbles: true,
        cancelable: true,
      });
    } catch {
      // Fall through to insertText.
    }
    if (pasteEvent) {
      (target || document.body).dispatchEvent(pasteEvent);
      if (pasteEvent.defaultPrevented) return;
    }
    document.execCommand("insertText", false, text);
  }

  const isMac = /Mac|iPhone|iPad/.test(navigator.platform);

  window.addEventListener(
    "keydown",
    (event) => {
      const modifier = isMac
        ? event.metaKey && !event.ctrlKey
        : event.ctrlKey && !event.metaKey;
      if (!modifier || event.altKey) return;
      const key = event.key.toLowerCase();
      if (key === "v") {
        event.preventDefault();
        event.stopImmediatePropagation();
        const target = document.activeElement;
        readClipboard().then((text) => {
          if (text) insertText(target, text);
        });
      } else if (key === "c" || key === "x") {
        const text = selectedText();
        if (!text) return;
        writeClipboard(text);
        if (key === "x") {
          event.preventDefault();
          document.execCommand("delete");
        }
      }
    },
    true,
  );

  // Copy buttons and other code using the async Clipboard API.
  try {
    const clipboard = navigator.clipboard;
    if (clipboard) {
      clipboard.writeText = async (text) => writeClipboard(text);
      clipboard.readText = async () => (await readClipboard()) ?? "";
    }
  } catch {
    // Keep the browser's implementation.
  }
})();
