import { useEffect, useState } from "react";

type CopyState = "idle" | "copied" | "error";

async function writeClipboard(value: string): Promise<void> {
  if (!navigator.clipboard?.writeText) throw new Error("Clipboard access is unavailable");
  await navigator.clipboard.writeText(value);
}

export function CopyButton({ value, label, className = "button button--secondary" }: { value: string; label: string; className?: string }) {
  const [state, setState] = useState<CopyState>("idle");

  useEffect(() => {
    if (state === "idle") return;
    const timeout = window.setTimeout(() => setState("idle"), 1800);
    return () => window.clearTimeout(timeout);
  }, [state]);

  const copy = async () => {
    try {
      await writeClipboard(value);
      setState("copied");
    } catch {
      setState("error");
    }
  };

  return (
    <span className="copy-control">
      <button className={className} type="button" onClick={() => { void copy(); }}>
        {state === "copied" ? "Copied" : state === "error" ? "Copy failed" : label}
      </button>
      <span className="sr-only" aria-live="polite">{state === "copied" ? `${label} copied to clipboard.` : state === "error" ? `${label} could not be copied. Clipboard access is unavailable.` : ""}</span>
    </span>
  );
}
