import React, { useMemo, useRef, useState } from "react";
import { createRoot } from "react-dom/client";
import { Download, FileArchive, Play, Settings, ShieldAlert, Smartphone } from "lucide-react";
import type { InspectResult, MergeOptions, MergeResult, WorkerRequest, WorkerResponse } from "./types";
import "./styles.css";

type SelectedFile = {
  file: File;
  bytes: ArrayBuffer;
};

const worker = new Worker(new URL("./mergeWorker.ts", import.meta.url), { type: "module" });

function App() {
  const [files, setFiles] = useState<SelectedFile[]>([]);
  const [inspect, setInspect] = useState<InspectResult | null>(null);
  const [includeSplits, setIncludeSplits] = useState<string[]>([]);
  const [logs, setLogs] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<MergeResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [signingMode, setSigningMode] = useState<NonNullable<MergeOptions["signingMode"]>>("v1-v2");
  const [compressionLevel, setCompressionLevel] = useState(6);
  const [dragging, setDragging] = useState(false);
  const fileInput = useRef<HTMLInputElement | null>(null);

  const selectedSize = useMemo(() => files.reduce((sum, entry) => sum + entry.file.size, 0), [files]);

  async function handleFiles(inputFiles: FileList | File[]) {
    const next = await Promise.all(
      Array.from(inputFiles).map(async (file) => ({
        file,
        bytes: await file.arrayBuffer()
      }))
    );
    setFiles(next);
    setResult(null);
    setError(null);
    setLogs([]);
    await inspectFiles(next);
  }

  async function inspectFiles(next: SelectedFile[]) {
    setBusy(true);
    try {
      const response = await sendWorker({
        id: crypto.randomUUID(),
        type: "inspect",
        files: next.map(toWorkerFile)
      });
      if (response.type === "inspect-result") {
        setInspect(response.result);
        setIncludeSplits(response.result.apkEntries.filter((entry) => entry.role !== "base").map((entry) => entry.name));
      } else if (response.type === "error") {
        setError(response.message);
      }
    } finally {
      setBusy(false);
    }
  }

  async function merge() {
    if (files.length === 0) {
      return;
    }
    setBusy(true);
    setResult(null);
    setError(null);
    setLogs([]);
    const options: MergeOptions = { includeSplits, compressionLevel, signApk: signingMode !== "none", signingMode };
    try {
      const response = await sendWorker({
        id: crypto.randomUUID(),
        type: "merge",
        files: files.map(toWorkerFile),
        options
      });
      if (response.type === "merge-result") {
        setResult(response.result);
      } else if (response.type === "error") {
        setError(response.message);
      }
    } finally {
      setBusy(false);
    }
  }

  function downloadResult() {
    if (!result) {
      return;
    }
    downloadBytes(result.fileName, result.apkBytes, "application/vnd.android.package-archive");
  }

  function downloadV4Sidecar() {
    if (!result?.v4SidecarBytes || !result.v4SidecarFileName) {
      return;
    }
    downloadBytes(result.v4SidecarFileName, result.v4SidecarBytes, "application/octet-stream");
  }

  function downloadBytes(fileName: string, bytes: Uint8Array, type: string) {
    const blob = new Blob([bytes], { type });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = fileName;
    anchor.click();
    URL.revokeObjectURL(url);
  }

  return (
    <main className="app">
      <section className="toolbar">
        <div>
          <h1>AntiSplit Web</h1>
          <p>Client-side split APK merge workspace</p>
        </div>
        <button className="primary" disabled={busy || files.length === 0} onClick={merge}>
          <Play size={18} />
          Merge
        </button>
      </section>

      <section
        className={dragging ? "dropzone dragging" : "dropzone"}
        role="button"
        tabIndex={0}
        aria-label="Choose split APK files"
        onClick={() => fileInput.current?.click()}
        onKeyDown={(event) => {
          if (event.key === "Enter" || event.key === " ") {
            event.preventDefault();
            fileInput.current?.click();
          }
        }}
        onDragOver={(event) => event.preventDefault()}
        onDragEnter={(event) => {
          event.preventDefault();
          setDragging(true);
        }}
        onDragLeave={() => setDragging(false)}
        onDrop={(event) => {
          event.preventDefault();
          setDragging(false);
          void handleFiles(event.dataTransfer.files);
        }}
      >
        <FileArchive size={32} />
        <div>
          <strong>{files.length === 0 ? "Tap to choose, or drop XAPK / APKS / APKM / APK files" : `${files.length} file(s), ${formatBytes(selectedSize)}`}</strong>
          <span>{files.length === 0 ? "Processing stays in this browser session." : files.map(({ file }) => file.name).join(", ")}</span>
        </div>
        <input
          ref={fileInput}
          type="file"
          multiple
          accept=".apk,.xapk,.apks,.apkm,.zip,application/zip,application/vnd.android.package-archive"
          onChange={(event) => event.target.files && void handleFiles(event.target.files)}
        />
        <button
          onClick={(event) => {
            event.stopPropagation();
            fileInput.current?.click();
          }}
        >
          Choose Files
        </button>
      </section>

      <section className="content">
        <div className="panel">
          <header>
            <h2>Splits</h2>
            {inspect?.packageName && <span>{inspect.packageName}</span>}
          </header>
          <div className="split-list">
            {inspect?.apkEntries.map((entry) => (
              <label key={entry.name} className="split-row">
                <input
                  type="checkbox"
                  checked={entry.role === "base" || includeSplits.includes(entry.name)}
                  disabled={entry.role === "base" || busy}
                  onChange={(event) => {
                    setIncludeSplits((current) =>
                      event.target.checked ? [...current, entry.name] : current.filter((name) => name !== entry.name)
                    );
                  }}
                />
                <span>{entry.name}</span>
                <small>{entry.role} · {formatBytes(entry.size)}{entry.resourceTable ? ` · ${entry.resourceTable}` : ""}</small>
              </label>
            )) ?? <p className="empty">No package selected.</p>}
          </div>
        </div>

        <div className="panel">
          <header>
            <h2><Settings size={18} /> Options</h2>
          </header>
          <label className="setting">
            <span>Compression</span>
            <input
              type="range"
              min="0"
              max="9"
              value={compressionLevel}
              onChange={(event) => setCompressionLevel(Number(event.target.value))}
            />
            <strong>{compressionLevel}</strong>
          </label>
          <label className="setting">
            <span>Signing</span>
            <select value={signingMode} onChange={(event) => setSigningMode(event.target.value as NonNullable<MergeOptions["signingMode"]>)}>
              <option value="v1-v2">JAR/v1 + v2 (recommended)</option>
              <option value="v1">JAR/v1 only (legacy)</option>
              <option value="v1-v2-v3">JAR/v1 + experimental v2/v3</option>
              <option value="v1-v2-v3-v4">JAR/v1 + experimental v2/v3 + v4 sidecar</option>
              <option value="none">Unsigned</option>
            </select>
          </label>
          <div className="notice">
            <ShieldAlert size={18} />
            <span>JAR/v1 + v2 is the default and is Android apksigner-verified. Apps targeting SDK 30 or newer may require v2 on matching Android versions.</span>
          </div>
          <div className="capabilities">
            <div>
              <FileArchive size={18} />
              <span>Merge selected files and download the APK.</span>
            </div>
            <div>
              <Smartphone size={18} />
              <span>Installed-app extraction and direct Android install prompts require Android platform APIs.</span>
            </div>
          </div>
        </div>
      </section>

      {(inspect?.warnings.length || result?.warnings.length || result?.unsupported.length || error) && (
        <section className="messages">
          {error && <div className="error">{error}</div>}
          {inspect?.warnings.map((message) => <div key={message}>{message}</div>)}
          {result?.warnings.map((message) => <div key={message}>{message}</div>)}
          {result?.unsupported.map((message) => <div className="unsupported" key={message}>{message}</div>)}
          {result?.verification.map((message) => <div className="verified" key={message}>{message}</div>)}
          {result?.resourceDiagnostics.map((message) => <div className="resource-detail" key={message}>{message}</div>)}
        </section>
      )}

      <section className="output">
        <div className="panel log-panel">
          <header>
            <h2>Log</h2>
          </header>
          <pre>{logs.length ? logs.join("\n") : "Waiting for input."}</pre>
        </div>
        <div className="panel result-panel">
          <header>
            <h2>Result</h2>
          </header>
          {result ? (
            <>
              <strong>{result.fileName}</strong>
              <span>{formatBytes(result.apkBytes.byteLength)}</span>
              <button className="primary" onClick={downloadResult}>
                <Download size={18} />
                Download
              </button>
              {result.v4SidecarBytes && (
                <>
                  <strong>{result.v4SidecarFileName}</strong>
                  <span>{formatBytes(result.v4SidecarBytes.byteLength)}</span>
                  <button onClick={downloadV4Sidecar}>
                    <Download size={18} />
                    Download
                  </button>
                </>
              )}
            </>
          ) : (
            <p className="empty">No merged APK yet.</p>
          )}
        </div>
      </section>
    </main>
  );

  function sendWorker(request: WorkerRequest): Promise<WorkerResponse> {
    return new Promise((resolve) => {
      const handler = (event: MessageEvent<WorkerResponse>) => {
        if (event.data.id !== request.id) {
          return;
        }
        const response = event.data;
        if (response.type === "progress") {
          setLogs((current) => [...current, response.message]);
          return;
        }
        worker.removeEventListener("message", handler);
        resolve(response);
      };
      worker.addEventListener("message", handler);
      const transfers = request.files.map((file) => file.bytes);
      worker.postMessage(request, transfers);
    });
  }
}

function toWorkerFile(entry: SelectedFile) {
  return { name: entry.file.name, bytes: entry.bytes.slice(0) };
}

function formatBytes(bytes: number) {
  if (bytes < 1024) {
    return `${bytes} B`;
  }
  const units = ["KB", "MB", "GB"];
  let value = bytes / 1024;
  let index = 0;
  while (value >= 1024 && index < units.length - 1) {
    value /= 1024;
    index++;
  }
  return `${value.toFixed(value >= 10 ? 1 : 2)} ${units[index]}`;
}

createRoot(document.getElementById("root")!).render(<App />);
