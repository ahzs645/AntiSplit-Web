import { inspectPackage, mergePackage } from "./mergeCore";
import type { WorkerRequest, WorkerResponse } from "./types";

function post(message: WorkerResponse, transfer?: Transferable[]) {
  self.postMessage(message, { transfer });
}

self.onmessage = (event: MessageEvent<WorkerRequest>) => {
  const request = event.data;
  const files = request.files.map((file) => ({
    name: file.name,
    bytes: new Uint8Array(file.bytes)
  }));

  try {
    if (request.type === "inspect") {
      post({
        id: request.id,
        type: "inspect-result",
        result: inspectPackage(files)
      });
      return;
    }

    const result = mergePackage(files, request.options, (message) => {
      post({ id: request.id, type: "progress", message });
    });
    const buffer = result.apkBytes.buffer.slice(
      result.apkBytes.byteOffset,
      result.apkBytes.byteOffset + result.apkBytes.byteLength
    );
    const v4SidecarBuffer = result.v4SidecarBytes?.buffer.slice(
      result.v4SidecarBytes.byteOffset,
      result.v4SidecarBytes.byteOffset + result.v4SidecarBytes.byteLength
    );
    const transfer = v4SidecarBuffer ? [buffer, v4SidecarBuffer] : [buffer];
    post(
      {
        id: request.id,
        type: "merge-result",
        result: {
          ...result,
          apkBytes: new Uint8Array(buffer),
          v4SidecarBytes: v4SidecarBuffer ? new Uint8Array(v4SidecarBuffer) : undefined
        }
      },
      transfer
    );
  } catch (error) {
    const err = error instanceof Error ? error : new Error(String(error));
    post({
      id: request.id,
      type: "error",
      message: err.message,
      stack: err.stack
    });
  }
};
