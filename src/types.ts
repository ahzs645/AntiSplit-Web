export type MergeOptions = {
  includeSplits: string[];
  compressionLevel: number;
  signApk?: boolean;
  signingMode?: "none" | "v1" | "v1-v2" | "v1-v2-v3" | "v1-v2-v3-v4";
};

export type ApkEntrySummary = {
  name: string;
  size: number;
  role: "base" | "config" | "unknown";
  selected: boolean;
  warnings: string[];
  resourceTable?: string;
};

export type InspectResult = {
  packageName: string | null;
  apkEntries: ApkEntrySummary[];
  warnings: string[];
};

export type MergeResult = {
  fileName: string;
  apkBytes: Uint8Array;
  v4SidecarFileName?: string;
  v4SidecarBytes?: Uint8Array;
  logs: string[];
  warnings: string[];
  unsupported: string[];
  verification: string[];
  resourceDiagnostics: string[];
};

export type WorkerRequest =
  | {
      id: string;
      type: "inspect";
      files: Array<{ name: string; bytes: ArrayBuffer }>;
    }
  | {
      id: string;
      type: "merge";
      files: Array<{ name: string; bytes: ArrayBuffer }>;
      options: MergeOptions;
    };

export type WorkerResponse =
  | {
      id: string;
      type: "inspect-result";
      result: InspectResult;
    }
  | {
      id: string;
      type: "merge-result";
      result: MergeResult;
    }
  | {
      id: string;
      type: "progress";
      message: string;
    }
  | {
      id: string;
      type: "error";
      message: string;
      stack?: string;
    };
