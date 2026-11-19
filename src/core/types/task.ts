export type TaskInterval = "once" | "hourly" | "daily";
export type TaskStatus = "pending" | "running" | "completed" | "failed";

export interface ScheduledTask {
  id: string;
  appId?: string; // Optional namespace tag to guarantee app-level isolation
  title: string;
  scheduledTime: string;
  interval: TaskInterval;
  status: TaskStatus;
  category: "hardware" | "database" | "system" | "network";
  createdAt: string;
  /** Additive: tasks driven by an external source (e.g. remote transfers). In-memory only, not persisted. */
  external?: boolean;
  /** Additive: 0..100 progress for external tasks. */
  progress?: number;
}

export interface TaskExecutionLog {
  id: string;
  taskId: string;
  taskTitle: string;
  appId?: string;
  executedAt: string;
  date: string; // YYYY-MM-DD
  durationMs: number;
  status: "success" | "failed";
  details?: string;
}
