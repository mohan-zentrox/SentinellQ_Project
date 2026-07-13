// Mirrors backend/app/schemas/*.py camelCase response shapes.

export type Role = "owner" | "admin" | "analyst" | "viewer";

export interface TokenResponse {
  accessToken: string;
  tokenType: string;
  tenantId: string;
  userId: string;
  role: Role;
}

export interface AlertOut {
  id: string;
  tenantId: string;
  ruleId: string | null;
  title: string;
  description: string;
  severity: "informational" | "low" | "medium" | "high" | "critical";
  status: string;
  eventIds: string[];
  caseId: string | null;
  createdAt: string;
}

export interface AlertListResponse {
  total: number;
  page: number;
  pageSize: number;
  items: AlertOut[];
}

export interface CaseOut {
  id: string;
  tenantId: string;
  title: string;
  description: string;
  status: "new" | "investigating" | "resolved" | "escalated";
  severity: string;
  assigneeUserId: string | null;
  alertIds: string[];
  createdAt: string;
  updatedAt: string;
  resolvedAt: string | null;
}

export interface CaseTimelineEntryOut {
  id: string;
  caseId: string;
  entryType: string;
  message: string;
  actorUserId: string | null;
  createdAt: string;
}

export interface PlanOut {
  id: string;
  slug: string;
  name: string;
  monthlyEventQuota: number;
  priceCents: number;
  features: Record<string, unknown>;
}

export interface UsageOut {
  period: string;
  eventCount: number;
  monthlyEventQuota: number | null;
  percentUsed: number | null;
}

export interface KPIResponse {
  periodStart: string;
  periodEnd: string;
  alertVolume: number;
  falsePositiveRate: number;
  mttdSeconds: number | null;
  mttrSeconds: number | null;
  openCases: number;
  resolvedCases: number;
}
