// Mirrors backend/app/schemas/*.py camelCase response shapes.

export type Role = "owner" | "admin" | "analyst" | "viewer";
export type Severity = "informational" | "low" | "medium" | "high" | "critical";
export type CaseStatus = "new" | "investigating" | "resolved" | "escalated";
export type AlertStatus = "open" | "dismissed" | "promoted";
export type DetectionSource = "rule" | "ml" | "manual";

/** Role privilege order, mirroring backend ROLE_HIERARCHY. */
export const ROLE_RANK: Record<Role, number> = {
  viewer: 0,
  analyst: 1,
  admin: 2,
  owner: 3,
};

export const SEVERITY_RANK: Record<Severity, number> = {
  informational: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export interface Paginated<T> {
  total: number;
  page: number;
  pageSize: number;
  items: T[];
}

export interface TokenResponse {
  accessToken: string;
  tokenType: string;
  tenantId: string;
  userId: string;
  role: Role;
  refreshToken: string | null;
  expiresIn: number | null;
}

export interface UserOut {
  id: string;
  tenantId: string;
  email: string;
  fullName: string;
  role: Role;
  isActive: boolean;
  provisionedBy: string;
  lastLoginAt: string | null;
  createdAt: string | null;
}

export interface SessionOut {
  id: string;
  issuedAt: string;
  expiresAt: string;
  userAgent: string | null;
  ipAddress: string | null;
  isCurrent: boolean;
}

export interface TenantOut {
  id: string;
  name: string;
  slug: string;
  planId: string | null;
  isActive: boolean;
}

export interface ServiceTokenSummary {
  id: string;
  name: string;
  isActive: boolean;
  createdAt: string;
}

/** The plaintext `token` exists only in the creation response. */
export interface ServiceTokenOut {
  id: string;
  name: string;
  token: string;
  createdAt: string | null;
}

export interface EnrichmentIndicator {
  id: string;
  type: string;
  value: string;
  source: string;
  confidence: number;
  severity: string;
  tags: string[];
}

export interface Enrichment {
  matched: boolean;
  indicatorCount: number;
  maxConfidence: number;
  maxSeverity: string | null;
  tags: string[];
  sources?: string[];
  indicators: EnrichmentIndicator[];
  enrichedAt: string;
}

export interface EventOut {
  id: string;
  tenantId: string;
  source: string;
  eventCategory: string;
  eventAction: string;
  severityHint: Severity;
  actor: string | null;
  target: string | null;
  sourceIp: string | null;
  enrichment: Enrichment | null;
  occurredAt: string;
  ingestedAt: string;
}

export interface EventDetailOut extends EventOut {
  rawPayload: Record<string, unknown>;
  normalized: Record<string, unknown>;
}

export type EventListResponse = Paginated<EventOut>;

export interface AlertOut {
  id: string;
  tenantId: string;
  ruleId: string | null;
  title: string;
  description: string;
  severity: Severity;
  status: AlertStatus;
  eventIds: string[];
  caseId: string | null;
  detectionSource: DetectionSource;
  mlScore: number | null;
  mlModelVersion: string | null;
  dismissedAt: string | null;
  dismissedByUserId: string | null;
  dismissReason: string | null;
  notifiedAt: string | null;
  createdAt: string;
}

/** Contributing events, inlined by GET /v1/alerts/{id}. */
export interface AlertEventSummary {
  id: string;
  source: string;
  eventCategory: string;
  eventAction: string;
  severityHint: Severity;
  actor: string | null;
  target: string | null;
  sourceIp: string | null;
  enrichment: Enrichment | null;
  occurredAt: string;
}

export interface AlertDetailOut extends AlertOut {
  events: AlertEventSummary[];
}

export type AlertListResponse = Paginated<AlertOut>;

export interface CaseOut {
  id: string;
  tenantId: string;
  title: string;
  description: string;
  status: CaseStatus;
  severity: Severity;
  assigneeUserId: string | null;
  alertIds: string[];
  createdAt: string;
  updatedAt: string;
  resolvedAt: string | null;
}

export type CaseListResponse = Paginated<CaseOut>;

export interface CaseTimelineEntryOut {
  id: string;
  caseId: string;
  entryType: string;
  message: string;
  actorUserId: string | null;
  createdAt: string;
}

export interface DetectionRuleOut {
  id: string;
  tenantId: string;
  name: string;
  description: string;
  condition: Record<string, unknown>;
  severity: Severity;
  isEnabled: boolean;
  evaluationWindowMinutes: number | null;
  lastEvaluatedAt: string | null;
  lastMatchedAt: string | null;
  matchCount: number;
  createdAt: string;
}

export interface RuleRunResponse {
  alertsCreated: number;
  alertIds: string[];
}

export interface RuleTestResponse {
  sampled: number;
  matched: number;
  matchedEventIds: string[];
}

export interface IndicatorOut {
  id: string;
  tenantId: string;
  indicatorType: string;
  value: string;
  valueNormalized: string;
  source: string;
  confidence: number;
  severity: Severity;
  tags: string[];
  description: string;
  isActive: boolean;
  expiresAt: string | null;
  lastSeenAt: string | null;
  matchCount: number;
  createdAt: string;
}

export type IndicatorListResponse = Paginated<IndicatorOut>;

export interface FeedOut {
  id: string;
  tenantId: string;
  slug: string;
  name: string;
  provider: string;
  url: string | null;
  apiKeyEnvVar: string | null;
  isEnabled: boolean;
  defaultConfidence: number;
  ttlHours: number;
  lastRefreshedAt: string | null;
  lastRefreshStatus: string | null;
  indicatorCount: number;
  createdAt: string;
}

export interface IndicatorStats {
  activeIndicators: number;
  inactiveIndicators: number;
  everMatched: number;
  matchRate: number;
  byType: Record<string, number>;
  bySource: Record<string, number>;
}

export interface PlaybookActionSpec {
  action: string;
  params: Record<string, unknown>;
}

export interface PlaybookOut {
  id: string;
  tenantId: string;
  name: string;
  description: string;
  trigger: string;
  triggerCondition: Record<string, unknown> | null;
  actions: PlaybookActionSpec[];
  isEnabled: boolean;
  dryRun: boolean;
  runCount: number;
  lastRunAt: string | null;
  createdAt: string;
  requiresApproval: boolean;
}

export interface ActionRegistryEntry {
  name: string;
  description: string;
  isHighRisk: boolean;
  haltOnFailure: boolean;
}

export interface ActionRecordOut {
  id: string;
  sequence: number;
  action: string;
  params: Record<string, unknown>;
  status: string;
  isHighRisk: boolean;
  result: Record<string, unknown>;
  error: string | null;
  durationMs: number | null;
  createdAt: string;
}

export interface PlaybookRunOut {
  id: string;
  tenantId: string;
  playbookId: string;
  status: string;
  trigger: string;
  subjectType: string | null;
  subjectId: string | null;
  dryRun: boolean;
  requiresApproval: boolean;
  approvedByUserId: string | null;
  approvedAt: string | null;
  rejectedByUserId: string | null;
  rejectedAt: string | null;
  rejectionReason: string | null;
  triggeredByUserId: string | null;
  startedAt: string | null;
  finishedAt: string | null;
  error: string | null;
  createdAt: string;
}

export interface PlaybookRunDetailOut extends PlaybookRunOut {
  actions: ActionRecordOut[];
}

export type PlaybookRunListResponse = Paginated<PlaybookRunOut>;

export interface ReportOut {
  id: string;
  tenantId: string;
  template: string;
  reportFormat: string;
  status: string;
  periodStart: string;
  periodEnd: string;
  sizeBytes: number | null;
  rowCount: number | null;
  generatedAt: string | null;
  error: string | null;
  requestedByUserId: string | null;
  createdAt: string;
  downloadUrl: string | null;
  downloadExpiresAt: string | null;
}

export type ReportListResponse = Paginated<ReportOut>;

export interface ReportTemplateOut {
  name: string;
  description: string;
  formats: string[];
}

export interface PlanOut {
  id: string;
  slug: string;
  name: string;
  monthlyEventQuota: number;
  priceCents: number;
  features: Record<string, unknown>;
}

export interface SubscriptionOut {
  id: string;
  tenantId: string;
  planId: string;
  status: string;
  stripeCheckoutSessionId: string | null;
  cancelAtPeriodEnd: boolean;
  canceledAt: string | null;
  currentPeriodEnd: string | null;
  createdAt: string | null;
}

export interface UsageOut {
  period: string;
  eventCount: number;
  monthlyEventQuota: number | null;
  percentUsed: number | null;
  overQuota: boolean;
}

export interface UsageHistoryResponse {
  entries: { period: string; eventCount: number }[];
}

export interface KPIResponse {
  periodStart: string;
  periodEnd: string;
  alertVolume: number;
  dismissedAlerts: number;
  falsePositiveRate: number;
  mttdSeconds: number | null;
  mttrSeconds: number | null;
  openCases: number;
  resolvedCases: number;
  alertsBySeverity: Record<string, number>;
  alertsByDetectionSource: Record<string, number>;
}

export interface TimeseriesBucket {
  bucketStart: string;
  count: number;
  bySeverity: Record<string, number>;
}

export interface AlertTimeseriesResponse {
  periodStart: string;
  periodEnd: string;
  bucketHours: number;
  buckets: TimeseriesBucket[];
}

export interface DetectionCoverageResponse {
  totalRules: number;
  enabledRules: number;
  rulesWithMatches: number;
  neverMatchedRules: {
    ruleId: string;
    name: string;
    severity: string;
    isEnabled: boolean;
    lastEvaluatedAt: string | null;
  }[];
  topRules: {
    ruleId: string;
    name: string;
    severity: string;
    matchCount: number;
    lastMatchedAt: string | null;
  }[];
}

export interface AuditLogOut {
  id: string;
  tenantId: string;
  actorUserId: string | null;
  action: string;
  targetType: string | null;
  targetId: string | null;
  detail: Record<string, unknown>;
  ipAddress: string | null;
  createdAt: string;
}

export type AuditLogListResponse = Paginated<AuditLogOut>;

export interface MLModelOut {
  id: string;
  tenantId: string;
  version: string;
  algorithm: string;
  featureNames: string[];
  trainedAt: string;
  trainingEventCount: number;
  trainingWindowStart: string | null;
  trainingWindowEnd: string | null;
  isActive: boolean;
  scoreThreshold: number;
  scoredEventCount: number;
  alertCount: number;
  metrics: Record<string, unknown>;
  createdAt: string;
}

export interface TrainModelResponse {
  trained: boolean;
  model: MLModelOut | null;
  detail: string | null;
}

export interface SettingsOverview {
  environment: string;
  queueBackend: string;
  telemetryStoreBackend: string;
  billingProvider: string;
  authProvider: string;
  detectionOnIngest: boolean;
  mlDetectionEnabled: boolean;
  threatIntelEnrichOnIngest: boolean;
  soarEnabled: boolean;
  soarRequireApprovalForHighRisk: boolean;
  notificationChannels: string[];
  notificationMinSeverity: string;
  notificationWebhookConfigured: boolean;
  smtpConfigured: boolean;
  autoCreateSchema: boolean;
  metricsEnabled: boolean;
}

export interface NotificationDeliveryOut {
  id: string;
  tenantId: string;
  alertId: string | null;
  caseId: string | null;
  channel: string;
  status: string;
  target: string | null;
  detail: Record<string, unknown>;
  error: string | null;
  durationMs: number | null;
  createdAt: string;
}

export type NotificationDeliveryListResponse = Paginated<NotificationDeliveryOut>;
