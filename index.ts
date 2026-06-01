/*
 * MultiCodex Extension
 *
 * Rotates multiple ChatGPT Codex OAuth accounts for the built-in
 * openai-codex-responses API.
 *
 * Note: The published @mariozechner/pi-coding-agent types do not expose the
 * extension surface yet. We import ExtensionAPI as a type and provide a local
 * module augmentation (pi-coding-agent.d.ts) so TypeScript can compile.
 */

import * as crypto from "node:crypto";
import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import {
	type Api,
	type AssistantMessage,
	type AssistantMessageEvent,
	type AssistantMessageEventStream,
	type Context,
	createAssistantMessageEventStream,
	getApiProvider,
	getModels,
	type Model,
	type SimpleStreamOptions,
} from "@mariozechner/pi-ai";
import {
	loginOpenAICodex,
	type OAuthCredentials,
	refreshOpenAICodexToken,
} from "@mariozechner/pi-ai/oauth";
import type {
	ExtensionAPI,
	ExtensionCommandContext,
	ExtensionContext,
} from "@mariozechner/pi-coding-agent";

// =============================================================================
// Helpers
// =============================================================================

const USAGE_CACHE_TTL_MS = 5 * 60 * 1000;
const USAGE_REQUEST_TIMEOUT_MS = 10 * 1000;
const ACCESS_TOKEN_REFRESH_SKEW_MS = 5 * 60 * 1000;
const TOKEN_REFRESH_LOCK_WAIT_MS = 60 * 1000;
const TOKEN_REFRESH_LOCK_STALE_MS = 5 * 60 * 1000;
const TOKEN_REFRESH_LOCK_POLL_MS = 250;
const TOKEN_REFRESH_LOCK_DIR = path.join(
	os.homedir(),
	".pi",
	"agent",
	"multicodex-refresh-locks",
);
const LOG_FILE = path.join(os.homedir(), ".pi", "agent", "multicodex.log");

function getMulticodexStorageFile(): string {
	return process.env.MULTICODEX_STORAGE_FILE || STORAGE_FILE;
}

function getMulticodexLogFile(): string | undefined {
	if (process.env.MULTICODEX_DISABLE_LOG === "1") return undefined;
	return process.env.MULTICODEX_LOG_FILE || LOG_FILE;
}

function redactLogString(value: string): string {
	return value.replace(
		/(access_token|refresh_token|id_token|api[-_]?key|authorization|password|secret)(["'\s:=]+)([^"'\s,&}]+)/gi,
		"$1$2[redacted]",
	);
}

function safeLogJson(details: Record<string, unknown>): string {
	const seen = new WeakSet<object>();
	return JSON.stringify(details, (key, value: unknown) => {
		if (/token|authorization|api[-_]?key|secret|password/i.test(key)) {
			return "[redacted]";
		}
		if (value instanceof Error) {
			return {
				name: value.name,
				message: redactLogString(value.message),
				stack: value.stack ? redactLogString(value.stack) : undefined,
			};
		}
		if (typeof value === "string") return redactLogString(value);
		if (typeof value === "bigint") return value.toString();
		if (typeof value === "object" && value !== null) {
			if (seen.has(value)) return "[circular]";
			seen.add(value);
		}
		return value;
	});
}

function logMulticodex(
	message: string,
	details?: Record<string, unknown>,
): void {
	try {
		const logFile = getMulticodexLogFile();
		if (!logFile) return;
		const dir = path.dirname(logFile);
		if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
		const suffix = details ? ` ${safeLogJson(details)}` : "";
		fs.appendFileSync(
			logFile,
			`${new Date().toISOString()} pid=${process.pid} ${message}${suffix}\n`,
		);
	} catch (error) {
		console.error("Failed to write multicodex log:", error);
	}
}

function sleep(ms: number): Promise<void> {
	return new Promise((resolve) => setTimeout(resolve, ms));
}

function getAccountLockId(email: string): string {
	return crypto.createHash("sha256").update(email).digest("hex").slice(0, 16);
}

function getTokenRefreshLockDir(): string {
	return process.env.MULTICODEX_LOCK_DIR || TOKEN_REFRESH_LOCK_DIR;
}

function getTokenRefreshLockPath(): string {
	return path.join(getTokenRefreshLockDir(), "token-refresh.lock");
}

function getErrnoCode(error: unknown): string | undefined {
	return typeof error === "object" && error !== null && "code" in error
		? String((error as { code?: unknown }).code)
		: undefined;
}

async function acquireTokenRefreshLock(email: string): Promise<() => void> {
	const lockPath = getTokenRefreshLockPath();
	const ownerFile = path.join(lockPath, "owner.json");
	const lockId = getAccountLockId(email);
	const ownerId = `${process.pid}:${Date.now()}:${crypto.randomUUID()}`;
	const startedAt = Date.now();
	let loggedWait = false;

	while (true) {
		try {
			const lockDir = getTokenRefreshLockDir();
			if (!fs.existsSync(lockDir)) {
				fs.mkdirSync(lockDir, { recursive: true });
			}
			fs.mkdirSync(lockPath);
			try {
				fs.writeFileSync(
					ownerFile,
					JSON.stringify(
						{ ownerId, pid: process.pid, lockId, email, createdAt: Date.now() },
						null,
						2,
					),
				);
			} catch (error) {
				fs.rmSync(lockPath, { recursive: true, force: true });
				throw error;
			}
			logMulticodex("token.refresh.lock.acquired", {
				email,
				lockId,
				waitMs: Date.now() - startedAt,
			});

			let released = false;
			return () => {
				if (released) return;
				released = true;
				try {
					const stored = JSON.parse(fs.readFileSync(ownerFile, "utf-8")) as {
						ownerId?: string;
					};
					if (stored.ownerId !== ownerId) {
						logMulticodex("token.refresh.lock.release.skipped", {
							email,
							lockId,
							reason: "owner_mismatch",
						});
						return;
					}
					fs.rmSync(lockPath, { recursive: true, force: true });
					logMulticodex("token.refresh.lock.released", { email, lockId });
				} catch (error) {
					if (!fs.existsSync(lockPath)) {
						logMulticodex("token.refresh.lock.release.missing", {
							email,
							lockId,
						});
						return;
					}
					logMulticodex("token.refresh.lock.release.failure", {
						email,
						lockId,
						error,
					});
				}
			};
		} catch (error) {
			if (getErrnoCode(error) !== "EEXIST") {
				logMulticodex("token.refresh.lock.acquire.failure", {
					email,
					lockId,
					error,
				});
				throw error;
			}

			let lockAgeMs = 0;
			try {
				lockAgeMs = Date.now() - fs.statSync(lockPath).mtimeMs;
			} catch {
				continue;
			}

			if (lockAgeMs > TOKEN_REFRESH_LOCK_STALE_MS) {
				logMulticodex("token.refresh.lock.stale_removed", {
					email,
					lockId,
					lockAgeMs,
				});
				fs.rmSync(lockPath, { recursive: true, force: true });
				continue;
			}

			const waitedMs = Date.now() - startedAt;
			if (waitedMs > TOKEN_REFRESH_LOCK_WAIT_MS) {
				const timeoutError = new Error(
					`Timed out waiting for token refresh lock for ${email}`,
				);
				logMulticodex("token.refresh.lock.timeout", {
					email,
					lockId,
					waitedMs,
				});
				throw timeoutError;
			}

			if (!loggedWait) {
				loggedWait = true;
				logMulticodex("token.refresh.lock.wait", { email, lockId });
			}
			await sleep(TOKEN_REFRESH_LOCK_POLL_MS);
		}
	}
}

export function isQuotaErrorMessage(message: string): boolean {
	return /\b429\b|quota|usage limit|rate.?limit|too many requests|limit reached/i.test(
		message,
	);
}

function getErrorMessage(err: unknown): string {
	if (err instanceof Error) return err.message;
	return typeof err === "string" ? err : JSON.stringify(err);
}

function createErrorAssistantMessage(
	model: Model<Api>,
	message: string,
): AssistantMessage {
	return {
		role: "assistant",
		content: [],
		api: model.api,
		provider: model.provider,
		model: model.id,
		usage: {
			input: 0,
			output: 0,
			cacheRead: 0,
			cacheWrite: 0,
			totalTokens: 0,
			cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0, total: 0 },
		},
		stopReason: "error",
		errorMessage: message,
		timestamp: Date.now(),
	};
}

interface CodexUsageWindow {
	usedPercent?: number;
	resetAt?: number;
}

export interface CodexUsageSnapshot {
	primary?: CodexUsageWindow;
	secondary?: CodexUsageWindow;
	fetchedAt: number;
}

interface WhamUsageResponse {
	rate_limit?: {
		primary_window?: WhamUsageWindow;
		secondary_window?: WhamUsageWindow;
	};
}

type WhamUsageWindow = {
	reset_at?: number;
	used_percent?: number;
};

export type ThinkingLevelMap = Partial<
	Record<"off" | "minimal" | "low" | "medium" | "high" | "xhigh", string | null>
>;

export interface ProviderModelDef {
	id: string;
	name: string;
	reasoning: boolean;
	thinkingLevelMap?: ThinkingLevelMap;
	input: ("text" | "image")[];
	cost: {
		input: number;
		output: number;
		cacheRead: number;
		cacheWrite: number;
	};
	contextWindow: number;
	maxTokens: number;
}

function getThinkingLevelMap(model: Model<Api>): ThinkingLevelMap | undefined {
	return (model as Model<Api> & { thinkingLevelMap?: ThinkingLevelMap })
		.thinkingLevelMap;
}

export function getOpenAICodexMirror(): {
	baseUrl: string;
	models: ProviderModelDef[];
} {
	const sourceModels = getModels("openai-codex");
	return {
		baseUrl: sourceModels[0]?.baseUrl || "https://chatgpt.com/backend-api",
		models: sourceModels.map((m) => {
			const thinkingLevelMap = getThinkingLevelMap(m);
			return {
				id: m.id,
				name: m.name,
				reasoning: m.reasoning,
				...(thinkingLevelMap !== undefined ? { thinkingLevelMap } : {}),
				input: m.input,
				cost: m.cost,
				contextWindow: m.contextWindow,
				maxTokens: m.maxTokens,
			};
		}),
	};
}

function normalizeUsedPercent(value?: number): number | undefined {
	if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
	return Math.min(100, Math.max(0, value));
}

function normalizeResetAt(value?: number): number | undefined {
	if (typeof value !== "number" || !Number.isFinite(value)) return undefined;
	return value * 1000;
}

function parseUsageWindow(
	window?: WhamUsageWindow,
): CodexUsageWindow | undefined {
	if (!window) return undefined;
	const usedPercent = normalizeUsedPercent(window.used_percent);
	const resetAt = normalizeResetAt(window.reset_at);
	if (usedPercent === undefined && resetAt === undefined) return undefined;
	return { usedPercent, resetAt };
}

export function parseCodexUsageResponse(
	data: WhamUsageResponse,
): Omit<CodexUsageSnapshot, "fetchedAt"> {
	return {
		primary: parseUsageWindow(data.rate_limit?.primary_window),
		secondary: parseUsageWindow(data.rate_limit?.secondary_window),
	};
}

export function isUsageUntouched(usage?: CodexUsageSnapshot): boolean {
	const primary = usage?.primary?.usedPercent;
	const secondary = usage?.secondary?.usedPercent;
	if (primary === undefined || secondary === undefined) return false;
	return primary === 0 && secondary === 0;
}

export function getNextResetAt(usage?: CodexUsageSnapshot): number | undefined {
	const candidates = [
		usage?.primary?.resetAt,
		usage?.secondary?.resetAt,
	].filter((value): value is number => typeof value === "number");
	if (candidates.length === 0) return undefined;
	return Math.min(...candidates);
}

// Weekly reset only (secondary window)
export function getWeeklyResetAt(
	usage?: CodexUsageSnapshot,
): number | undefined {
	const resetAt = usage?.secondary?.resetAt;
	return typeof resetAt === "number" ? resetAt : undefined;
}

function formatResetAt(resetAt?: number): string {
	if (!resetAt) return "unknown";
	const diffMs = resetAt - Date.now();
	if (diffMs <= 0) return "now";
	const diffMinutes = Math.max(1, Math.round(diffMs / 60000));
	if (diffMinutes < 60) return `in ${diffMinutes}m`;
	const diffHours = Math.round(diffMinutes / 60);
	if (diffHours < 48) return `in ${diffHours}h`;
	const diffDays = Math.round(diffHours / 24);
	return `in ${diffDays}d`;
}

async function fetchCodexUsage(
	accessToken: string,
	accountId: string | undefined,
	options?: { signal?: AbortSignal },
): Promise<CodexUsageSnapshot> {
	const { controller, clear } = createTimeoutController(
		options?.signal,
		USAGE_REQUEST_TIMEOUT_MS,
	);
	try {
		const headers: Record<string, string> = {
			Authorization: `Bearer ${accessToken}`,
			Accept: "application/json",
		};
		if (accountId) {
			headers["ChatGPT-Account-Id"] = accountId;
		}

		const response = await fetch("https://chatgpt.com/backend-api/wham/usage", {
			headers,
			signal: controller.signal,
		});

		if (!response.ok) {
			throw new Error(`Usage request failed: ${response.status}`);
		}

		const data = (await response.json()) as WhamUsageResponse;
		return { ...parseCodexUsageResponse(data), fetchedAt: Date.now() };
	} finally {
		clear();
	}
}

function createLinkedAbortController(signal?: AbortSignal): AbortController {
	const controller = new AbortController();
	if (signal?.aborted) {
		controller.abort();
		return controller;
	}
	signal?.addEventListener("abort", () => controller.abort(), { once: true });
	return controller;
}

function createTimeoutController(
	signal: AbortSignal | undefined,
	timeoutMs: number,
): { controller: AbortController; clear: () => void } {
	const controller = createLinkedAbortController(signal);
	const timeout = setTimeout(() => controller.abort(), timeoutMs);
	return {
		controller,
		clear: () => clearTimeout(timeout),
	};
}

function withProvider(
	event: AssistantMessageEvent,
	provider: string,
): AssistantMessageEvent {
	if ("partial" in event) {
		return { ...event, partial: { ...event.partial, provider } };
	}
	if (event.type === "done") {
		return { ...event, message: { ...event.message, provider } };
	}
	if (event.type === "error") {
		return { ...event, error: { ...event.error, provider } };
	}
	return event;
}

async function openLoginInBrowser(
	pi: ExtensionAPI,
	ctx: ExtensionCommandContext,
	url: string,
): Promise<void> {
	let command: string;
	let args: string[];

	if (process.platform === "darwin") {
		command = "open";
		args = [url];
	} else if (process.platform === "win32") {
		command = "cmd";
		args = ["/c", "start", "", url];
	} else {
		command = "xdg-open";
		args = [url];
	}

	try {
		await pi.exec(command, args);
	} catch (error) {
		ctx.ui.notify(
			"Could not open a browser automatically. Please open the login URL manually.",
			"warning",
		);
		console.warn("[multicodex] Failed to open browser:", error);
	}
}

// =============================================================================
// Storage
// =============================================================================

export interface Account {
	email: string;
	accessToken: string;
	refreshToken: string;
	expiresAt: number;
	accountId?: string;
	lastUsed?: number;
	quotaExhaustedUntil?: number;
}

interface StorageData {
	accounts: Account[];
	activeEmail?: string;
}

const STORAGE_FILE = path.join(os.homedir(), ".pi", "agent", "multicodex.json");
const PROVIDER_ID = "multicodex";
const QUOTA_COOLDOWN_MS = 60 * 60 * 1000; // 1 hour

type WarningHandler = (message: string) => void;

function isAccountAvailable(account: Account, now: number): boolean {
	return !account.quotaExhaustedUntil || account.quotaExhaustedUntil <= now;
}

function pickRandomAccount(accounts: Account[]): Account | undefined {
	if (accounts.length === 0) return undefined;
	return accounts[Math.floor(Math.random() * accounts.length)];
}

function pickEarliestWeeklyResetAccount(
	accounts: Account[],
	usageByEmail: Map<string, CodexUsageSnapshot>,
): Account | undefined {
	const candidates = accounts
		.map((account) => ({
			account,
			resetAt: getWeeklyResetAt(usageByEmail.get(account.email)),
		}))
		.filter(
			(entry): entry is { account: Account; resetAt: number } =>
				typeof entry.resetAt === "number",
		)
		.sort((a, b) => a.resetAt - b.resetAt);

	return candidates[0]?.account;
}

export function pickBestAccount(
	accounts: Account[],
	usageByEmail: Map<string, CodexUsageSnapshot>,
	options?: { excludeEmails?: Set<string>; now?: number },
): Account | undefined {
	const now = options?.now ?? Date.now();
	const available = accounts.filter(
		(account) =>
			isAccountAvailable(account, now) &&
			!options?.excludeEmails?.has(account.email),
	);
	if (available.length === 0) return undefined;

	const withUsage = available.filter((account) =>
		usageByEmail.has(account.email),
	);
	const untouched = withUsage.filter((account) =>
		isUsageUntouched(usageByEmail.get(account.email)),
	);

	if (untouched.length > 0) {
		return (
			pickEarliestWeeklyResetAccount(untouched, usageByEmail) ??
			pickRandomAccount(untouched)
		);
	}

	const earliestWeeklyReset = pickEarliestWeeklyResetAccount(
		withUsage,
		usageByEmail,
	);
	if (earliestWeeklyReset) return earliestWeeklyReset;

	return pickRandomAccount(available);
}

// =============================================================================
// Account Manager
// =============================================================================

export class AccountManager {
	private data: StorageData;
	private usageCache = new Map<string, CodexUsageSnapshot>();
	private tokenRefreshes = new Map<string, Promise<string>>();
	private warningHandler?: WarningHandler;
	private manualEmail?: string;

	constructor() {
		this.data = this.load();
	}

	private load(): StorageData {
		try {
			const storageFile = getMulticodexStorageFile();
			if (fs.existsSync(storageFile)) {
				const data = JSON.parse(
					fs.readFileSync(storageFile, "utf-8"),
				) as StorageData;
				logMulticodex("storage.load.success", {
					accounts: data.accounts?.length ?? 0,
					activeEmail: data.activeEmail,
				});
				return data;
			}
			logMulticodex("storage.load.missing");
		} catch (e) {
			console.error("Failed to load multicodex accounts:", e);
			logMulticodex("storage.load.failure", { error: e });
		}
		return { accounts: [] };
	}

	private save(): void {
		try {
			const storageFile = getMulticodexStorageFile();
			const dir = path.dirname(storageFile);
			if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
			fs.writeFileSync(storageFile, JSON.stringify(this.data, null, 2));
			logMulticodex("storage.save.success", {
				accounts: this.data.accounts.map((account) => ({
					email: account.email,
					expiresAt: account.expiresAt,
				})),
				activeEmail: this.data.activeEmail,
			});
		} catch (e) {
			console.error("Failed to save multicodex accounts:", e);
			logMulticodex("storage.save.failure", { error: e });
		}
	}

	getAccounts(): Account[] {
		return this.data.accounts;
	}

	getAccount(email: string): Account | undefined {
		return this.data.accounts.find((a) => a.email === email);
	}

	setWarningHandler(handler?: WarningHandler): void {
		this.warningHandler = handler;
	}

	addOrUpdateAccount(email: string, creds: OAuthCredentials): void {
		const existing = this.getAccount(email);
		const accountId =
			typeof creds.accountId === "string" ? creds.accountId : undefined;
		logMulticodex("account.upsert.start", {
			email,
			existing: Boolean(existing),
			hasAccountId: Boolean(accountId),
			expiresAt: creds.expires,
		});
		if (existing) {
			existing.accessToken = creds.access;
			existing.refreshToken = creds.refresh;
			existing.expiresAt = creds.expires;
			if (accountId) {
				existing.accountId = accountId;
			}
		} else {
			this.data.accounts.push({
				email,
				accessToken: creds.access,
				refreshToken: creds.refresh,
				expiresAt: creds.expires,
				accountId,
			});
		}
		this.setActiveAccount(email);
		logMulticodex("account.upsert.success", { email });
	}

	getActiveAccount(): Account | undefined {
		const manual = this.getManualAccount();
		if (manual) return manual;
		if (this.data.activeEmail) {
			return this.getAccount(this.data.activeEmail);
		}
		return this.data.accounts[0];
	}

	getManualAccount(): Account | undefined {
		if (!this.manualEmail) return undefined;
		const account = this.getAccount(this.manualEmail);
		if (!account) {
			this.manualEmail = undefined;
			return undefined;
		}
		return account;
	}

	hasManualAccount(): boolean {
		return Boolean(this.getManualAccount());
	}

	getAvailableManualAccount(options?: {
		now?: number;
		excludeEmails?: Set<string>;
	}): Account | undefined {
		const now = options?.now ?? Date.now();
		this.clearExpiredExhaustion(now);
		const manual = this.getManualAccount();
		if (!manual) return undefined;
		if (options?.excludeEmails?.has(manual.email)) return undefined;
		if (!isAccountAvailable(manual, now)) return undefined;
		return manual;
	}

	setActiveAccount(email: string): void {
		const account = this.getAccount(email);
		if (!account) {
			logMulticodex("account.active.missing", { email });
			return;
		}
		this.data.activeEmail = email;
		account.lastUsed = Date.now();
		this.save();
		// 		logMulticodex("account.active.set", { email });
	}

	setManualAccount(email: string): void {
		const account = this.getAccount(email);
		if (!account) {
			logMulticodex("account.manual.missing", { email });
			return;
		}
		this.manualEmail = email;
		account.lastUsed = Date.now();
		logMulticodex("account.manual.set", { email });
	}

	clearManualAccount(): void {
		if (this.manualEmail) {
			logMulticodex("account.manual.clear", { email: this.manualEmail });
		}
		this.manualEmail = undefined;
	}

	markExhausted(email: string, until: number): void {
		const account = this.getAccount(email);
		if (account) {
			account.quotaExhaustedUntil = until;
			this.save();
			logMulticodex("account.quota.mark_exhausted", { email, until });
		} else {
			logMulticodex("account.quota.mark_exhausted_missing", { email, until });
		}
	}

	getCachedUsage(email: string): CodexUsageSnapshot | undefined {
		return this.usageCache.get(email);
	}

	async refreshUsageForAccount(
		account: Account,
		options?: { force?: boolean; signal?: AbortSignal },
	): Promise<CodexUsageSnapshot | undefined> {
		const cached = this.usageCache.get(account.email);
		const now = Date.now();
		if (
			cached &&
			!options?.force &&
			now - cached.fetchedAt < USAGE_CACHE_TTL_MS
		) {
			return cached;
		}

		try {
			// 			logMulticodex("usage.refresh.start", {
			// 				email: account.email,
			// 				force: Boolean(options?.force),
			// 			});
			const token = await this.ensureValidToken(account);
			const usage = await fetchCodexUsage(token, account.accountId, {
				signal: options?.signal,
			});
			this.usageCache.set(account.email, usage);
			// 			logMulticodex("usage.refresh.success", {
			// 				email: account.email,
			// 				primaryUsedPercent: usage.primary?.usedPercent,
			// 				secondaryUsedPercent: usage.secondary?.usedPercent,
			// 			});
			return usage;
		} catch (error) {
			logMulticodex("usage.refresh.failure", {
				email: account.email,
				error,
			});
			this.warningHandler?.(
				`Multicodex: failed to fetch usage for ${account.email}: ${getErrorMessage(
					error,
				)}`,
			);
			return undefined;
		}
	}

	async refreshUsageForAllAccounts(options?: {
		force?: boolean;
		signal?: AbortSignal;
	}): Promise<void> {
		const accounts = this.getAccounts();
		// 		logMulticodex("usage.refresh_all.start", {
		// 			accounts: accounts.length,
		// 			force: Boolean(options?.force),
		// 		});
		await Promise.all(
			accounts.map((account) => this.refreshUsageForAccount(account, options)),
		);
		// 		logMulticodex("usage.refresh_all.done", { accounts: accounts.length });
	}

	async refreshUsageIfStale(
		accounts: Account[],
		options?: { signal?: AbortSignal },
	): Promise<void> {
		const now = Date.now();
		const stale = accounts.filter((account) => {
			const cached = this.usageCache.get(account.email);
			return !cached || now - cached.fetchedAt >= USAGE_CACHE_TTL_MS;
		});
		if (stale.length === 0) return;
		await Promise.all(
			stale.map((account) =>
				this.refreshUsageForAccount(account, { force: true, ...options }),
			),
		);
	}

	async activateBestAccount(options?: {
		excludeEmails?: Set<string>;
		signal?: AbortSignal;
	}): Promise<Account | undefined> {
		const now = Date.now();
		this.clearExpiredExhaustion(now);
		const accounts = this.data.accounts;
		await this.refreshUsageIfStale(accounts, options);

		const selected = pickBestAccount(accounts, this.usageCache, {
			excludeEmails: options?.excludeEmails,
			now,
		});
		if (selected) {
			this.setActiveAccount(selected.email);
			// 			logMulticodex("account.best.selected", {
			// 				email: selected.email,
			// 				excludedEmails: options?.excludeEmails?.size ?? 0,
			// 			});
		} else {
			logMulticodex("account.best.none", {
				accounts: accounts.length,
				excludedEmails: options?.excludeEmails?.size ?? 0,
			});
		}
		return selected;
	}

	async handleQuotaExceeded(
		account: Account,
		options?: { signal?: AbortSignal },
	): Promise<void> {
		logMulticodex("quota.exceeded", { email: account.email });
		const usage = await this.refreshUsageForAccount(account, {
			force: true,
			signal: options?.signal,
		});
		const now = Date.now();
		const resetAt = getNextResetAt(usage);
		const fallback = now + QUOTA_COOLDOWN_MS;
		const until = resetAt && resetAt > now ? resetAt : fallback;
		this.markExhausted(account.email, until);
	}

	private clearExpiredExhaustion(now: number): void {
		let changed = false;
		for (const account of this.data.accounts) {
			if (account.quotaExhaustedUntil && account.quotaExhaustedUntil <= now) {
				account.quotaExhaustedUntil = undefined;
				changed = true;
			}
		}
		if (changed) {
			this.save();
		}
	}

	private isAccessTokenFresh(account: Account): boolean {
		return Date.now() < account.expiresAt - ACCESS_TOKEN_REFRESH_SKEW_MS;
	}

	private tryReloadFromDisk(): boolean {
		try {
			const storageFile = getMulticodexStorageFile();
			if (!fs.existsSync(storageFile)) return false;
			this.data = JSON.parse(
				fs.readFileSync(storageFile, "utf-8"),
			) as StorageData;
			logMulticodex("storage.reload.success", {
				accounts: this.data.accounts.length,
				activeEmail: this.data.activeEmail,
			});
			return true;
		} catch (error) {
			logMulticodex("storage.reload.failure", { error });
			return false;
		}
	}

	private syncAccountFields(target: Account, source: Account): void {
		target.email = source.email;
		target.accessToken = source.accessToken;
		target.refreshToken = source.refreshToken;
		target.expiresAt = source.expiresAt;
		target.accountId = source.accountId;
		target.lastUsed = source.lastUsed;
		target.quotaExhaustedUntil = source.quotaExhaustedUntil;
	}

	private getOrAttachAccount(account: Account): Account {
		const current = this.getAccount(account.email);
		if (current) return current;
		this.data.accounts.push(account);
		logMulticodex("account.attach_missing", { email: account.email });
		return account;
	}

	private async refreshTokenWithLocks(account: Account): Promise<string> {
		const releaseLock = await acquireTokenRefreshLock(account.email);
		try {
			this.tryReloadFromDisk();
			const current = this.getOrAttachAccount(account);
			if (current !== account) {
				this.syncAccountFields(account, current);
			}

			if (this.isAccessTokenFresh(current)) {
				logMulticodex("token.refresh.skip_after_lock", {
					email: current.email,
					expiresAt: current.expiresAt,
				});
				return current.accessToken;
			}

			logMulticodex("token.refresh.start", {
				email: current.email,
				expiresAt: current.expiresAt,
			});
			const result = await refreshOpenAICodexToken(current.refreshToken);
			current.accessToken = result.access;
			current.refreshToken = result.refresh;
			current.expiresAt = result.expires;
			const accountId =
				typeof result.accountId === "string" ? result.accountId : undefined;
			if (accountId) {
				current.accountId = accountId;
			}
			this.save();
			if (current !== account) {
				this.syncAccountFields(account, current);
			}
			logMulticodex("token.refresh.success", {
				email: current.email,
				expiresAt: current.expiresAt,
				hasAccountId: Boolean(current.accountId),
			});
			return current.accessToken;
		} catch (error) {
			logMulticodex("token.refresh.failure", {
				email: account.email,
				error,
			});
			throw error;
		} finally {
			releaseLock();
		}
	}

	async ensureValidToken(account: Account): Promise<string> {
		// Valid for at least 5 more mins
		if (this.isAccessTokenFresh(account)) {
			return account.accessToken;
		}

		const inFlight = this.tokenRefreshes.get(account.email);
		if (inFlight) {
			logMulticodex("token.refresh.wait_in_process", {
				email: account.email,
			});
			return inFlight;
		}

		const refresh = this.refreshTokenWithLocks(account).finally(() => {
			this.tokenRefreshes.delete(account.email);
		});
		this.tokenRefreshes.set(account.email, refresh);
		return refresh;
	}
}

// =============================================================================
// Extension Entry Point
// =============================================================================

type ApiProviderRef = NonNullable<ReturnType<typeof getApiProvider>>;

export function buildMulticodexProviderConfig(accountManager: AccountManager): {
	baseUrl: string;
	apiKey: string;
	api: "openai-codex-responses";
	streamSimple: (
		model: Model<Api>,
		context: Context,
		options?: SimpleStreamOptions,
	) => AssistantMessageEventStream;
	models: ProviderModelDef[];
} {
	const mirror = getOpenAICodexMirror();
	const baseProvider = getApiProvider("openai-codex-responses");
	if (!baseProvider) {
		throw new Error(
			"OpenAI Codex provider not available. Please update pi to include openai-codex support.",
		);
	}
	return {
		baseUrl: mirror.baseUrl,
		apiKey: "managed-by-extension",
		api: "openai-codex-responses",
		streamSimple: createStreamWrapper(accountManager, baseProvider),
		models: mirror.models,
	};
}

export default function multicodexExtension(pi: ExtensionAPI) {
	const accountManager = new AccountManager();
	let lastContext: ExtensionContext | undefined;

	accountManager.setWarningHandler((message) => {
		if (lastContext) {
			lastContext.ui.notify(message, "warning");
		}
	});

	pi.registerProvider(
		PROVIDER_ID,
		buildMulticodexProviderConfig(accountManager),
	);

	// Login command
	pi.registerCommand("multicodex-login", {
		description: "Login to an OpenAI Codex account for the rotation pool",
		handler: async (
			args: string,
			ctx: ExtensionCommandContext,
		): Promise<void> => {
			const email = args.trim();
			if (!email) {
				ctx.ui.notify(
					"Please provide an email/identifier: /multicodex-login my@email.com",
					"error",
				);
				return;
			}

			try {
				ctx.ui.notify(
					`Starting login for ${email}... Check your browser.`,
					"info",
				);

				const creds = await loginOpenAICodex({
					onAuth: ({ url }) => {
						void openLoginInBrowser(pi, ctx, url);
						ctx.ui.notify(`Please open this URL to login: ${url}`, "info");
						console.log(`[multicodex] Login URL: ${url}`);
					},
					onPrompt: async ({ message }) => (await ctx.ui.input(message)) || "",
				});

				accountManager.addOrUpdateAccount(email, creds);
				ctx.ui.notify(`Successfully logged in as ${email}`, "info");
			} catch (e) {
				ctx.ui.notify(`Login failed: ${getErrorMessage(e)}`, "error");
			}
		},
	});

	// Switch active account
	pi.registerCommand("multicodex-use", {
		description: "Switch active Codex account for this session",
		handler: async (
			_args: string,
			ctx: ExtensionCommandContext,
		): Promise<void> => {
			const accounts = accountManager.getAccounts();
			if (accounts.length === 0) {
				ctx.ui.notify(
					"No accounts logged in. Use /multicodex-login first.",
					"warning",
				);
				return;
			}

			const options = accounts.map(
				(a) =>
					a.email +
					(a.quotaExhaustedUntil && a.quotaExhaustedUntil > Date.now()
						? " (Quota)"
						: ""),
			);
			const selected = await ctx.ui.select("Select Account", options);
			if (!selected) return;

			const email = selected.split(" ")[0];
			accountManager.setManualAccount(email);
			ctx.ui.notify(`Switched to ${email}`, "info");
		},
	});

	pi.registerCommand("multicodex-status", {
		description: "Show all Codex accounts and active status",
		handler: async (
			_args: string,
			ctx: ExtensionCommandContext,
		): Promise<void> => {
			await accountManager.refreshUsageForAllAccounts();
			const accounts = accountManager.getAccounts();
			if (accounts.length === 0) {
				ctx.ui.notify(
					"No accounts logged in. Use /multicodex-login first.",
					"warning",
				);
				return;
			}

			const active = accountManager.getActiveAccount();
			const options = accounts.map((account) => {
				const usage = accountManager.getCachedUsage(account.email);
				const isActive = active?.email === account.email;
				const quotaHit =
					account.quotaExhaustedUntil &&
					account.quotaExhaustedUntil > Date.now();
				const untouched = isUsageUntouched(usage) ? "untouched" : null;
				const tags = [
					isActive ? "active" : null,
					quotaHit ? "quota" : null,
					untouched,
				]
					.filter(Boolean)
					.join(", ");
				const suffix = tags ? ` (${tags})` : "";
				const primaryUsed = usage?.primary?.usedPercent;
				const secondaryUsed = usage?.secondary?.usedPercent;
				const primaryReset = usage?.primary?.resetAt;
				const secondaryReset = usage?.secondary?.resetAt;
				const primaryLabel =
					primaryUsed === undefined ? "unknown" : `${Math.round(primaryUsed)}%`;
				const secondaryLabel =
					secondaryUsed === undefined
						? "unknown"
						: `${Math.round(secondaryUsed)}%`;
				const usageSummary = `5h ${primaryLabel} reset:${formatResetAt(primaryReset)} | weekly ${secondaryLabel} reset:${formatResetAt(secondaryReset)}`;
				return `${isActive ? "•" : " "} ${account.email}${suffix} - ${usageSummary}`;
			});

			await ctx.ui.select("MultiCodex Accounts", options);
		},
	});

	// Hooks
	pi.on("session_start", (_event: unknown, ctx: ExtensionContext) => {
		lastContext = ctx;
		if (accountManager.getAccounts().length === 0) return;
		void (async () => {
			await accountManager.refreshUsageForAllAccounts({ force: true });
			const manual = accountManager.getAvailableManualAccount();
			if (manual) return;
			if (accountManager.hasManualAccount()) {
				accountManager.clearManualAccount();
			}
			await accountManager.activateBestAccount();
		})();
	});

	pi.on(
		"session_switch",
		(event: { reason?: string }, ctx: ExtensionContext) => {
			lastContext = ctx;
			if (event.reason === "new") {
				void (async () => {
					await accountManager.refreshUsageForAllAccounts({ force: true });
					const manual = accountManager.getAvailableManualAccount();
					if (manual) return;
					if (accountManager.hasManualAccount()) {
						accountManager.clearManualAccount();
					}
					await accountManager.activateBestAccount();
				})();
			}
		},
	);
}

// =============================================================================
// Stream Wrapper
// =============================================================================

const MAX_ROTATION_RETRIES = 5;

export function createStreamWrapper(
	accountManager: AccountManager,
	baseProvider: ApiProviderRef,
) {
	return (
		model: Model<Api>,
		context: Context,
		options?: SimpleStreamOptions,
	): AssistantMessageEventStream => {
		const stream = createAssistantMessageEventStream();
		const requestId = crypto.randomUUID();
		// 		logMulticodex("stream.start", {
		// 			requestId,
		// 			model: model.id,
		// 			provider: model.provider,
		// 		});

		(async () => {
			try {
				const excludedEmails = new Set<string>();
				for (let attempt = 0; attempt <= MAX_ROTATION_RETRIES; attempt++) {
					const now = Date.now();
					const manual = accountManager.getAvailableManualAccount({
						excludeEmails: excludedEmails,
						now,
					});
					const usingManual = Boolean(manual);
					let account = manual;
					if (!account) {
						if (accountManager.hasManualAccount()) {
							accountManager.clearManualAccount();
						}
						account = await accountManager.activateBestAccount({
							excludeEmails: excludedEmails,
							signal: options?.signal,
						});
					}
					if (!account) {
						throw new Error(
							"No available Multicodex accounts. Please use /multicodex-login.",
						);
					}

					// 					logMulticodex("stream.account.selected", {
					// 						requestId,
					// 						email: account.email,
					// 						attempt,
					// 						manual: usingManual,
					// 					});
					const token = await accountManager.ensureValidToken(account);

					const abortController = createLinkedAbortController(options?.signal);

					const internalModel: Model<"openai-codex-responses"> = {
						...(model as Model<"openai-codex-responses">),
						provider: "openai-codex",
						api: "openai-codex-responses",
					};

					const inner = baseProvider.streamSimple(
						{
							...internalModel,
							headers: {
								...(internalModel.headers || {}),
								"X-Multicodex-Account": account.email,
							},
						},
						context,
						{
							...options,
							apiKey: token,
							signal: abortController.signal,
						},
					);

					let forwardedAny = false;
					let retry = false;

					for await (const event of inner) {
						if (event.type === "error") {
							const msg = event.error.errorMessage || "";
							const isQuota = isQuotaErrorMessage(msg);

							if (isQuota && !forwardedAny && attempt < MAX_ROTATION_RETRIES) {
								logMulticodex("stream.quota.retry", {
									requestId,
									email: account.email,
									attempt,
								});
								await accountManager.handleQuotaExceeded(account, {
									signal: options?.signal,
								});
								if (usingManual) {
									accountManager.clearManualAccount();
								}
								excludedEmails.add(account.email);
								abortController.abort();
								retry = true;
								break;
							}

							logMulticodex("stream.error", {
								requestId,
								email: account.email,
								attempt,
								isQuota,
								message: msg,
							});
							stream.push(withProvider(event, model.provider));
							stream.end();
							return;
						}

						forwardedAny = true;
						stream.push(withProvider(event, model.provider));

						if (event.type === "done") {
							// 							logMulticodex("stream.done", {
							// 								requestId,
							// 								email: account.email,
							// 								attempt,
							// 							});
							stream.end();
							return;
						}
					}

					if (retry) {
						continue;
					}

					// If inner finished without done/error, stop to avoid hanging.
					logMulticodex("stream.inner_finished_without_terminal_event", {
						requestId,
						email: account.email,
						attempt,
					});
					stream.end();
					return;
				}
			} catch (e) {
				const message = getErrorMessage(e);
				logMulticodex("stream.failure", { requestId, error: e });
				const errorEvent: AssistantMessageEvent = {
					type: "error",
					reason: "error",
					error: createErrorAssistantMessage(
						model,
						`Multicodex failed: ${message}`,
					),
				};
				stream.push(withProvider(errorEvent, model.provider));
				stream.end();
			}
		})();

		return stream;
	};
}
