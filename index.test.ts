import * as fs from "node:fs";
import * as os from "node:os";
import * as path from "node:path";
import { getModels } from "@mariozechner/pi-ai";
import { refreshOpenAICodexToken } from "@mariozechner/pi-ai/oauth";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

vi.mock("@mariozechner/pi-ai/oauth", () => ({
	loginOpenAICodex: vi.fn(),
	refreshOpenAICodexToken: vi.fn(),
}));

import {
	type Account,
	AccountManager,
	buildMulticodexProviderConfig,
	createStreamWrapper,
	getNextResetAt,
	getOpenAICodexMirror,
	getWeeklyResetAt,
	isQuotaErrorMessage,
	isUsageUntouched,
	parseCodexUsageResponse,
	pickBestAccount,
	type ThinkingLevelMap,
} from "./index";

describe("isQuotaErrorMessage", () => {
	it("matches 429", () => {
		expect(isQuotaErrorMessage("HTTP 429 Too Many Requests")).toBe(true);
	});

	it("matches common quota / usage limit messages", () => {
		expect(isQuotaErrorMessage("You have hit your ChatGPT usage limit.")).toBe(
			true,
		);
		expect(isQuotaErrorMessage("Quota exceeded")).toBe(true);
	});

	it("matches rate limit phrasing", () => {
		expect(isQuotaErrorMessage("rate limit exceeded")).toBe(true);
		expect(isQuotaErrorMessage("Rate-Limit: exceeded")).toBe(true);
	});

	it("does not match unrelated errors", () => {
		expect(isQuotaErrorMessage("network error")).toBe(false);
		expect(isQuotaErrorMessage("bad request")).toBe(false);
	});
});

describe("getOpenAICodexMirror", () => {
	it("mirrors the openai-codex provider models exactly (metadata)", () => {
		const sourceModels = getModels("openai-codex");
		const expected = {
			baseUrl: sourceModels[0]?.baseUrl || "https://chatgpt.com/backend-api",
			models: sourceModels.map((m) => {
				const thinkingLevelMap = (
					m as typeof m & { thinkingLevelMap?: ThinkingLevelMap }
				).thinkingLevelMap;
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

		expect(getOpenAICodexMirror()).toEqual(expected);
	});
});

describe("buildMulticodexProviderConfig", () => {
	it("uses mirrored models and baseUrl", () => {
		const mirror = getOpenAICodexMirror();
		const config = buildMulticodexProviderConfig(
			{} as unknown as AccountManager,
		);

		expect(config.api).toBe("openai-codex-responses");
		expect(config.apiKey).toBe("managed-by-extension");
		expect(config.baseUrl).toBe(mirror.baseUrl);
		expect(config.models).toEqual(mirror.models);
		expect(typeof config.streamSimple).toBe("function");
	});
});

function makeAccount(email: string, overrides?: Partial<Account>): Account {
	return {
		email,
		accessToken: "token",
		refreshToken: "refresh",
		expiresAt: 0,
		...overrides,
	};
}

type StreamWrapper = ReturnType<typeof createStreamWrapper>;
type StreamModel = Parameters<StreamWrapper>[0];
type StreamContext = Parameters<StreamWrapper>[1];
type BaseProvider = Parameters<typeof createStreamWrapper>[1];
type RefreshTokenResult = Awaited<ReturnType<typeof refreshOpenAICodexToken>>;
const refreshTokenMock = vi.mocked(refreshOpenAICodexToken);

describe("AccountManager token refresh", () => {
	let tempDir: string;
	let previousStorageFile: string | undefined;
	let previousLogFile: string | undefined;
	let previousLockDir: string | undefined;

	beforeEach(() => {
		tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "multicodex-test-"));
		previousStorageFile = process.env.MULTICODEX_STORAGE_FILE;
		previousLogFile = process.env.MULTICODEX_LOG_FILE;
		previousLockDir = process.env.MULTICODEX_LOCK_DIR;
		process.env.MULTICODEX_STORAGE_FILE = path.join(tempDir, "accounts.json");
		process.env.MULTICODEX_LOG_FILE = path.join(tempDir, "multicodex.log");
		process.env.MULTICODEX_LOCK_DIR = path.join(tempDir, "locks");
		refreshTokenMock.mockReset();
	});

	function restoreEnv(name: string, value: string | undefined): void {
		if (value === undefined) {
			delete process.env[name];
		} else {
			process.env[name] = value;
		}
	}

	afterEach(() => {
		restoreEnv("MULTICODEX_STORAGE_FILE", previousStorageFile);
		restoreEnv("MULTICODEX_LOG_FILE", previousLogFile);
		restoreEnv("MULTICODEX_LOCK_DIR", previousLockDir);
		fs.rmSync(tempDir, { recursive: true, force: true });
	});

	it("deduplicates concurrent refreshes for the same account", async () => {
		const manager = new AccountManager();
		manager.addOrUpdateAccount("a@example.com", {
			access: "old-access",
			refresh: "old-refresh",
			expires: 0,
			accountId: "acct-old",
		});
		const account = manager.getAccount("a@example.com");
		expect(account).toBeDefined();

		let resolveRefresh: (value: RefreshTokenResult) => void = () => {};
		let markStarted: () => void = () => {};
		const refreshResult = new Promise<RefreshTokenResult>((resolve) => {
			resolveRefresh = resolve;
		});
		const refreshStarted = new Promise<void>((resolve) => {
			markStarted = resolve;
		});
		refreshTokenMock.mockImplementation(async () => {
			markStarted();
			return refreshResult;
		});

		const first = manager.ensureValidToken(account as Account);
		await refreshStarted;
		const second = manager.ensureValidToken(account as Account);

		const expires = Date.now() + 60 * 60 * 1000;
		resolveRefresh({
			access: "new-access",
			refresh: "new-refresh",
			expires,
			accountId: "acct-new",
		});

		await expect(Promise.all([first, second])).resolves.toEqual([
			"new-access",
			"new-access",
		]);
		expect(refreshTokenMock).toHaveBeenCalledTimes(1);
		expect(refreshTokenMock).toHaveBeenCalledWith("old-refresh");
		expect(account?.refreshToken).toBe("new-refresh");

		const stored = JSON.parse(
			fs.readFileSync(process.env.MULTICODEX_STORAGE_FILE || "", "utf-8"),
		) as { accounts: Account[] };
		expect(stored.accounts[0]?.refreshToken).toBe("new-refresh");
		expect(stored.accounts[0]?.expiresAt).toBe(expires);
	});

	it("waits for a cross-manager refresh and reuses the saved rotated token", async () => {
		const managerA = new AccountManager();
		managerA.addOrUpdateAccount("a@example.com", {
			access: "old-access",
			refresh: "old-refresh",
			expires: 0,
			accountId: "acct-old",
		});
		const managerB = new AccountManager();
		const accountA = managerA.getAccount("a@example.com");
		const accountB = managerB.getAccount("a@example.com");
		expect(accountA).toBeDefined();
		expect(accountB).toBeDefined();

		let resolveRefresh: (value: RefreshTokenResult) => void = () => {};
		let markStarted: () => void = () => {};
		const refreshResult = new Promise<RefreshTokenResult>((resolve) => {
			resolveRefresh = resolve;
		});
		const refreshStarted = new Promise<void>((resolve) => {
			markStarted = resolve;
		});
		refreshTokenMock.mockImplementation(async () => {
			markStarted();
			return refreshResult;
		});

		const first = managerA.ensureValidToken(accountA as Account);
		await refreshStarted;
		const second = managerB.ensureValidToken(accountB as Account);

		resolveRefresh({
			access: "new-access",
			refresh: "new-refresh",
			expires: Date.now() + 60 * 60 * 1000,
			accountId: "acct-new",
		});

		await expect(Promise.all([first, second])).resolves.toEqual([
			"new-access",
			"new-access",
		]);
		expect(refreshTokenMock).toHaveBeenCalledTimes(1);
		expect(accountB?.refreshToken).toBe("new-refresh");
	});
});

describe("usage helpers", () => {
	it("parses usage response windows", () => {
		const response = parseCodexUsageResponse({
			rate_limit: {
				primary_window: {
					reset_at: 1700000000,
					used_percent: 12.5,
				},
				secondary_window: {
					reset_at: 1700003600,
					used_percent: 0,
				},
			},
		});

		expect(response.primary?.usedPercent).toBe(12.5);
		expect(response.primary?.resetAt).toBe(1700000000 * 1000);
		expect(response.secondary?.usedPercent).toBe(0);
		expect(response.secondary?.resetAt).toBe(1700003600 * 1000);
	});

	it("detects untouched usage", () => {
		expect(
			isUsageUntouched({
				primary: { usedPercent: 0, resetAt: 1 },
				secondary: { usedPercent: 0, resetAt: 2 },
				fetchedAt: 0,
			}),
		).toBe(true);
		expect(
			isUsageUntouched({
				primary: { usedPercent: 0, resetAt: 1 },
				secondary: { usedPercent: 5, resetAt: 2 },
				fetchedAt: 0,
			}),
		).toBe(false);
	});

	it("picks earliest reset from usage", () => {
		expect(
			getNextResetAt({
				primary: { resetAt: 2000 },
				secondary: { resetAt: 1000 },
				fetchedAt: 0,
			}),
		).toBe(1000);
	});

	it("picks weekly reset from usage", () => {
		expect(
			getWeeklyResetAt({
				primary: { resetAt: 2000 },
				secondary: { resetAt: 1000 },
				fetchedAt: 0,
			}),
		).toBe(1000);
	});
});

describe("pickBestAccount", () => {
	it("prefers untouched accounts when available", () => {
		const accounts = [makeAccount("a"), makeAccount("b")];
		const usage = new Map([
			[
				"a",
				{
					primary: { usedPercent: 10, resetAt: 5000 },
					secondary: { usedPercent: 10, resetAt: 6000 },
					fetchedAt: 0,
				},
			],
			[
				"b",
				{
					primary: { usedPercent: 0, resetAt: 4000 },
					secondary: { usedPercent: 0, resetAt: 7000 },
					fetchedAt: 0,
				},
			],
		]);

		const selected = pickBestAccount(accounts, usage, { now: 0 });
		expect(selected?.email).toBe("b");
	});

	it("prefers earliest weekly reset when all accounts touched", () => {
		const accounts = [makeAccount("a"), makeAccount("b")];
		const usage = new Map([
			[
				"a",
				{
					primary: { usedPercent: 10, resetAt: 5000 },
					secondary: { usedPercent: 10, resetAt: 8000 },
					fetchedAt: 0,
				},
			],
			[
				"b",
				{
					primary: { usedPercent: 20, resetAt: 3000 },
					secondary: { usedPercent: 20, resetAt: 9000 },
					fetchedAt: 0,
				},
			],
		]);

		const selected = pickBestAccount(accounts, usage, { now: 0 });
		expect(selected?.email).toBe("a");
	});

	it("ignores 5h reset and prefers earliest weekly reset", () => {
		const accounts = [makeAccount("sh01"), makeAccount("hind")];
		const usage = new Map([
			[
				"sh01",
				{
					primary: { usedPercent: 0, resetAt: 60 * 60 * 1000 },
					secondary: { usedPercent: 9, resetAt: 5 * 24 * 60 * 60 * 1000 },
					fetchedAt: 0,
				},
			],
			[
				"hind",
				{
					primary: { usedPercent: 24, resetAt: 55 * 60 * 1000 },
					secondary: { usedPercent: 13, resetAt: 6 * 24 * 60 * 60 * 1000 },
					fetchedAt: 0,
				},
			],
		]);

		const selected = pickBestAccount(accounts, usage, { now: 0 });
		expect(selected?.email).toBe("sh01");
	});

	it("falls back to available account when usage is unknown", () => {
		const accounts = [makeAccount("a"), makeAccount("b")];
		const selected = pickBestAccount(accounts, new Map(), { now: 0 });
		expect(["a", "b"]).toContain(selected?.email);
	});

	it("ignores exhausted accounts", () => {
		const accounts = [
			makeAccount("a", { quotaExhaustedUntil: 2000 }),
			makeAccount("b"),
		];
		const usage = new Map([
			[
				"a",
				{
					primary: { usedPercent: 0, resetAt: 1000 },
					secondary: { usedPercent: 0, resetAt: 1000 },
					fetchedAt: 0,
				},
			],
		]);

		const selected = pickBestAccount(accounts, usage, { now: 1000 });
		expect(selected?.email).toBe("b");
	});
});

describe("manual account selection", () => {
	it("prefers the manual account in stream wrapper", async () => {
		const manual = makeAccount("manual@example.com");
		let activateCalled = false;
		let headerEmail: string | undefined;

		const accountManager = {
			getAvailableManualAccount: () => manual,
			hasManualAccount: () => true,
			clearManualAccount: () => {},
			activateBestAccount: async () => {
				activateCalled = true;
				return undefined;
			},
			ensureValidToken: async () => "manual-token",
			handleQuotaExceeded: async () => {},
		} as unknown as AccountManager;

		const baseProvider = {
			streamSimple: (
				model: { headers?: Record<string, string> },
				_context: unknown,
				_options?: unknown,
			) => {
				headerEmail = model.headers?.["X-Multicodex-Account"];
				async function* inner() {
					yield { type: "done" };
				}
				return inner() as unknown as AsyncIterable<unknown>;
			},
		};

		const stream = createStreamWrapper(
			accountManager,
			baseProvider as unknown as BaseProvider,
		)(
			{
				id: "test",
				provider: "multicodex",
				api: "openai-codex-responses",
			} as StreamModel,
			{} as StreamContext,
		);

		for await (const _event of stream) {
			// drain
		}

		expect(activateCalled).toBe(false);
		expect(headerEmail).toBe("manual@example.com");
	});

	it("falls back to auto selection when manual is unavailable", async () => {
		const auto = makeAccount("auto@example.com");
		let cleared = false;
		let headerEmail: string | undefined;

		const accountManager = {
			getAvailableManualAccount: () => undefined,
			hasManualAccount: () => true,
			clearManualAccount: () => {
				cleared = true;
			},
			activateBestAccount: async () => auto,
			ensureValidToken: async () => "auto-token",
			handleQuotaExceeded: async () => {},
		} as unknown as AccountManager;

		const baseProvider = {
			streamSimple: (
				model: { headers?: Record<string, string> },
				_context: unknown,
				_options?: unknown,
			) => {
				headerEmail = model.headers?.["X-Multicodex-Account"];
				async function* inner() {
					yield { type: "done" };
				}
				return inner() as unknown as AsyncIterable<unknown>;
			},
		};

		const stream = createStreamWrapper(
			accountManager,
			baseProvider as unknown as BaseProvider,
		)(
			{
				id: "test",
				provider: "multicodex",
				api: "openai-codex-responses",
			} as StreamModel,
			{} as StreamContext,
		);

		for await (const _event of stream) {
			// drain
		}

		expect(cleared).toBe(true);
		expect(headerEmail).toBe("auto@example.com");
	});

	it("clears manual on quota and retries with auto account", async () => {
		const manual = makeAccount("manual@example.com");
		const auto = makeAccount("auto@example.com");
		let cleared = false;
		let activateCount = 0;
		const headers: string[] = [];
		let streamCalls = 0;

		const accountManager = {
			getAvailableManualAccount: () => (cleared ? undefined : manual),
			hasManualAccount: () => !cleared,
			clearManualAccount: () => {
				cleared = true;
			},
			activateBestAccount: async () => {
				activateCount += 1;
				return auto;
			},
			ensureValidToken: async (account: Account) => `${account.email}-token`,
			handleQuotaExceeded: async () => {},
		} as unknown as AccountManager;

		const baseProvider = {
			streamSimple: (
				model: { headers?: Record<string, string> },
				_context: unknown,
				_options?: unknown,
			) => {
				headers.push(model.headers?.["X-Multicodex-Account"] || "");
				streamCalls += 1;
				async function* inner() {
					if (streamCalls === 1) {
						yield { type: "error", error: { errorMessage: "quota exceeded" } };
						return;
					}
					yield { type: "done" };
				}
				return inner() as unknown as AsyncIterable<unknown>;
			},
		};

		const stream = createStreamWrapper(
			accountManager,
			baseProvider as unknown as BaseProvider,
		)(
			{
				id: "test",
				provider: "multicodex",
				api: "openai-codex-responses",
			} as StreamModel,
			{} as StreamContext,
		);

		for await (const _event of stream) {
			// drain
		}

		expect(cleared).toBe(true);
		expect(headers[0]).toBe("manual@example.com");
		expect(headers[1]).toBe("auto@example.com");
		expect(activateCount).toBe(1);
	});
});
