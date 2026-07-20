import * as crypto from "node:crypto";
import * as http from "node:http";
import type { OAuthCredentials, OAuthPrompt } from "@mariozechner/pi-ai/oauth";
import * as piAiOAuth from "@mariozechner/pi-ai/oauth";

const CALLBACK_HOST = process.env.PI_OAUTH_CALLBACK_HOST || "127.0.0.1";
const CLIENT_ID = "app_EMoamEEZ73f0CkXaXp7hrann";
const AUTHORIZE_URL = "https://auth.openai.com/oauth/authorize";
const TOKEN_URL = "https://auth.openai.com/oauth/token";
const REDIRECT_URI = "http://localhost:1455/auth/callback";
const SCOPE = "openid profile email offline_access";
const JWT_CLAIM_PATH = "https://api.openai.com/auth";

export interface OpenAICodexLoginOptions {
	onAuth(info: { url: string; instructions?: string }): void;
	onPrompt(prompt: OAuthPrompt): Promise<string>;
	onProgress?(message: string): void;
	originator?: string;
	signal?: AbortSignal;
}

type LegacyOAuthModule = {
	loginOpenAICodex?: (
		options: OpenAICodexLoginOptions,
	) => Promise<OAuthCredentials>;
	refreshOpenAICodexToken?: (refreshToken: string) => Promise<OAuthCredentials>;
};

type TokenResponse = {
	access_token?: unknown;
	refresh_token?: unknown;
	expires_in?: unknown;
};

type JwtPayload = {
	[JWT_CLAIM_PATH]?: { chatgpt_account_id?: unknown };
};

interface LocalOAuthServer {
	close(): void;
	waitForCode(): Promise<string | undefined>;
}

function getLegacyOAuth(): LegacyOAuthModule {
	return piAiOAuth as LegacyOAuthModule;
}

function throwIfAborted(signal?: AbortSignal): void {
	if (signal?.aborted) throw new Error("Login cancelled");
}

function parseAuthorizationInput(input: string): {
	code?: string;
	state?: string;
} {
	const value = input.trim();
	if (!value) return {};

	try {
		const url = new URL(value);
		return {
			code: url.searchParams.get("code") ?? undefined,
			state: url.searchParams.get("state") ?? undefined,
		};
	} catch {
		// The input may be a code rather than a URL.
	}

	if (value.includes("#")) {
		const [code, state] = value.split("#", 2);
		return { code, state };
	}
	if (value.includes("code=")) {
		const params = new URLSearchParams(value);
		return {
			code: params.get("code") ?? undefined,
			state: params.get("state") ?? undefined,
		};
	}
	return { code: value };
}

function getAccountId(accessToken: string): string | undefined {
	try {
		const parts = accessToken.split(".");
		if (parts.length !== 3 || !parts[1]) return undefined;
		const payload = JSON.parse(
			Buffer.from(parts[1], "base64url").toString("utf8"),
		) as JwtPayload;
		const accountId = payload[JWT_CLAIM_PATH]?.chatgpt_account_id;
		return typeof accountId === "string" && accountId.length > 0
			? accountId
			: undefined;
	} catch {
		return undefined;
	}
}

async function readTokenResponse(
	response: Response,
	operation: "exchange" | "refresh",
): Promise<OAuthCredentials> {
	if (!response.ok) {
		const text = await response.text().catch(() => "");
		throw new Error(
			`OpenAI Codex token ${operation} failed (${response.status}): ${
				text || response.statusText
			}`,
		);
	}

	const json = (await response.json()) as TokenResponse;
	if (
		typeof json.access_token !== "string" ||
		typeof json.refresh_token !== "string" ||
		typeof json.expires_in !== "number"
	) {
		throw new Error(
			`OpenAI Codex token ${operation} response missing required fields`,
		);
	}

	const accountId = getAccountId(json.access_token);
	if (!accountId) {
		throw new Error("Failed to extract accountId from OpenAI Codex token");
	}

	return {
		access: json.access_token,
		refresh: json.refresh_token,
		expires: Date.now() + json.expires_in * 1000,
		accountId,
	};
}

async function requestToken(
	body: URLSearchParams,
	operation: "exchange" | "refresh",
	signal?: AbortSignal,
): Promise<OAuthCredentials> {
	let response: Response;
	try {
		response = await fetch(TOKEN_URL, {
			method: "POST",
			headers: { "Content-Type": "application/x-www-form-urlencoded" },
			body,
			signal,
		});
	} catch (error) {
		if (signal?.aborted) throw new Error("Login cancelled");
		throw new Error(
			`OpenAI Codex token ${operation} error: ${
				error instanceof Error ? error.message : String(error)
			}`,
		);
	}
	return readTokenResponse(response, operation);
}

/**
 * Refresh implementation used when newer pi versions expose only OAuth types
 * from the public /oauth entry point.
 */
export function refreshOpenAICodexTokenFallback(
	refreshToken: string,
): Promise<OAuthCredentials> {
	return requestToken(
		new URLSearchParams({
			grant_type: "refresh_token",
			refresh_token: refreshToken,
			client_id: CLIENT_ID,
		}),
		"refresh",
	);
}

function createAuthorizationFlow(originator = "pi"): {
	verifier: string;
	state: string;
	url: string;
} {
	const verifier = crypto.randomBytes(32).toString("base64url");
	const challenge = crypto
		.createHash("sha256")
		.update(verifier)
		.digest("base64url");
	const state = crypto.randomBytes(16).toString("hex");
	const url = new URL(AUTHORIZE_URL);
	url.searchParams.set("response_type", "code");
	url.searchParams.set("client_id", CLIENT_ID);
	url.searchParams.set("redirect_uri", REDIRECT_URI);
	url.searchParams.set("scope", SCOPE);
	url.searchParams.set("code_challenge", challenge);
	url.searchParams.set("code_challenge_method", "S256");
	url.searchParams.set("state", state);
	url.searchParams.set("id_token_add_organizations", "true");
	url.searchParams.set("codex_cli_simplified_flow", "true");
	url.searchParams.set("originator", originator);
	return { verifier, state, url: url.toString() };
}

function callbackHtml(message: string): string {
	return `<!doctype html><html><body><p>${message}</p></body></html>`;
}

function startLocalOAuthServer(
	state: string,
	signal?: AbortSignal,
): Promise<LocalOAuthServer> {
	let settleWait: ((code: string | undefined) => void) | undefined;
	const waitForCodePromise = new Promise<string | undefined>((resolve) => {
		let settled = false;
		settleWait = (code) => {
			if (settled) return;
			settled = true;
			resolve(code);
		};
	});

	const server = http.createServer((request, response) => {
		try {
			const url = new URL(request.url || "", "http://localhost");
			if (url.pathname !== "/auth/callback") {
				response.writeHead(404, { "Content-Type": "text/html; charset=utf-8" });
				response.end(callbackHtml("Callback route not found."));
				return;
			}
			if (url.searchParams.get("state") !== state) {
				response.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
				response.end(callbackHtml("State mismatch."));
				return;
			}
			const code = url.searchParams.get("code");
			if (!code) {
				response.writeHead(400, { "Content-Type": "text/html; charset=utf-8" });
				response.end(callbackHtml("Missing authorization code."));
				return;
			}
			response.writeHead(200, { "Content-Type": "text/html; charset=utf-8" });
			response.end(
				callbackHtml(
					"OpenAI authentication completed. You can close this window.",
				),
			);
			settleWait?.(code);
		} catch {
			response.writeHead(500, { "Content-Type": "text/html; charset=utf-8" });
			response.end(callbackHtml("Could not process the OAuth callback."));
		}
	});

	return new Promise((resolve) => {
		const abort = () => settleWait?.(undefined);
		signal?.addEventListener("abort", abort, { once: true });
		server
			.listen(1455, CALLBACK_HOST, () => {
				resolve({
					close: () => {
						signal?.removeEventListener("abort", abort);
						server.close();
					},
					waitForCode: () => waitForCodePromise,
				});
			})
			.on("error", () => {
				settleWait?.(undefined);
				resolve({
					close: () => {
						signal?.removeEventListener("abort", abort);
						server.close();
					},
					waitForCode: () => waitForCodePromise,
				});
			});
	});
}

async function loginOpenAICodexFallback(
	options: OpenAICodexLoginOptions,
): Promise<OAuthCredentials> {
	throwIfAborted(options.signal);
	const { verifier, state, url } = createAuthorizationFlow(options.originator);
	const server = await startLocalOAuthServer(state, options.signal);
	options.onAuth({
		url,
		instructions: "A browser window should open. Complete login to finish.",
	});

	try {
		let code = await server.waitForCode();
		throwIfAborted(options.signal);
		if (!code) {
			const input = await options.onPrompt({
				message: "Paste the authorization code (or full redirect URL):",
			});
			const parsed = parseAuthorizationInput(input);
			if (parsed.state && parsed.state !== state) {
				throw new Error("State mismatch");
			}
			code = parsed.code;
		}
		if (!code) throw new Error("Missing authorization code");

		return requestToken(
			new URLSearchParams({
				grant_type: "authorization_code",
				client_id: CLIENT_ID,
				code,
				code_verifier: verifier,
				redirect_uri: REDIRECT_URI,
			}),
			"exchange",
			options.signal,
		);
	} finally {
		server.close();
	}
}

export function loginOpenAICodex(
	options: OpenAICodexLoginOptions,
): Promise<OAuthCredentials> {
	const legacyLogin = getLegacyOAuth().loginOpenAICodex;
	return typeof legacyLogin === "function"
		? legacyLogin(options)
		: loginOpenAICodexFallback(options);
}

export function refreshOpenAICodexToken(
	refreshToken: string,
): Promise<OAuthCredentials> {
	const legacyRefresh = getLegacyOAuth().refreshOpenAICodexToken;
	return typeof legacyRefresh === "function"
		? legacyRefresh(refreshToken)
		: refreshOpenAICodexTokenFallback(refreshToken);
}
