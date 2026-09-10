/**
 * WARNING: This file should ONLY be accessed through OnStageProvider.
 * Do not import or use functions from this file directly in other parts of the application.
 * Use ContentProviderRegistry or OnStageProvider instead.
 */

import { createHash, randomFillSync } from "crypto"
import express from "express"
import http from "http"

import { ToMain } from "../../../types/IPC/ToMain"
import { getContentProviderAccess, setContentProviderAccess } from "../../data/contentProviders"
import { sendToMain } from "../../IPC/main"
import { openURL } from "../../IPC/responsesMain"
import { getKey } from "../../utils/keys"
import { httpsRequest } from "../../utils/requests"
import { onStageLoadServices } from "./request"

// OnStage stores the token pair under one logical scope key; the OAuth request itself asks for the
// granular read scopes below.
export type OnStageScopes = "presenter"
export const ONSTAGE_OAUTH_SCOPES = "events:read songs:read"

export type OnStageAuthData = {
    access_token: string
    refresh_token: string
    token_type: "Bearer"
    created_at: number
    expires_in: number
    scope: OnStageScopes
} | null

export const ONSTAGE_API_URL = process.env.ONSTAGE_API_URL || "https://on-stage.app/api"

// ONSTAGE_API_URL may be plain http with a custom port during local development; production is
// always https. httpsRequest only speaks https on port 443, so all OnStage calls go through here.
export function onStageApiRequest(path: string, method: "POST" | "GET", headers: object, content: object, callback: (err: Error | null, result?: any) => void) {
    const url = new URL(ONSTAGE_API_URL)
    const fullPath = url.pathname.replace(/\/$/, "") + path

    if (!ONSTAGE_API_URL.startsWith("http://")) {
        httpsRequest(url.hostname, fullPath, method, headers, content, callback)
        return
    }

    const dataString = Object.keys(content).length ? JSON.stringify(content) : ""
    const request = http.request(
        {
            hostname: url.hostname,
            port: url.port || 80,
            path: fullPath,
            method,
            headers: {
                ...(dataString.length ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(dataString) } : {}),
                ...headers
            }
        },
        (response) => {
            let data = ""
            response.on("data", (chunk) => (data += chunk))
            response.on("end", () => {
                if ((response.statusCode || 0) >= 400) return callback(new Error(`HTTP ${response.statusCode}: ${data}`))
                try {
                    callback(null, data ? JSON.parse(data) : null)
                } catch (err: any) {
                    callback(err)
                }
            })
        }
    )
    request.on("error", (err) => callback(err))
    if (dataString) request.write(dataString)
    request.end()
}

const ONSTAGE_PORT = 5503
const clientId = getKey("onstage_id")
const HTML_success = `
    <head>
        <title>Success!</title>
    </head>
    <body style="padding: 80px;background: #242832;color: #f0f0ff;font-family: system-ui;font-size: 1.2em;">
        <h1 style="color: #f0008c;">Success!</h1>
        <p>You can close this page</p>
    </body>
`
const HTML_error = `
    <head>
        <title>Error!</title>
    </head>
    <body style="padding: 80px;background: #242832;color: #f0f0ff;font-family: system-ui;font-size: 1.2em;">
        <h1>Could not complete authentication!</h1>
        <p>{error_msg}</p>
    </body>
`

let ONSTAGE_ACCESS: OnStageAuthData = null
// Startup auto-sync and a manual connect click can request authorization at the same moment; two
// flows would each open a browser tab with its own PKCE verifier, and completing one tab exchanges
// its code against the other flow's verifier. All callers share one in-flight authorization.
let pendingAuthentication: Promise<OnStageAuthData> | null = null
let pendingAuthUrl = ""
// An abandoned browser flow (tab closed before consent) never hits the callback, so the pending
// promise would otherwise stay in-flight forever and every later connect click would be a no-op.
const AUTH_FLOW_TIMEOUT_MS = 10 * 60 * 1000

function onStageAuthenticate(scope: OnStageScopes): Promise<OnStageAuthData> {
    if (pendingAuthentication) {
        // re-open the same flow (same PKCE verifier) so a closed tab can be recovered by clicking connect again
        if (pendingAuthUrl) openURL(pendingAuthUrl)
        return pendingAuthentication
    }
    pendingAuthentication = startAuthentication(scope)
    pendingAuthentication.finally(() => {
        pendingAuthentication = null
        pendingAuthUrl = ""
    })
    return pendingAuthentication
}

function startAuthentication(scope: OnStageScopes): Promise<OnStageAuthData> {
    const path = "/auth/complete"
    const redirect_uri = `http://localhost:${ONSTAGE_PORT}${path}`

    const codeVerifier = generateCodeVerifier()
    const codeChallenge = generateCodeChallenge(codeVerifier)

    const app = express()
    app.use(express.json())

    return new Promise((resolve) => {
        let settled = false
        const finish = (result: OnStageAuthData) => {
            if (settled) return
            settled = true
            clearTimeout(abandonTimer)
            server.close()
            resolve(result)
        }

        const abandonTimer = setTimeout(() => finish(null), AUTH_FLOW_TIMEOUT_MS)

        const server = app.listen(ONSTAGE_PORT, () => {
            console.info(`Listening for OnStage OAuth response at port ${ONSTAGE_PORT}`)
        })

        server.once("error", (err: Error) => {
            if ((err as any).code === "EADDRINUSE") finish(null)
        })

        app.get(path, (req, res) => {
            const code = req.query.code?.toString() || ""
            if (!code) {
                return finish(null)
            }

            const params = {
                grant_type: "authorization_code",
                code,
                client_id: clientId,
                redirect_uri,
                code_verifier: codeVerifier
            }

            onStageApiRequest("/oauth/token", "POST", {}, params, (err, data: OnStageAuthData) => {
                if (err) {
                    res.setHeader("Content-Type", "text/html")
                    res.send(HTML_error.replace("{error_msg}", err.message))

                    sendToMain(ToMain.ALERT, "Could not authorize! " + err.message)
                    return finish(null)
                }

                console.info("OnStage OAuth completed!")

                res.setHeader("Content-Type", "text/html")
                res.send(HTML_success)

                const storedData = { ...data, scope } as OnStageAuthData
                setContentProviderAccess("onstage", scope, storedData)
                ONSTAGE_ACCESS = storedData
                connectionInitialized(true)
                finish(storedData)
            })
        })

        const URL = `${ONSTAGE_API_URL}/oauth/authorize?client_id=${clientId}&redirect_uri=${encodeURIComponent(redirect_uri)}&response_type=code&scope=${encodeURIComponent(ONSTAGE_OAUTH_SCOPES)}&code_challenge=${codeChallenge}&code_challenge_method=S256`

        pendingAuthUrl = URL
        openURL(URL)
    })
}

function hasExpired(access: OnStageAuthData): boolean {
    if (!access?.created_at || !access?.expires_in) return true

    const expirationTime = (access.created_at + access.expires_in) * 1000
    return Date.now() >= expirationTime
}

function refreshToken(access: OnStageAuthData): Promise<OnStageAuthData> {
    return new Promise((resolve) => {
        if (!access?.refresh_token) {
            console.warn("No refresh token available, cannot refresh OnStage OAuth token")
            return resolve(null)
        }

        const params = { grant_type: "refresh_token", client_id: clientId, refresh_token: access.refresh_token }

        onStageApiRequest("/oauth/token", "POST", {}, params, (err: any, data: OnStageAuthData) => {
            if (err || data === null) {
                // OnStage revokes the whole grant when a rotated refresh token is replayed, so a
                // failed refresh always means a fresh authorization is needed.
                return resolve(handleRefreshFailure(access.scope))
            }

            const storedData = { ...data, scope: access.scope } as OnStageAuthData
            setContentProviderAccess("onstage", access.scope, storedData)
            return resolve(storedData)
        })
    })
}

async function handleRefreshFailure(scope: OnStageScopes): Promise<OnStageAuthData> {
    try {
        return await onStageAuthenticate(scope)
    } catch (authErr: any) {
        sendToMain(ToMain.ALERT, "Could not refresh token! " + String(authErr?.message))
        return null
    }
}

function generateCodeVerifier() {
    const array = new Uint8Array(32)
    randomFillSync(array)
    return Buffer.from(array).toString("base64url")
}

function generateCodeChallenge(verifier: string) {
    const hash = createHash("sha256").update(verifier).digest()
    return Buffer.from(hash).toString("base64url")
}

export function onStageInitialize() {
    ONSTAGE_ACCESS = null
}

export async function onStageConnect(scope: OnStageScopes): Promise<OnStageAuthData> {
    let accessData = ONSTAGE_ACCESS || getContentProviderAccess("onstage", scope)

    if (hasExpired(accessData)) accessData = await refreshToken(accessData)
    if (!accessData) accessData = await onStageAuthenticate(scope)
    if (!accessData) return null

    if (!ONSTAGE_ACCESS) connectionInitialized()
    ONSTAGE_ACCESS = accessData

    return accessData
}

export function onStageDisconnect(scope: OnStageScopes = "presenter") {
    const access = ONSTAGE_ACCESS || getContentProviderAccess("onstage", scope)
    if (access?.refresh_token) {
        // Revoke the grant server-side so the user does not have to clean up from OnStage settings.
        onStageApiRequest("/oauth/revoke", "POST", {}, { token: access.refresh_token }, () => undefined)
    }
    setContentProviderAccess("onstage", scope, null)
    ONSTAGE_ACCESS = null
    return { success: true }
}

export async function onStageStartupLoad(scope: OnStageScopes = "presenter", providerData?: unknown) {
    if (!getContentProviderAccess("onstage", scope)) return
    await onStageLoadServices(providerData)
}

function connectionInitialized(isFirstConnection = false): void {
    sendToMain(ToMain.PROVIDER_CONNECT, { providerId: "onstage", success: true, isFirstConnection })
}
