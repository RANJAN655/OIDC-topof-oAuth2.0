import "dotenv/config";
import crypto from "node:crypto";
import express from "express";
import path from "node:path";
import { eq } from "drizzle-orm";
import JWT from "jsonwebtoken";
import jose from "node-jose";
import {
  generateResetToken,
  generateAccessToken,
  generateRefreshToken,
  verifyAccessToken,
  verifyRefreshToken,
  hashToken,
} from "./utils/jwt.js";

import { db } from "./db/index.js";
import {
  usersTable,
  authCodesTable,
  oauthClients,
  refreshTokensTable,
} from "./db/schema.js";

import { PRIVATE_KEY, PUBLIC_KEY } from "./utils/cert.js";
import type { JWTClaims } from "./utils/user-token.js";

const app = express();
const PORT = process.env.PORT ?? 8000;
const ISSUER = `http://localhost:${PORT}`;

// ================= MIDDLEWARE =================
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// serve static files (register.html, authenticate.html)
app.use(express.static("./public"));

// ================= HELPERS =================
function generateClientId() {
  return crypto.randomBytes(16).toString("hex");
}

function generateClientSecret() {
  return crypto.randomBytes(32).toString("hex");
}

// ================= ROOT =================
app.get("/", (_, res) => {
  res.json({ message: "Auth Server Running" });
});

// ================= DISCOVERY =================
app.get("/.well-known/openid-configuration", (_, res) => {
  res.json({
    issuer: ISSUER,
    authorization_endpoint: `${ISSUER}/o/authorize`,
    token_endpoint: `${ISSUER}/o/token`,
    userinfo_endpoint: `${ISSUER}/o/userinfo`,
    jwks_uri: `${ISSUER}/.well-known/jwks.json`,
    registration_endpoint: `${ISSUER}/register/website`,
    response_types_supported: ["code"],
    id_token_signing_alg_values_supported: ["RS256"],
  });
});

// ================= JWKS =================
app.get("/.well-known/jwks.json", async (_, res) => {
  const key = await jose.JWK.asKey(
    PUBLIC_KEY,
    "pem",
  ); /* PEM (string) → JWK (JavaScript object) */
  res.json({
    keys: [key.toJSON()],
  }); /* Converts the key object into plain JSON format */
}); /* JS object → JSON string + header + send                JWK object → plain JS object */

// ================= AUTHORIZE =================
app.get("/o/authorize", (req, res) => {
  const { client_id, redirect_uri, state } = req.query;

  // Type-safe validation (fixes TS error)
  if (typeof client_id !== "string" || typeof redirect_uri !== "string") {
    return res.status(400).send("Invalid request");
  }

  const params = new URLSearchParams({
    client_id,
    redirect_uri,
    ...(typeof state === "string" && { state }),
  });

  res.redirect(
    `/o/authenticate?${params.toString()}`,
  ); /* It is used to convert URL parameters → query string */
});

// ================= AUTH UI =================
app.get("/o/authenticate", (_, res) => {
  res.sendFile(path.resolve("public", "authenticate.html"));
});

// ================= REGISTER UI =================
app.get("/register/website", (_, res) => {
  res.sendFile(path.resolve("public", "register.html"));
});

// ================= REGISTER API =================
app.post("/register/website", async (req, res) => {
  try {
    const { name, website_url, redirect_uri } = req.body;

    if (!name || !website_url || !redirect_uri) {
      return res.status(400).json({ error: "invalid_request" });
    }

    // validate redirect URL
    try {
      const url = new URL(redirect_uri);
      if (!["http:", "https:"].includes(url.protocol)) {
        throw new Error();
      }
    } catch {
      return res.status(400).json({ error: "invalid_redirect_uri" });
    }

    const clientId = generateClientId();
    const clientSecret = generateClientSecret();

    await db.insert(oauthClients).values({
      id: crypto.randomUUID(),
      name,
      websiteUrl: website_url,
      redirectUrl: redirect_uri,
      clientId,
      clientSecret,
    });

    return res.status(201).json({
      client_id: clientId,
      client_secret: clientSecret,
    });
  } catch (err) {
    console.error("REGISTER ERROR:", err);
    return res.status(500).json({ error: "server_error" });
  }
});

// ================= SIGN UP =================
app.post("/o/authenticate/sign-up", async (req, res) => {
  const { email, password, firstName, lastName } = req.body;

  if (!email || !password) {
    return res.status(400).json({ error: "missing_fields" });
  }

  const [existing] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.email, email))
    .limit(1);

  if (existing) {
    return res.status(409).json({ error: "user_exists" });
  }

  const salt = crypto.randomBytes(16).toString("hex");
  const hashedPassword = crypto
    .createHash("sha256")
    .update(password + salt)
    .digest("hex");

  const [user] = await db
    .insert(usersTable)
    .values({
      email,
      password: hashedPassword,
      salt,
      firstName,
      lastName,
      emailVerified: false,
    })
    .returning();

  return res.json({ userId: user.id });
});

// ================= SIGN IN =================
// app.post("/o/authenticate/sign-in", async (req, res) => {
//   const { email, password, client_id, redirect_uri, state } = req.body;

//   const [user] = await db
//     .select()
//     .from(usersTable)
//     .where(eq(usersTable.email, email))
//     .limit(1);

//   if (!user) return res.status(401).send("Invalid credentials");

//   const hash = crypto
//     .createHash("sha256")
//     .update(password + user.salt)
//     .digest("hex");

//   if (hash !== user.password) {
//     return res.status(401).send("Invalid credentials");
//   }

//   const code = crypto.randomBytes(32).toString("hex");

//   authCodes.set(code, {
//     userId: user.id,
//     client_id,
//     redirect_uri,
//   });

//   const redirectURL = new URL(redirect_uri);
//   redirectURL.searchParams.set("code", code);
//   if (state) redirectURL.searchParams.set("state", state);

//   res.redirect(redirectURL.toString());
// });

app.post("/o/authenticate/sign-in", async (req, res) => {
  try {
    const { email, password, client_id, redirect_uri, state } = req.body;
    console.log("client_id from request:", client_id);
    const [client] = await db
      .select()
      .from(oauthClients)
      .where(eq(oauthClients.clientId, client_id))
      .limit(1);

    if (!client) {
      return res.status(400).send("invalid client id");
    }

    if (client.redirectUrl !== redirect_uri) {
      return res.status(400).send("invalid redirct_url");
    }

    const [user] = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.email, email))
      .limit(1);

    if (!user) {
      return res.status(400).send("Invalide credentials");
    }

    const hash = crypto
      .createHash("sha256")
      .update(password + user.salt)
      .digest("hex");

    if (hash !== user.password) {
      return res.status(400).send("Invalid password");
    }

    const code = crypto.randomBytes(32).toString("hex");
    const expireAt = new Date(Date.now() + 60 * 1000);

    await db.insert(authCodesTable).values({
      code,
      userId:
        user.id /* Right now you only match type. Add foreign key reference: */,
      clientId: client.clientId,
      redirectUrl: client.redirectUrl,
      expiresAt: expireAt,
      used: false,
    });

    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.set("code", code);
    if (state) {
      redirectUrl.searchParams.set("state", state);
    }
    return res.redirect(redirectUrl.toString());   /* HTTP/1.1 302 Found
                                                   Location: http://localhost:5050/client/callback?code=XYZ */
  } catch (error) {
    console.error(error);
    return res.status(500).send("Internal Server Error");
  }
});

// ================= TOKEN =================


app.post("/o/token", async (req, res) => {
  const { grant_type } = req.body;

  // =========================================
  // 1. AUTHORIZATION CODE FLOW (LOGIN)
  // =========================================
  if (grant_type === "authorization_code") {
    const { code, client_id, client_secret, redirect_uri } = req.body;

    const [record] = await db
      .select()
      .from(authCodesTable)
      .where(eq(authCodesTable.code, code))
      .limit(1);

    if (!record) {
      return res.status(400).json({ error: "invalid_code" });
    }

    if (record.clientId !== client_id) {
      return res.status(400).json({ error: "client_mismatch" });
    }

    const [client] = await db
      .select()
      .from(oauthClients)
      .where(eq(oauthClients.clientId, client_id))
      .limit(1);

    if (!client || client.clientSecret !== client_secret) {
      return res.status(400).json({ error: "invalid_client" });
    }

    if (new Date() > new Date(record.expiresAt)) {
      return res.status(400).json({ error: "code_expired" });
    }

    if (record.used) {
      return res.status(400).json({ error: "code_used" });
    }

    if (client.redirectUrl !== redirect_uri) {
      return res.status(400).json({ error: "invalid_redirect_uri" });
    }

    // mark code used
    await db
      .update(authCodesTable)
      .set({ used: true })
      .where(eq(authCodesTable.code, code));

    const [user] = await db
      .select()
      .from(usersTable)
      .where(eq(usersTable.id, record.userId))
      .limit(1);

    // generate tokens
    const accessToken = generateAccessToken({ id: user.id });
    const refreshToken = generateRefreshToken({ id: user.id });

    // store refresh token
    const hashed = hashToken(refreshToken);

    await db.insert(refreshTokensTable).values({
      userId: user.id,
      clientId: client.clientId,
      tokenHash: hashed,
      expiresAt: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000),
      revoked: false,
    });

    // optional id_token
    const now = Math.floor(Date.now() / 1000);
    const id_token = JWT.sign(
      {
        iss: ISSUER,
        sub: user.id,
        aud: client.clientId,
        exp: now + 3600,
        iat: now,
        email: user.email,
      },
      PRIVATE_KEY,
      { algorithm: "RS256" },
    );

    return res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      id_token,
      token_type: "Bearer",
      expires_in: 86400,
    });
  }

  // =========================================
  // 2. REFRESH TOKEN FLOW
  // =========================================
  if (grant_type === "refresh_token") {
    const { refresh_token } = req.body;

    if (!refresh_token) {
      return res.status(400).json({ error: "missing_refresh_token" });
    }

    // verify JWT
    let payload;
    try {
      payload = verifyRefreshToken(refresh_token);
    } catch {
      return res.status(401).json({ error: "invalid_refresh_token" });
    }

    // check DB
    const hashed = hashToken(refresh_token);

    const [stored] = await db
      .select()
      .from(refreshTokensTable)
      .where(eq(refreshTokensTable.tokenHash, hashed))
      .limit(1);

    if (!stored) return res.status(401).json({ error: "not_found" });
    if (stored.revoked) return res.status(401).json({ error: "revoked" });

    if (new Date() > stored.expiresAt) {
      return res.status(401).json({ error: "refresh_expired" });
    }

    // generate new access token
    const accessToken = generateAccessToken({
      id: stored.userId,
    });

    // SIMPLE VERSION (no rotation)
    return res.json({
      access_token: accessToken,
      refresh_token: refresh_token,
      token_type: "Bearer",
      expires_in: 86400,
    });
  }

  return res.status(400).json({
    error: "unsupported_grant_type",
  });
});

// ================= USERINFO =================


app.get("/o/userinfo", async (req, res) => {
  const auth = req.headers.authorization;

  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "invalid_token" });
  }

  const token = auth.split(" ")[1];

  let payload;
  try {
    payload = verifyAccessToken(token);
  } catch {
    return res.status(401).json({ error: "invalid_token" });
  }

  const [user] = await db
    .select()
    .from(usersTable)
    .where(eq(usersTable.id, payload.id))
    .limit(1);

  if (!user) {
    return res.status(404).json({ error: "user_not_found" });
  }

  return res.json({
    sub: user.id,
    email: user.email,
    name: `${user.firstName ?? ""} ${user.lastName ?? ""}`.trim(),
  });
});

// ================= START =================
app.listen(PORT, () => {
  console.log(`OIDC server running at ${ISSUER}`);
});
