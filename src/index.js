import { DurableObject } from "cloudflare:workers";

const EMBED_MODEL = "@cf/baai/bge-base-en-v1.5";
const LLM_MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
const VISION_MODEL = "@cf/meta/llama-4-scout-17b-16e-instruct";
const SESSION_MAX_AGE_S = 7 * 24 * 60 * 60;
const MAX_TEXT_CHARS = 400000;
const MAX_MESSAGE_CHARS = 4000;
const MAX_IMAGE_CHARS = 6000000;
const MAX_SEARCH_DOCS = 10;
const FULL_CONTEXT_CHARS = 24000;
const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const ID_RE = /^[a-zA-Z0-9-]{1,64}$/;
const REFUSAL_RE =
  /(no|not any) (document|passage|information)|nothing to (summari[sz]e|tell)|not provided|no passages|passages (provided )?(are|is) empty|there is no document|no relevant/i;

const SYSTEM_PROMPT =
  "You are a document assistant. The user's documents are given inside <documents> tags in the user's latest message, " +
  "each labeled [1], [2], etc. with its file name. Answer using ONLY those documents and cite the ones you use as [1], [2]. " +
  "When asked what a document is about, or to summarize it, write a clear, well-organized overview of its actual content. " +
  "Earlier replies in this conversation that claimed there was no document, no passage, or nothing to summarize were errors; ignore them. " +
  "If the documents truly do not contain the answer to a specific question, say so plainly. " +
  "For greetings, thanks, or small talk, reply briefly and naturally.";

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function bytesToB64u(buf) {
  const arr = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function b64uToBytes(str) {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", encoder.encode(text));
  return [...new Uint8Array(digest)]
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
}

async function hmac(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  return bytesToB64u(sig);
}

async function hashPassword(password, salt) {
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" },
    key,
    256
  );
  return bytesToB64u(bits);
}

function getSecret(env) {
  return env.SESSION_SECRET || env.ACCESS_CODE;
}

async function makeSessionToken(uid, secret) {
  const payload = bytesToB64u(
    encoder.encode(JSON.stringify({ uid, iat: Date.now() }))
  );
  const signature = await hmac(secret, payload);
  return `${payload}.${signature}`;
}

async function verifySessionToken(token, secret) {
  if (!token || !secret) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payload, signature] = parts;
  const expected = await hmac(secret, payload);
  if (!safeEqual(signature, expected)) return null;
  try {
    const { uid, iat } = JSON.parse(decoder.decode(b64uToBytes(payload)));
    if (typeof uid !== "string" || typeof iat !== "number") return null;
    if (Date.now() - iat > SESSION_MAX_AGE_S * 1000) return null;
    return uid;
  } catch {
    return null;
  }
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? match[1] : null;
}

function sessionCookie(token, maxAge) {
  return `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

async function getUid(request, env) {
  return verifySessionToken(getCookie(request, "session"), getSecret(env));
}

function json(data, status = 200, headers = {}) {
  return Response.json(data, { status, headers });
}

function normalizeEmail(value) {
  return String(value || "").trim().toLowerCase();
}

function userStub(env, uid) {
  return env.USERS.get(env.USERS.idFromName(uid));
}

function chatStub(env, uid, chatId) {
  return env.ChatAgent.get(env.ChatAgent.idFromName(`${uid}:${chatId}`));
}

export class UserStore extends DurableObject {
  async createUser(user) {
    const existing = await this.ctx.storage.get("user");
    if (existing) return false;
    await this.ctx.storage.put("user", user);
    return true;
  }

  async getUser() {
    return (await this.ctx.storage.get("user")) || null;
  }

  async listChats() {
    const chats = (await this.ctx.storage.get("chats")) || [];
    return chats.sort((a, b) => b.updatedAt - a.updatedAt);
  }

  async createChat(chat) {
    const chats = (await this.ctx.storage.get("chats")) || [];
    chats.push(chat);
    await this.ctx.storage.put("chats", chats);
  }

  async hasChat(id) {
    const chats = (await this.ctx.storage.get("chats")) || [];
    return chats.some((c) => c.id === id);
  }

  async updateChat(id, patch) {
    const chats = (await this.ctx.storage.get("chats")) || [];
    let updated = null;
    const next = chats.map((c) => {
      if (c.id !== id) return c;
      updated = { ...c, ...patch };
      return updated;
    });
    await this.ctx.storage.put("chats", next);
    return updated;
  }

  async deleteChat(id) {
    const chats = (await this.ctx.storage.get("chats")) || [];
    await this.ctx.storage.put(
      "chats",
      chats.filter((c) => c.id !== id)
    );
  }

  async listDocs() {
    const docs = (await this.ctx.storage.get("docs")) || [];
    return docs.sort((a, b) => b.createdAt - a.createdAt);
  }

  async addDoc(meta, text) {
    const docs = (await this.ctx.storage.get("docs")) || [];
    docs.push(meta);
    await this.ctx.storage.put("docs", docs);
    await this.ctx.storage.put(`doctext:${meta.id}`, text);
  }

  async getDoc(id) {
    const docs = (await this.ctx.storage.get("docs")) || [];
    const meta = docs.find((d) => d.id === id);
    if (!meta) return null;
    const text = (await this.ctx.storage.get(`doctext:${id}`)) || "";
    return { ...meta, text };
  }

  async getDocsByIds(ids) {
    const docs = (await this.ctx.storage.get("docs")) || [];
    const out = [];
    for (const id of ids) {
      const meta = docs.find((d) => d.id === id);
      if (!meta) continue;
      const text = (await this.ctx.storage.get(`doctext:${id}`)) || "";
      out.push({ ...meta, text });
    }
    return out;
  }

  async deleteDoc(id) {
    const docs = (await this.ctx.storage.get("docs")) || [];
    const meta = docs.find((d) => d.id === id);
    if (!meta) return null;
    await this.ctx.storage.put(
      "docs",
      docs.filter((d) => d.id !== id)
    );
    await this.ctx.storage.delete(`doctext:${id}`);
    return meta;
  }
}

export class ChatAgent extends DurableObject {
  async getMessages() {
    return (await this.ctx.storage.get("messages")) || [];
  }

  async addExchange(userContent, assistantContent) {
    const messages = await this.getMessages();
    const updated = [
      ...messages,
      { role: "user", content: userContent },
      { role: "assistant", content: assistantContent },
    ].slice(-100);
    await this.ctx.storage.put("messages", updated);
  }

  async clear() {
    await this.ctx.storage.deleteAll();
  }
}

function chunkText(text, chunkSize = 1000, overlap = 150) {
  const chunks = [];
  let start = 0;
  while (start < text.length) {
    const end = Math.min(start + chunkSize, text.length);
    const chunk = text.slice(start, end);
    if (chunk.trim()) chunks.push(chunk);
    if (end >= text.length) break;
    start = end - overlap;
  }
  return chunks;
}

function cleanHistory(messages) {
  const out = [];
  for (let i = 0; i + 1 < messages.length; i += 2) {
    const user = messages[i];
    const assistant = messages[i + 1];
    if (!user || !assistant) continue;
    if (assistant.content.length < 400 && REFUSAL_RE.test(assistant.content)) {
      continue;
    }
    out.push(
      { role: "user", content: user.content.slice(0, 1500) },
      { role: "assistant", content: assistant.content.slice(0, 1500) }
    );
  }
  return out.slice(-6);
}

function searchQuery(message, history) {
  if (message.length > 80 || history.length === 0) return message;
  const lastUser = [...history].reverse().find((m) => m.role === "user");
  return lastUser ? `${lastUser.content.slice(0, 300)}\n${message}` : message;
}

async function retrieve(env, docIds, query) {
  if (!docIds.length) return [];
  const embedded = await env.AI.run(EMBED_MODEL, { text: [query] });
  const vector = embedded?.data?.[0];
  if (!vector) return [];

  const results = await Promise.all(
    docIds.map((id) =>
      env.VECTORIZE.query(vector, {
        topK: 4,
        namespace: id,
        returnMetadata: "all",
      }).catch((err) => {
        console.error("Vector query error:", err);
        return { matches: [] };
      })
    )
  );

  const all = results
    .flatMap((r) => r?.matches || [])
    .sort((a, b) => b.score - a.score);
  const strong = all.filter((m) => m.score > 0.3).slice(0, 6);
  return strong.length ? strong : all.slice(0, 3);
}

async function gatherPassages(env, docs, query) {
  const usable = docs.filter((d) => d.text && d.text.trim());
  if (!usable.length) return [];

  const total = usable.reduce((n, d) => n + d.text.length, 0);
  if (total <= FULL_CONTEXT_CHARS) {
    return usable.map((d) => ({ filename: d.filename, text: d.text }));
  }

  let matches = [];
  try {
    matches = await retrieve(
      env,
      usable.map((d) => d.id),
      query
    );
  } catch (err) {
    console.error("Vector search error:", err);
  }

  if (matches.length) {
    return matches.map((m) => ({
      filename: m.metadata?.filename ?? "document",
      text: m.metadata?.text ?? "",
    }));
  }

  const per = Math.floor(FULL_CONTEXT_CHARS / usable.length);
  return usable.map((d) => ({
    filename: d.filename,
    text: d.text.slice(0, per),
  }));
}

function buildUserTurn(passages, message) {
  const docs = passages
    .map((p, i) => `[${i + 1}] (${p.filename})\n${p.text}`)
    .join("\n\n");
  return `<documents>\n${docs}\n</documents>\n\nQuestion: ${message}`;
}

function makeTitle(message) {
  const clean = message.replace(/\s+/g, " ").trim();
  return clean.length > 48 ? clean.slice(0, 48) + "..." : clean;
}

async function signup(request, env) {
  const secret = getSecret(env);
  if (!secret) return json({ error: "Server is missing SESSION_SECRET." }, 500);

  const body = await request.json().catch(() => null);
  const email = normalizeEmail(body?.email);
  const password = String(body?.password || "");
  const name = String(body?.name || "").trim().slice(0, 60);

  if (!EMAIL_RE.test(email) || email.length > 200) {
    return json({ error: "Enter a valid email address." }, 400);
  }
  if (password.length < 8 || password.length > 200) {
    return json({ error: "Password must be 8 to 200 characters." }, 400);
  }

  const uid = (await sha256Hex(email)).slice(0, 32);
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const hash = await hashPassword(password, salt);
  const user = {
    email,
    name: name || email.split("@")[0],
    salt: bytesToB64u(salt),
    hash,
    createdAt: Date.now(),
  };

  const created = await userStub(env, uid).createUser(user);
  if (!created) {
    return json({ error: "An account with this email already exists." }, 409);
  }

  const token = await makeSessionToken(uid, secret);
  return json(
    { authenticated: true, user: { email: user.email, name: user.name } },
    200,
    { "Set-Cookie": sessionCookie(token, SESSION_MAX_AGE_S) }
  );
}

async function login(request, env) {
  const secret = getSecret(env);
  if (!secret) return json({ error: "Server is missing SESSION_SECRET." }, 500);

  const body = await request.json().catch(() => null);
  const email = normalizeEmail(body?.email);
  const password = String(body?.password || "");
  const invalid = () => json({ error: "Invalid email or password." }, 401);

  if (!EMAIL_RE.test(email) || !password || password.length > 200) {
    return invalid();
  }

  const uid = (await sha256Hex(email)).slice(0, 32);
  const user = await userStub(env, uid).getUser();
  if (!user) return invalid();

  const hash = await hashPassword(password, b64uToBytes(user.salt));
  if (!safeEqual(hash, user.hash)) return invalid();

  const token = await makeSessionToken(uid, secret);
  return json(
    { authenticated: true, user: { email: user.email, name: user.name } },
    200,
    { "Set-Cookie": sessionCookie(token, SESSION_MAX_AGE_S) }
  );
}

async function session(request, env) {
  const uid = await getUid(request, env);
  if (!uid) return json({ authenticated: false });
  const user = await userStub(env, uid).getUser();
  if (!user) return json({ authenticated: false });
  return json({
    authenticated: true,
    user: { email: user.email, name: user.name },
  });
}

async function ocrImage(request, env) {
  const body = await request.json().catch(() => null);
  const image = String(body?.image || "");
  if (!image.startsWith("data:image/") || image.length > MAX_IMAGE_CHARS) {
    return json({ error: "Invalid or oversized image." }, 400);
  }

  const result = await env.AI.run(VISION_MODEL, {
    messages: [
      {
        role: "user",
        content: [
          {
            type: "text",
            text:
              "This image is one slide or page of a document. Transcribe all visible text exactly, keeping headings and bullet points in reading order. " +
              "Then add one short line starting with 'Visual:' describing any chart, diagram, screenshot or image that carries meaning. " +
              "Output plain text only, with no commentary.",
          },
          { type: "image_url", image_url: { url: image } },
        ],
      },
    ],
    max_tokens: 1024,
  });

  const text = (typeof result === "string" ? result : result?.response) || "";
  return json({ text: text.trim() });
}

async function sendMessage(request, env, uid, chatId) {
  const body = await request.json().catch(() => null);
  const message = String(body?.message || "")
    .trim()
    .slice(0, MAX_MESSAGE_CHARS);
  if (!message) return json({ error: "Message is required." }, 400);

  const requested = Array.isArray(body?.docIds)
    ? body.docIds.filter((id) => typeof id === "string" && ID_RE.test(id))
    : [];
  const docIds = [...new Set(requested)].slice(0, MAX_SEARCH_DOCS);
  const docs = docIds.length
    ? await userStub(env, uid).getDocsByIds(docIds)
    : [];

  if (!docs.length) {
    return json({
      reply:
        "No document is selected for this chat. Tick one or more documents in the sidebar (or index a new one), then ask again.",
      sources: [],
      used: { documents: 0, chars: 0 },
      chat: null,
    });
  }

  const chat = chatStub(env, uid, chatId);
  const stored = await chat.getMessages();
  const history = cleanHistory(stored);

  const passages = await gatherPassages(
    env,
    docs,
    searchQuery(message, history)
  );

  if (!passages.length) {
    return json({
      reply:
        "The selected documents have no readable text. Delete them and index them again.",
      sources: [],
      used: { documents: docs.length, chars: 0 },
      chat: null,
    });
  }

  const chars = passages.reduce((n, p) => n + p.text.length, 0);

  const aiResult = await env.AI.run(LLM_MODEL, {
    messages: [
      { role: "system", content: SYSTEM_PROMPT },
      ...history,
      { role: "user", content: buildUserTurn(passages, message) },
    ],
    max_tokens: 1024,
  });

  const reply =
    (typeof aiResult === "string" ? aiResult : aiResult?.response) ||
    "Sorry, I couldn't generate a response.";

  await chat.addExchange(message, reply);

  const patch = { updatedAt: Date.now() };
  if (stored.length === 0) patch.title = makeTitle(message);
  const updatedChat = await userStub(env, uid).updateChat(chatId, patch);

  const sources = [...new Set(passages.map((p) => p.filename).filter(Boolean))];

  return json({
    reply,
    sources,
    used: { documents: docs.length, chars },
    chat: updatedChat,
  });
}

async function uploadDocument(request, env, uid) {
  const body = await request.json().catch(() => null);
  const filename =
    String(body?.filename || "").trim().slice(0, 120) || "pasted-text";
  const text = String(body?.text || "")
    .trim()
    .slice(0, MAX_TEXT_CHARS);

  if (!text) {
    return json({ error: "Could not extract text from the document." }, 400);
  }

  const chunks = chunkText(text);
  const docId = crypto.randomUUID();
  const vectors = [];
  const BATCH = 20;

  for (let i = 0; i < chunks.length; i += BATCH) {
    const batch = chunks.slice(i, i + BATCH);
    const embedded = await env.AI.run(EMBED_MODEL, { text: batch });
    if (!embedded?.data || embedded.data.length !== batch.length) {
      return json({ error: "Failed to generate document embeddings." }, 500);
    }
    embedded.data.forEach((values, j) => {
      vectors.push({
        id: `${docId}-${i + j}`,
        namespace: docId,
        values,
        metadata: {
          text: batch[j],
          filename,
          docId,
          chunkIndex: i + j,
        },
      });
    });
  }

  for (let i = 0; i < vectors.length; i += 500) {
    await env.VECTORIZE.upsert(vectors.slice(i, i + 500));
  }

  const meta = {
    id: docId,
    filename,
    chunks: vectors.length,
    chars: text.length,
    createdAt: Date.now(),
  };
  await userStub(env, uid).addDoc(meta, text);

  return json({ success: true, document: meta });
}

async function deleteDocument(env, uid, docId) {
  const meta = await userStub(env, uid).deleteDoc(docId);
  if (!meta) return json({ error: "Document not found." }, 404);

  const ids = Array.from({ length: meta.chunks }, (_, i) => `${docId}-${i}`);
  for (let i = 0; i < ids.length; i += 500) {
    await env.VECTORIZE.deleteByIds(ids.slice(i, i + 500));
  }
  return json({ success: true });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    if (!path.startsWith("/api/")) {
      if (env.ASSETS) return env.ASSETS.fetch(request);
      return new Response("Not Found", { status: 404 });
    }

    try {
      if (path === "/api/signup" && method === "POST") {
        return await signup(request, env);
      }
      if (path === "/api/login" && method === "POST") {
        return await login(request, env);
      }
      if (path === "/api/session" && method === "GET") {
        return await session(request, env);
      }
      if (path === "/api/logout" && method === "POST") {
        return json({ authenticated: false }, 200, {
          "Set-Cookie": sessionCookie("", 0),
        });
      }

      const uid = await getUid(request, env);
      if (!uid) return json({ error: "Unauthorized." }, 401);

      if (path === "/api/ocr" && method === "POST") {
        return await ocrImage(request, env);
      }

      if (path === "/api/chats" || path === "/api/chats/") {
        if (method === "GET") {
          return json({ chats: await userStub(env, uid).listChats() });
        }
        if (method === "POST") {
          const now = Date.now();
          const chat = {
            id: crypto.randomUUID(),
            title: "New chat",
            createdAt: now,
            updatedAt: now,
          };
          await userStub(env, uid).createChat(chat);
          return json({ chat });
        }
        return json({ error: "Method not allowed." }, 405);
      }

      const chatMatch = path.match(/^\/api\/chats\/([^/]+)(?:\/(messages))?\/?$/);
      if (chatMatch) {
        const chatId = decodeURIComponent(chatMatch[1]);
        const isMessages = Boolean(chatMatch[2]);

        if (!ID_RE.test(chatId)) {
          return json({ error: "Invalid chat id." }, 400);
        }
        if (!(await userStub(env, uid).hasChat(chatId))) {
          return json({ error: "Chat not found." }, 404);
        }

        if (isMessages && method === "GET") {
          return json({ messages: await chatStub(env, uid, chatId).getMessages() });
        }
        if (isMessages && method === "POST") {
          return await sendMessage(request, env, uid, chatId);
        }
        if (!isMessages && method === "DELETE") {
          await chatStub(env, uid, chatId).clear();
          await userStub(env, uid).deleteChat(chatId);
          return json({ success: true });
        }
        return json({ error: "Method not allowed." }, 405);
      }

      const docMatch = path.match(/^\/api\/documents(?:\/([^/]+))?\/?$/);
      if (docMatch) {
        const docId = docMatch[1] ? decodeURIComponent(docMatch[1]) : null;

        if (!docId) {
          if (method === "GET") {
            return json({ documents: await userStub(env, uid).listDocs() });
          }
          if (method === "POST") {
            return await uploadDocument(request, env, uid);
          }
          return json({ error: "Method not allowed." }, 405);
        }

        if (!ID_RE.test(docId)) {
          return json({ error: "Invalid document id." }, 400);
        }
        if (method === "GET") {
          const doc = await userStub(env, uid).getDoc(docId);
          if (!doc) return json({ error: "Document not found." }, 404);
          return json({ document: doc });
        }
        if (method === "DELETE") {
          return await deleteDocument(env, uid, docId);
        }
        return json({ error: "Method not allowed." }, 405);
      }

      return json({ error: "Not found." }, 404);
    } catch (error) {
      console.error("Request error:", error);
      return json(
        {
          error: "Something went wrong.",
          details: error?.message || String(error),
        },
        500
      );
    }
  },
};
