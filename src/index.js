import { Agent, getAgentByName } from "agents";

const EMBED_MODEL = "@cf/baai/bge-base-en-v1.5";
const LLM_MODEL = "@cf/meta/llama-3.3-70b-instruct-fp8-fast";
const SESSION_MAX_AGE_MS = 24 * 60 * 60 * 1000;

/* =========================================================
   AUTH
========================================================= */

function toBase64Url(bytes) {
  let binary = "";
  const arr = new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) binary += String.fromCharCode(arr[i]);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(str) {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/");
  return atob(b64 + "=".repeat((4 - (b64.length % 4)) % 4));
}

async function hmac(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(message)
  );
  return toBase64Url(sig);
}

async function makeSessionToken(secret) {
  const payload = toBase64Url(
    new TextEncoder().encode(JSON.stringify({ iat: Date.now() }))
  );
  const signature = await hmac(secret, payload);
  return `${payload}.${signature}`;
}

async function verifySessionToken(token, secret) {
  if (!token || !secret) return false;
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [payload, signature] = parts;
  if (!payload || !signature) return false;

  const expected = await hmac(secret, payload);
  if (signature !== expected) return false;

  try {
    const { iat } = JSON.parse(fromBase64Url(payload));
    return typeof iat === "number" && Date.now() - iat < SESSION_MAX_AGE_MS;
  } catch {
    return false;
  }
}

function getCookie(request, name) {
  const header = request.headers.get("Cookie") || "";
  const match = header.match(new RegExp(`(?:^|;\\s*)${name}=([^;]+)`));
  return match ? match[1] : null;
}

async function isAuthenticated(request, env) {
  const token = getCookie(request, "session");
  if (!token) return false;
  return verifySessionToken(token, env.ACCESS_CODE);
}

/* =========================================================
   CHAT AGENT (Durable Object) - plain HTTP
   GET  -> { messages }
   POST -> { reply }
========================================================= */

export class ChatAgent extends Agent {
  async onRequest(request) {
    const messages = (await this.ctx.storage.get("messages")) || [];

    if (request.method === "GET") {
      return Response.json({ messages });
    }

    if (request.method === "DELETE") {
      await this.ctx.storage.delete("messages");
      return Response.json({ success: true });
    }

    if (request.method !== "POST") {
      return Response.json({ error: "Method not allowed." }, { status: 405 });
    }

    let body;
    try {
      body = await request.json();
    } catch {
      return Response.json({ error: "Invalid JSON." }, { status: 400 });
    }

    const userMessage = (body?.message || "").trim();
    if (!userMessage) {
      return Response.json({ error: "Message is required." }, { status: 400 });
    }

    try {
      /* ---------- retrieve relevant passages ---------- */
      let context = "";
      try {
        const embedded = await this.env.AI.run(EMBED_MODEL, {
          text: [userMessage],
        });
        const vector = embedded?.data?.[0];

        if (vector) {
          const result = await this.env.VECTORIZE.query(vector, {
            topK: 4,
            returnMetadata: "all",
          });

          const good = (result?.matches || []).filter((m) => m.score > 0.5);

          context = good
            .map(
              (m, i) =>
                `[${i + 1}] (${m.metadata?.filename ?? "document"})\n${
                  m.metadata?.text ?? ""
                }`
            )
            .join("\n\n");
        }
      } catch (err) {
        console.error("Vector search error:", err);
      }

      /* ---------- build prompt ---------- */
      const system =
        "You are a document assistant. Answer using ONLY the passages provided below. " +
        "Cite passages you use as [1], [2], etc. " +
        "If the passages do not contain the answer, say so plainly instead of guessing.\n\n" +
        (context
          ? `PASSAGES:\n${context}`
          : "PASSAGES: (none found - no relevant documents were retrieved)");

      const history = messages
        .slice(-10)
        .map((m) => ({ role: m.role, content: m.content }));

      const aiResult = await this.env.AI.run(LLM_MODEL, {
        messages: [
          { role: "system", content: system },
          ...history,
          { role: "user", content: userMessage },
        ],
        max_tokens: 1024,
      });

      const reply =
        (typeof aiResult === "string" ? aiResult : aiResult?.response) ||
        "Sorry, I couldn't generate a response.";

      /* ---------- persist ---------- */
      const updated = [
        ...messages,
        { role: "user", content: userMessage },
        { role: "assistant", content: reply },
      ].slice(-50);

      await this.ctx.storage.put("messages", updated);

      return Response.json({ reply });
    } catch (error) {
      console.error("Chat error:", error);
      return Response.json(
        {
          error: "Failed to generate a reply.",
          details: error?.message || String(error),
        },
        { status: 500 }
      );
    }
  }
}

/* =========================================================
   HELPERS
========================================================= */

function chunkText(text, chunkSize = 1200, overlap = 200) {
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

async function extractText(request, env) {
  const contentType = request.headers.get("Content-Type") || "";

  /* ----- JSON: { text, filename? } ----- */
  if (contentType.includes("application/json")) {
    const body = await request.json();
    return {
      text: typeof body?.text === "string" ? body.text : "",
      filename: body?.filename || "pasted-text",
    };
  }

  /* ----- multipart: file ----- */
  if (contentType.includes("multipart/form-data")) {
    const formData = await request.formData();
    const file = formData.get("file");

    if (!file || typeof file === "string") {
      return { error: "No file uploaded." };
    }

    const filename = file.name || "document";
    const lower = filename.toLowerCase();

    if (file.type === "application/pdf" || lower.endsWith(".pdf")) {
      const buf = await file.arrayBuffer();
      const results = await env.AI.toMarkdown([
        {
          name: filename,
          blob: new Blob([buf], { type: "application/pdf" }),
        },
      ]);
      const first = Array.isArray(results) ? results[0] : results;
      return { text: first?.data || first?.text || "", filename };
    }

    if (
      (file.type || "").startsWith("text/") ||
      lower.endsWith(".txt") ||
      lower.endsWith(".md")
    ) {
      return { text: await file.text(), filename };
    }

    return { error: "Unsupported file type. Please upload PDF, TXT, or MD." };
  }

  return { error: "Unsupported content type." };
}

/* =========================================================
   WORKER
========================================================= */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    /* ---------------- LOGIN ---------------- */
    if (path === "/api/login" && request.method === "POST") {
      try {
        const body = await request.json();
        const accessCode = body?.accessCode;

        if (!accessCode) {
          return Response.json(
            { error: "Access code is required." },
            { status: 400 }
          );
        }
        if (!env.ACCESS_CODE || accessCode !== env.ACCESS_CODE) {
          return Response.json(
            { error: "Invalid access code." },
            { status: 401 }
          );
        }

        const token = await makeSessionToken(env.ACCESS_CODE);

        return new Response(JSON.stringify({ authenticated: true }), {
          status: 200,
          headers: {
            "Content-Type": "application/json",
            "Set-Cookie":
              `session=${token}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=86400`,
          },
        });
      } catch {
        return Response.json({ error: "Invalid request." }, { status: 400 });
      }
    }

    /* ---------------- SESSION ---------------- */
    if (path === "/api/session" && request.method === "GET") {
      return Response.json({
        authenticated: await isAuthenticated(request, env),
      });
    }

    /* ---------------- LOGOUT ---------------- */
    if (path === "/api/logout" && request.method === "POST") {
      return new Response(JSON.stringify({ authenticated: false }), {
        status: 200,
        headers: {
          "Content-Type": "application/json",
          "Set-Cookie":
            "session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0",
        },
      });
    }

    /* ---------------- AUTH GATE FOR OTHER /api/* ---------------- */
    if (path.startsWith("/api/")) {
      if (!(await isAuthenticated(request, env))) {
        return Response.json({ error: "Unauthorized." }, { status: 401 });
      }
    }

    /* ---------------- CHAT: /api/chat/:id and /api/chat/:id/history ---------------- */
    const chatMatch = path.match(/^\/api\/chat\/([^/]+)(\/history)?\/?$/);
    if (chatMatch) {
      const chatId = decodeURIComponent(chatMatch[1]);
      const isHistory = Boolean(chatMatch[2]);

      if (isHistory && request.method !== "GET") {
        return Response.json({ error: "Method not allowed." }, { status: 405 });
      }
      if (!isHistory && !["POST", "DELETE"].includes(request.method)) {
        return Response.json({ error: "Method not allowed." }, { status: 405 });
      }

      try {
        const agent = await getAgentByName(env.ChatAgent, chatId);
        return await agent.fetch(request);
      } catch (error) {
        console.error("Chat routing error:", error);
        return Response.json(
          {
            error: "Failed to route chat request.",
            details: error?.message || String(error),
          },
          { status: 500 }
        );
      }
    }

    /* ---------------- UPLOAD ---------------- */
    if (path === "/api/upload" && request.method === "POST") {
      try {
        const extracted = await extractText(request, env);

        if (extracted.error) {
          return Response.json({ error: extracted.error }, { status: 400 });
        }

        const { text, filename } = extracted;

        if (!text || !text.trim()) {
          return Response.json(
            { error: "Could not extract text from the document." },
            { status: 400 }
          );
        }

        const chunks = chunkText(text);
        const docId = crypto.randomUUID();
        const vectors = [];
        const BATCH = 20;

        for (let i = 0; i < chunks.length; i += BATCH) {
          const batch = chunks.slice(i, i + BATCH);
          const embedded = await env.AI.run(EMBED_MODEL, { text: batch });

          if (!embedded?.data) continue;

          embedded.data.forEach((values, j) => {
            vectors.push({
              id: `${docId}-${i + j}`,
              values,
              metadata: {
                text: batch[j],
                filename,
                chunkIndex: i + j,
              },
            });
          });
        }

        if (vectors.length === 0) {
          return Response.json(
            { error: "Failed to generate document embeddings." },
            { status: 500 }
          );
        }

        for (let i = 0; i < vectors.length; i += 500) {
          await env.VECTORIZE.upsert(vectors.slice(i, i + 500));
        }

        return Response.json({
          success: true,
          filename,
          chunks: vectors.length,
        });
      } catch (error) {
        console.error("Upload error:", error);
        return Response.json(
          {
            error: "Failed to process document.",
            details: error?.message || String(error),
          },
          { status: 500 }
        );
      }
    }

    /* ---------------- UNKNOWN /api/* ---------------- */
    if (path.startsWith("/api/")) {
      return Response.json({ error: "Not found." }, { status: 404 });
    }

    /* ---------------- STATIC ASSETS ---------------- */
    if (env.ASSETS) return env.ASSETS.fetch(request);

    return new Response("Not Found", { status: 404 });
  },
};
