# Docs Chat Agent

A document-aware chat agent built entirely on Cloudflare's platform.

## How it satisfies the assignment

- **LLM:** Workers AI (Llama 3.3)
- **Workflow / coordination:** a Cloudflare Durable Object orchestrates retrieval, prompt building, and generation for each chat session
- **User input via chat:** a web chat UI served directly from the Worker
- **Memory / state:** the Durable Object persists conversation history per session; Vectorize stores document embeddings as long-term retrieval memory

## How it works

1. Paste text (or upload a document) — it's chunked, embedded, and stored in a Vectorize index.
2. Ask a question — the agent embeds the question, retrieves the most relevant passages from Vectorize, and asks Llama 3.3 to answer using only those passages, citing which one(s) it used.
3. Conversation history persists per session via Durable Object storage, so follow-up questions have context.

## Run it locally

    npm install
    npx wrangler login
    npx wrangler vectorize create docs-index --dimensions=768 --metric=cosine
    npx wrangler dev

## Deploy

    npx wrangler deploy

Live at: **https://ragharsh.workers.dev**  ← replace with your real URL

## Known limitations

- Single shared document index — not multi-tenant.
- No authentication yet — anyone with the URL can use it.
- Text and plain documents only in this version.

## Prompt history

See `PROMPT_HISTORY.md` — this project was built with AI assistance, as permitted by the assignment, and the full prompt history is included per their instructions.
