/**
 * Central license row store for multi-LAN Anisette replicas behind one hostname.
 * Path contract matches Middleware /internal/license* (Package-C sync).
 *
 * Auth: header X-Anisette-License-Sync == ANISETTE_LICENSE_SYNC_SECRET
 *       or Authorization: Bearer <secret>
 */

const SYNC_HEADER = "X-Anisette-License-Sync";
const REPLICA_HEADER = "X-Anisette-Replica-Id";

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const replicaId = env.REPLICA_ID || "license-hub";

    if (!path.startsWith("/internal/license")) {
      return json({ ok: false, error: "not_found" }, 404, replicaId);
    }

    if (!isAuthorized(request, env)) {
      return json({ ok: false, error: "sync_unauthorized" }, 401, replicaId);
    }

    const store = kv(env);
    if (!store) {
      return json(
        {
          ok: false,
          error: "kv_not_bound",
          detail: "Bind KV as LICENSES (see wrangler.toml.example) and redeploy.",
        },
        500,
        replicaId);
    }

    if (request.method === "POST" && path === "/internal/license-sync") {
      let body;
      try {
        body = await request.json();
      } catch {
        return json({ ok: false, error: "bad_json" }, 400, replicaId);
      }
      const id = String(body?.license_id || body?.licenseId || "").trim();
      if (!id) {
        return json({ ok: false, error: "license_id_required" }, 400, replicaId);
      }

      const record = normalize(body);
      await store.put(keyId(id), JSON.stringify(record));
      if (record.fingerprint) {
        await store.put(keyFp(record.fingerprint), id);
      }
      await addToIndex(store, id);
      return json({ ok: true, license_id: id, replica_id: replicaId }, 200, replicaId);
    }

    if (request.method === "GET") {
      if (path === "/internal/license/index") {
        const ids = await readIndex(store);
        return json({ ok: true, ids, replica_id: replicaId }, 200, replicaId);
      }

      // Fingerprint route first — do not treat "by-fingerprint" as a license id.
      const byFp = path.match(/^\/internal\/license\/by-fingerprint\/([^/]+)$/);
      if (byFp) {
        const fp = decodeURIComponent(byFp[1]).trim();
        const id = await store.get(keyFp(fp));
        if (!id) {
          return json({ ok: false, error: "not_found" }, 404, replicaId);
        }
        const raw = await store.get(keyId(id));
        if (!raw) {
          return json({ ok: false, error: "not_found" }, 404, replicaId);
        }
        return rawJson(raw, 200, replicaId);
      }

      const byId = path.match(/^\/internal\/license\/([^/]+)$/);
      if (byId) {
        const id = decodeURIComponent(byId[1]).trim();
        if (id.toLowerCase() === "by-fingerprint" || id.toLowerCase() === "index") {
          return json({ ok: false, error: "not_found" }, 404, replicaId);
        }
        const raw = await store.get(keyId(id));
        if (!raw) {
          return json({ ok: false, error: "not_found" }, 404, replicaId);
        }
        return rawJson(raw, 200, replicaId);
      }
    }

    return json({ ok: false, error: "method_not_allowed" }, 405, replicaId);
  },
};

function kv(env) {
  return env.LICENSES || env.ANISETTE_LICENSE_KV || null;
}

const INDEX_KEY = "lic:index";

async function readIndex(store) {
  try {
    const raw = await store.get(INDEX_KEY);
    let ids = [];
    if (raw) {
      const parsed = JSON.parse(raw);
      if (Array.isArray(parsed)) {
        ids = parsed.map((x) => String(x || "").trim()).filter(Boolean);
      }
    }
    if (ids.length === 0) {
      // Backfill from existing lic:* keys (first deploy / pre-index rows).
      let cursor;
      do {
        const page = await store.list({ prefix: "lic:", cursor });
        for (const k of page.keys) {
          if (!k.name || k.name === INDEX_KEY) continue;
          // skip accidental nested keys; license ids are lic:{hex}
          const id = k.name.slice("lic:".length);
          if (id && id !== "index") ids.push(id);
        }
        cursor = page.list_complete ? undefined : page.cursor;
      } while (cursor);
      ids = [...new Set(ids)];
      if (ids.length) await store.put(INDEX_KEY, JSON.stringify(ids));
    }
    return ids;
  } catch {
    return [];
  }
}

async function addToIndex(store, id) {
  const ids = await readIndex(store);
  if (!ids.includes(id)) {
    ids.push(id);
    await store.put(INDEX_KEY, JSON.stringify(ids));
  }
}

function keyId(id) {
  return `lic:${id}`;
}

function keyFp(fp) {
  return `fp:${fp}`;
}

function pick(body, snake, camel) {
  if (body[snake] !== undefined && body[snake] !== null) return body[snake];
  if (body[camel] !== undefined && body[camel] !== null) return body[camel];
  return null;
}

function normalize(body) {
  const fp = pick(body, "fingerprint", "fingerprint");
  return {
    license_id: String(pick(body, "license_id", "licenseId") || "").trim(),
    subject: String(pick(body, "subject", "subject") || ""),
    issued_at: pick(body, "issued_at", "issuedAt"),
    expires_at: pick(body, "expires_at", "expiresAt"),
    revoked_at: pick(body, "revoked_at", "revokedAt"),
    note: pick(body, "note", "note"),
    token_hint: pick(body, "token_hint", "tokenHint"),
    fingerprint: fp ? String(fp).trim() : null,
    client_ip: pick(body, "client_ip", "clientIp"),
    enabled: pick(body, "enabled", "enabled") !== false,
    emitted_once: !!pick(body, "emitted_once", "emittedOnce"),
  };
}

function isAuthorized(request, env) {
  const secret = (env.ANISETTE_LICENSE_SYNC_SECRET || "").trim();
  if (!secret) return false;
  const sync = (request.headers.get(SYNC_HEADER) || "").trim();
  if (sync && sync === secret) return true;
  const auth = (request.headers.get("Authorization") || "").trim();
  if (auth.toLowerCase().startsWith("bearer ") && auth.slice(7).trim() === secret) {
    return true;
  }
  return false;
}

function json(obj, status, replicaId) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      [REPLICA_HEADER]: replicaId,
    },
  });
}

function rawJson(raw, status, replicaId) {
  return new Response(raw, {
    status,
    headers: {
      "content-type": "application/json; charset=utf-8",
      [REPLICA_HEADER]: replicaId,
    },
  });
}
