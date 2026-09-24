// The push relay as an ordinary Node server — for a VPS, Fly.io, Render, or
// anywhere that runs a container.
//
// All of the relay is in `relay.ts`, shared verbatim with the Supabase Edge
// Function. This file is only the adapter: Node's http server in, Web
// `Request`/`Response` out. Node strips the TypeScript itself, so there is no
// build step.
//
//   FCM_SERVICE_ACCOUNT="$(cat rift-service-key.json)" \
//   SUPABASE_URL=... RIFT_SECRET_KEY=... PUSH_SECRET=... \
//   node relay/server.mjs
import { createServer } from "node:http";
import { Buffer } from "node:buffer";
import {
  createRelay,
  relayConfigFromEnv,
} from "../supabase/functions/push_send/relay.ts";

const handle = createRelay(relayConfigFromEnv());
const port = Number(process.env.PORT ?? 8080);

createServer(async (req, res) => {
  const chunks = [];
  for await (const chunk of req) chunks.push(chunk);

  // Node's header bag can hold arrays; `Headers` cannot. Nothing the relay
  // reads is ever repeated, so the first value is the right one.
  const headers = {};
  for (const [key, value] of Object.entries(req.headers)) {
    headers[key] = Array.isArray(value) ? value[0] : value;
  }

  let out;
  try {
    out = await handle(
      new Request(`http://relay${req.url}`, {
        method: req.method,
        headers,
        body: chunks.length ? Buffer.concat(chunks) : undefined,
      }),
    );
  } catch (err) {
    out = new Response(`error: ${err}`, { status: 500 });
  }

  res.writeHead(out.status, Object.fromEntries(out.headers));
  res.end(Buffer.from(await out.arrayBuffer()));
}).listen(port, () => console.log(`push relay listening on :${port}`));
