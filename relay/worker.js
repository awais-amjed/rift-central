// The push relay as a Cloudflare Worker — in either of two roles.
//
// **Forwarder** (set `RELAY_BACKEND`): passes the request through to whatever
// is actually running the relay today. This is what gives `push.joinrift.app`
// a fixed meaning while the thing behind it moves. Operators store the
// hostname; you change one binding.
//
// **The relay itself** (no `RELAY_BACKEND`): runs `relay.ts` here at the edge.
// Note the ceiling before choosing this — a Worker invocation may hold only
// six connections waiting for response headers, on *every* plan, which caps a
// single fan-out at roughly 20 devices/second. Split larger fan-outs across
// invocations at the caller. Measured, not guessed: see relay/README.md.
import {
  createRelay,
  relayConfigFromEnv,
} from "../supabase/functions/push_send/relay.ts";

let handle;

export default {
  fetch(request, env) {
    if (env.RELAY_BACKEND) {
      // Method, headers and body pass through untouched: the backend does the
      // authenticating, and this knows nothing worth knowing.
      return fetch(env.RELAY_BACKEND, request);
    }
    handle ??= createRelay(relayConfigFromEnv(env));
    return handle(request);
  },
};
