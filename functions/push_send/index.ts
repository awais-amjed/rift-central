import "@supabase/functions-js/edge-runtime.d.ts";
import { createRelay, relayConfigFromEnv } from "./relay.ts";

/**
 * Supabase Edge Functions' entry point for the push relay.
 *
 * Deliberately this short. All of the relay lives in `relay.ts`, which has no
 * imports and uses only Web APIs, so the same code runs unchanged on a VPS, on
 * Fly.io or in a Cloudflare Worker — see `relay/README.md` for those entry
 * points. Hosting is then a decision that can be revisited rather than one
 * that has to be right the first time.
 */
Deno.serve(createRelay(relayConfigFromEnv()));
