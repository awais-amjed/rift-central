import { assert } from "jsr:@std/assert@1";
import { isPlainAddress } from "./address.ts";

Deno.test("an ordinary server address is plain", () => {
  assert(isPlainAddress("https://rift.example.com"));
  assert(isPlainAddress("https://Rift.Example.com/"));
  assert(isPlainAddress("https://rift.example.com:8443"));
  assert(isPlainAddress("https://xn--bcher-kva.example"));
});

Deno.test("spellings a parser reads as the same host are refused", () => {
  // Each reaches the same machine as https://srv.example.com and would be a
  // listing of its own under the directory's key.
  assert(!isPlainAddress("https://sr%76.example.com"));
  assert(!isPlainAddress("https://bücher.example"));
  assert(!isPlainAddress("https://srv.example.com:0443"));
  assert(!isPlainAddress("https://user@srv.example.com"));
  assert(!isPlainAddress("https://srv.example.com/?x"));
  assert(!isPlainAddress("http://srv.example.com"));
});
