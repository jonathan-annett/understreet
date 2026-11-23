import { DurableObject } from "cloudflare:workers";

export class MyDurableObject extends DurableObject {
  async fetch() {
    return new Response("ok\n");
  }
}

export default {
  async fetch(request, env) {
    return new Response("understreet: placeholder\n");
  },
};
