const API_ORIGIN = "https://billion-bro.uddinofficial.workers.dev";

export default {
  async fetch(request, env) {
    const incoming = new URL(request.url);

    // Keep the existing account API and its saved data on the original Worker.
    // Only the front-end is deployed from this repository.
    if (incoming.pathname === "/api" || incoming.pathname.startsWith("/api/")) {
      const target = new URL(incoming.pathname + incoming.search, API_ORIGIN);
      const headers = new Headers(request.headers);

      // The old API expects same-origin requests. The proxy makes the request
      // server-to-server, so present the original API origin to its origin checks.
      headers.set("origin", API_ORIGIN);
      const referer = headers.get("referer");
      if (referer) {
        try {
          const ref = new URL(referer);
          const apiHost = new URL(API_ORIGIN);
          ref.protocol = apiHost.protocol;
          ref.host = apiHost.host;
          headers.set("referer", ref.toString());
        } catch {
          headers.delete("referer");
        }
      }

      const init = {
        method: request.method,
        headers,
        redirect: "manual"
      };
      if (request.method !== "GET" && request.method !== "HEAD") {
        init.body = request.body;
      }

      return fetch(new Request(target.toString(), init));
    }

    return env.ASSETS.fetch(request);
  }
};
