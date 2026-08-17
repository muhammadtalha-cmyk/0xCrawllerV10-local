export default {
  async fetch(request, env) {
    const incomingUrl = new URL(request.url);

    const allowedOrigin = env.FRONTEND_ORIGIN;
    const requestOrigin = request.headers.get("Origin");

    // Handle browser CORS preflight.
    if (request.method === "OPTIONS") {
      const headers = new Headers();

      if (requestOrigin === allowedOrigin) {
        headers.set("Access-Control-Allow-Origin", allowedOrigin);
        headers.set("Access-Control-Allow-Credentials", "true");
      }

      headers.set(
        "Access-Control-Allow-Methods",
        "GET,POST,PUT,PATCH,DELETE,OPTIONS"
      );

      headers.set(
        "Access-Control-Allow-Headers",
        request.headers.get("Access-Control-Request-Headers") ||
          "Content-Type,Authorization"
      );

      headers.set("Access-Control-Max-Age", "86400");
      headers.set("Vary", "Origin");

      return new Response(null, {
        status: 204,
        headers
      });
    }

    const backendBase = new URL(env.BACKEND_ORIGIN);

    const targetUrl = new URL(
      incomingUrl.pathname + incomingUrl.search,
      backendBase
    );

    const headers = new Headers(request.headers);

    // Preserve the real browser Origin so FastAPI's existing CORS
    // configuration can continue validating the Vercel frontend.
    if (requestOrigin) {
      headers.set("Origin", requestOrigin);
    }

    headers.set("Host", backendBase.host);

    const upstreamRequest = new Request(targetUrl.toString(), {
      method: request.method,
      headers,
      body:
        request.method === "GET" || request.method === "HEAD"
          ? undefined
          : request.body,
      redirect: "manual"
    });

    let response;

    try {
      response = await fetch(upstreamRequest);
    } catch (error) {
      return new Response(
        JSON.stringify({
          detail: "Backend unavailable",
          error: String(error)
        }),
        {
          status: 502,
          headers: {
            "Content-Type": "application/json"
          }
        }
      );
    }

    // WebSocket upgrade responses must be returned directly so
    // Cloudflare can proxy the upgraded connection.
    if (response.status === 101 || response.webSocket) {
      return response;
    }

    const responseHeaders = new Headers(response.headers);

    if (requestOrigin === allowedOrigin) {
      responseHeaders.set(
        "Access-Control-Allow-Origin",
        allowedOrigin
      );
      responseHeaders.set(
        "Access-Control-Allow-Credentials",
        "true"
      );
      responseHeaders.set("Vary", "Origin");
    }

    return new Response(response.body, {
      status: response.status,
      statusText: response.statusText,
      headers: responseHeaders
    });
  }
};
