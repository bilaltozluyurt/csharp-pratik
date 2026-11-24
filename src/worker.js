// Siteyi kullanıcı adı + şifre (HTTP Basic Auth) ile korur.
// Kimlik bilgileri koda yazılmaz; Cloudflare'de secret olarak tanımlanır:
//   AUTH_USER  ve  AUTH_PASS
export default {
  async fetch(request, env) {
    if (!env.AUTH_USER || !env.AUTH_PASS) {
      // Secret'lar tanımlanmadıysa site kapalı kalır (güvenli varsayılan)
      return new Response("Site kilitli: AUTH_USER ve AUTH_PASS secret'ları tanımlı değil.", {
        status: 503,
        headers: { "Content-Type": "text/plain; charset=utf-8", "Cache-Control": "no-store" },
      });
    }

    if (await isAuthorized(request, env)) {
      const res = await env.ASSETS.fetch(request);
      const out = new Response(res.body, res);
      out.headers.set("Cache-Control", "private, no-store");
      out.headers.set("X-Robots-Tag", "noindex, nofollow");
      out.headers.set("X-Frame-Options", "DENY");
      out.headers.set("Referrer-Policy", "no-referrer");
      return out;
    }

    return new Response("Giriş gerekli.", {
      status: 401,
      headers: {
        "WWW-Authenticate": 'Basic realm="csharp-pratik", charset="UTF-8"',
        "Content-Type": "text/plain; charset=utf-8",
        "Cache-Control": "no-store",
      },
    });
  },
};

async function isAuthorized(request, env) {
  const header = request.headers.get("Authorization") || "";
  if (!header.startsWith("Basic ")) return false;

  let decoded;
  try {
    const bytes = Uint8Array.from(atob(header.slice(6).trim()), (c) => c.charCodeAt(0));
    decoded = new TextDecoder().decode(bytes); // Türkçe karakterli şifreler için
  } catch {
    return false;
  }

  const sep = decoded.indexOf(":");
  if (sep < 0) return false;

  const userOk = await safeEqual(decoded.slice(0, sep), env.AUTH_USER);
  const passOk = await safeEqual(decoded.slice(sep + 1), env.AUTH_PASS);
  return userOk && passOk;
}

// Zamanlama saldırılarına karşı sabit süreli karşılaştırma
async function safeEqual(a, b) {
  const enc = new TextEncoder();
  const [ha, hb] = await Promise.all([
    crypto.subtle.digest("SHA-256", enc.encode(a)),
    crypto.subtle.digest("SHA-256", enc.encode(b)),
  ]);
  return crypto.subtle.timingSafeEqual(ha, hb);
}
