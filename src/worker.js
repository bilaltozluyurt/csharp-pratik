// C# Kodlama Pratiği — Cloudflare Worker
// Oturum (D1) ve statik dosya koruması. Bağımlılık yok.
// Yapı algoritma-antrenmani projesindeki giriş sistemiyle aynıdır.

const OTURUM_CEREZ = 'oturum';
const OTURUM_SURE = 30 * 24 * 60 * 60 * 1000;        // 30 gün
const PBKDF2_TUR = 20000;                             // ücretsiz plan CPU sınırı için
const KILIT_PENCERE = 15 * 60 * 1000;                 // 15 dk
const EPOSTA_SINIR = 8;
const IP_SINIR = 30;

// Oturumsuz da sunulan dosyalar
const ACIK_DOSYALAR = new Set(['/giris.html']);

// ---------- Şema ----------

const SEMA = [
  `CREATE TABLE IF NOT EXISTS kullanici (
     id INTEGER PRIMARY KEY,
     eposta TEXT NOT NULL UNIQUE,
     sifre TEXT NOT NULL,
     olusturma INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS oturum (
     token_hash TEXT PRIMARY KEY,
     kullanici_id INTEGER NOT NULL,
     olusturma INTEGER NOT NULL,
     bitis INTEGER NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS deneme (
     id INTEGER PRIMARY KEY AUTOINCREMENT,
     anahtar TEXT NOT NULL,
     zaman INTEGER NOT NULL)`,
  `CREATE INDEX IF NOT EXISTS deneme_anahtar ON deneme (anahtar, zaman)`,
];

let semaHazir = null;
function semaKur(db) {
  if (!semaHazir) {
    semaHazir = db.batch(SEMA.map((s) => db.prepare(s))).catch((e) => { semaHazir = null; throw e; });
  }
  return semaHazir;
}

// ---------- Yardımcılar ----------

const enc = new TextEncoder();

function b64(buf) {
  let s = '';
  for (const b of new Uint8Array(buf)) s += String.fromCharCode(b);
  return btoa(s);
}
function b64Coz(str) {
  const s = atob(str);
  const a = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) a[i] = s.charCodeAt(i);
  return a;
}
function hex(buf) {
  return [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');
}
async function sha256(metin) {
  return crypto.subtle.digest('SHA-256', enc.encode(metin));
}
function rastgele(n) {
  return crypto.getRandomValues(new Uint8Array(n));
}

// Uzunluktan bağımsız sabit süreli karşılaştırma (önce ikisinin de özeti alınır)
async function esitMi(a, b) {
  const [x, y] = await Promise.all([sha256(String(a)), sha256(String(b))]);
  const u = new Uint8Array(x), v = new Uint8Array(y);
  let fark = 0;
  for (let i = 0; i < u.length; i++) fark |= u[i] ^ v[i];
  return fark === 0;
}

async function pbkdf2(sifre, tuz, tur) {
  const anahtar = await crypto.subtle.importKey('raw', enc.encode(sifre), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: tuz, iterations: tur }, anahtar, 256);
}
async function sifreHashle(sifre) {
  const tuz = rastgele(16);
  const h = await pbkdf2(sifre, tuz, PBKDF2_TUR);
  return `pbkdf2$${PBKDF2_TUR}$${b64(tuz)}$${b64(h)}`;
}
// Kullanıcı yoksa da aynı işi yapmak için sahte kayıt (zamanlama farkını azaltır)
const SAHTE_HASH = `pbkdf2$${PBKDF2_TUR}$AAAAAAAAAAAAAAAAAAAAAA==$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=`;
async function sifreDogrula(sifre, kayit) {
  const p = String(kayit || '').split('$');
  if (p.length !== 4 || p[0] !== 'pbkdf2') return false;
  const tur = parseInt(p[1], 10);
  if (!(tur > 0 && tur <= 1000000)) return false;
  const h = await pbkdf2(sifre, b64Coz(p[2]), tur);
  const beklenen = b64Coz(p[3]);
  const gelen = new Uint8Array(h);
  if (beklenen.length !== gelen.length) return false;
  let fark = 0;
  for (let i = 0; i < gelen.length; i++) fark |= gelen[i] ^ beklenen[i];
  return fark === 0;
}

function epostaNormal(e) {
  // tr-TR kullanılmaz: 'I' → 'ı' dönüşümü e-postayı bozar.
  return String(e || '').trim().toLowerCase();
}
function epostaGecerli(e) {
  return e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
}
function sifreKuraliHatasi(s) {
  if (typeof s !== 'string' || s.length < 8) return 'Şifre en az 8 karakter olmalı.';
  if (s.length > 200) return 'Şifre en fazla 200 karakter olabilir.';
  if (!/\p{L}/u.test(s) || !/\d/.test(s)) return 'Şifre en az bir harf ve bir rakam içermeli.';
  return null;
}

// Türkiye saati (UTC+3)
function saatTR(ms) {
  return new Date(ms + 3 * 60 * 60 * 1000).toISOString().slice(11, 16);
}

function cerezOku(req, ad) {
  const c = req.headers.get('Cookie') || '';
  for (const parca of c.split(';')) {
    const i = parca.indexOf('=');
    if (i > -1 && parca.slice(0, i).trim() === ad) return parca.slice(i + 1).trim();
  }
  return null;
}
function cerezYaz(token, maxAgeSn) {
  return `${OTURUM_CEREZ}=${token}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAgeSn}`;
}

function guvenlikBasliklari(res, ek = {}) {
  const r = new Response(res.body, res);
  const h = r.headers;
  h.set('X-Content-Type-Options', 'nosniff');
  h.set('X-Frame-Options', 'DENY');
  h.set('Referrer-Policy', 'same-origin');
  h.set('X-Robots-Tag', 'noindex, nofollow');
  for (const [k, v] of Object.entries(ek)) h.set(k, v);
  return r;
}

function json(veri, durum = 200, basliklar = {}) {
  return new Response(JSON.stringify(veri), {
    status: durum,
    headers: { 'Content-Type': 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...basliklar },
  });
}
const hata = (mesaj, durum, ek) => json({ hata: mesaj, ...(ek || {}) }, durum);

function yonlendir(yer) {
  return new Response(null, { status: 302, headers: { Location: yer, 'Cache-Control': 'no-store' } });
}

class IstekHatasi extends Error {
  constructor(m, d) { super(m); this.durum = d; }
}
async function govdeOku(req, sinir = 10_000) {
  const metin = await req.text();
  if (metin.length > sinir) throw new IstekHatasi('İstek çok büyük.', 413);
  if (!metin) return {};
  try { return JSON.parse(metin); } catch { throw new IstekHatasi('Geçersiz JSON.', 400); }
}

// ---------- Oturum ----------

async function oturumBul(env, req) {
  const token = cerezOku(req, OTURUM_CEREZ);
  if (!token || !/^[A-Za-z0-9_-]{43}$/.test(token)) return null;
  const th = hex(await sha256(token));
  const simdi = Date.now();
  const o = await env.DB.prepare(
    'SELECT o.token_hash, o.bitis, k.id, k.eposta FROM oturum o JOIN kullanici k ON k.id = o.kullanici_id WHERE o.token_hash = ? AND o.bitis > ?'
  ).bind(th, simdi).first();
  if (!o) return null;
  let yeniCerez = null;
  // Sürenin yarısı geçtiyse uzat
  if (o.bitis - simdi < OTURUM_SURE / 2) {
    await env.DB.prepare('UPDATE oturum SET bitis = ? WHERE token_hash = ?').bind(simdi + OTURUM_SURE, th).run();
    yeniCerez = cerezYaz(token, OTURUM_SURE / 1000);
  }
  return { tokenHash: th, kullaniciId: o.id, eposta: o.eposta, yeniCerez };
}

async function oturumAc(env, kullaniciId) {
  const token = b64(rastgele(32)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  const th = hex(await sha256(token));
  const simdi = Date.now();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM oturum WHERE bitis < ?').bind(simdi),
    env.DB.prepare('INSERT INTO oturum (token_hash, kullanici_id, olusturma, bitis) VALUES (?, ?, ?, ?)')
      .bind(th, kullaniciId, simdi, simdi + OTURUM_SURE),
  ]);
  return cerezYaz(token, OTURUM_SURE / 1000);
}

// ---------- Kaba kuvvet koruması ----------

// Kilitliyse açılacağı zamanı (ms) döner, değilse null
async function kilitKontrol(env, anahtar, sinir) {
  const r = await env.DB.prepare(
    'SELECT zaman FROM deneme WHERE anahtar = ? AND zaman > ? ORDER BY zaman DESC LIMIT 1 OFFSET ?'
  ).bind(anahtar, Date.now() - KILIT_PENCERE, sinir - 1).first();
  return r ? r.zaman + KILIT_PENCERE : null;
}
function kilitYaniti(acilis, kapsam) {
  const dk = Math.max(1, Math.ceil((acilis - Date.now()) / 60000));
  return hata(
    `Çok fazla hatalı deneme: ${kapsam} 15 dakikalığına kilitlendi. Kilit yaklaşık ${dk} dakika sonra (${saatTR(acilis)}) açılacak. ` +
      'Kilitliyken doğru şifre de kabul edilmez; lütfen bekleyip tekrar deneyin.',
    429,
    { kilitAcilis: acilis }
  );
}
async function denemeKaydet(env, anahtarlar) {
  const simdi = Date.now();
  await env.DB.batch([
    env.DB.prepare('DELETE FROM deneme WHERE zaman < ?').bind(simdi - 24 * 60 * 60 * 1000),
    ...anahtarlar.map((a) => env.DB.prepare('INSERT INTO deneme (anahtar, zaman) VALUES (?, ?)').bind(a, simdi)),
  ]);
}

// ---------- Oturum uç noktaları (oturumsuz erişilebilir) ----------

async function kullaniciVarMi(env) {
  const r = await env.DB.prepare('SELECT COUNT(*) AS n FROM kullanici').first();
  return r.n > 0;
}

async function durum(env, req) {
  const o = await oturumBul(env, req);
  return json({ kurulum: !(await kullaniciVarMi(env)), girisli: !!o });
}

async function kurulum(env, req, ip) {
  if (await kullaniciVarMi(env)) return hata('Kurulum tamamlanmış. Bu uç nokta kapalı.', 409);
  if (!env.KURULUM_KODU) {
    return hata("KURULUM_KODU Secret'ı tanımlı değil. Cloudflare → Worker → Settings → Variables and Secrets bölümünden ekleyin.", 503);
  }
  const ipAnahtar = 'ip:' + ip;
  const ipKilit = await kilitKontrol(env, ipAnahtar, IP_SINIR);
  if (ipKilit) return kilitYaniti(ipKilit, 'bu IP adresi');

  const g = await govdeOku(req);
  if (!(await esitMi(String(g.kod || '').trim(), String(env.KURULUM_KODU).trim()))) {
    await denemeKaydet(env, [ipAnahtar]);
    return hata('Kurulum kodu yanlış.', 403);
  }
  const eposta = epostaNormal(g.eposta);
  if (!epostaGecerli(eposta)) return hata('Geçerli bir e-posta girin.', 400);
  const kural = sifreKuraliHatasi(g.sifre);
  if (kural) return hata(kural, 400);

  const hash = await sifreHashle(g.sifre);
  const r = await env.DB.prepare(
    'INSERT INTO kullanici (eposta, sifre, olusturma) SELECT ?, ?, ? WHERE NOT EXISTS (SELECT 1 FROM kullanici)'
  ).bind(eposta, hash, Date.now()).run();
  if (!r.meta.changes) return hata('Kurulum tamamlanmış. Bu uç nokta kapalı.', 409);
  const k = await env.DB.prepare('SELECT id FROM kullanici WHERE eposta = ?').bind(eposta).first();
  const cerez = await oturumAc(env, k.id);
  return json({ tamam: true }, 200, { 'Set-Cookie': cerez });
}

async function giris(env, req, ip) {
  const g = await govdeOku(req);
  const eposta = epostaNormal(g.eposta);
  const sifre = typeof g.sifre === 'string' ? g.sifre : '';
  if (!eposta || !sifre) return hata('E-posta ve şifre gerekli.', 400);

  // Kilit kontrolü şifre kontrolünden ÖNCE
  const eAnahtar = 'e:' + eposta, ipAnahtar = 'ip:' + ip;
  const eKilit = await kilitKontrol(env, eAnahtar, EPOSTA_SINIR);
  if (eKilit) return kilitYaniti(eKilit, 'bu hesap');
  const ipKilit = await kilitKontrol(env, ipAnahtar, IP_SINIR);
  if (ipKilit) return kilitYaniti(ipKilit, 'bu IP adresi');

  const k = await env.DB.prepare('SELECT id, sifre FROM kullanici WHERE eposta = ?').bind(eposta).first();
  const dogru = await sifreDogrula(sifre, k ? k.sifre : SAHTE_HASH);
  if (!k || !dogru) {
    await denemeKaydet(env, [eAnahtar, ipAnahtar]);
    const kalan = await env.DB.prepare('SELECT COUNT(*) AS n FROM deneme WHERE anahtar = ? AND zaman > ?')
      .bind(eAnahtar, Date.now() - KILIT_PENCERE).first();
    const hak = Math.max(0, EPOSTA_SINIR - kalan.n);
    return hata(
      hak > 0 ? `E-posta ya da şifre yanlış. Kilitlenmeden önce ${hak} deneme hakkın kaldı.`
              : 'E-posta ya da şifre yanlış. Bu hesap 15 dakikalığına kilitlendi; bu sürede doğru şifre de kabul edilmez.',
      hak > 0 ? 401 : 429
    );
  }
  await env.DB.prepare('DELETE FROM deneme WHERE anahtar = ?').bind(eAnahtar).run();
  const cerez = await oturumAc(env, k.id);
  return json({ tamam: true }, 200, { 'Set-Cookie': cerez });
}

// ---------- Oturum gerektiren uç noktalar ----------

async function cikis(env, o) {
  // Bu oturum dahil tüm oturumlar kapanır
  await env.DB.prepare('DELETE FROM oturum WHERE kullanici_id = ?').bind(o.kullaniciId).run();
  return json({ tamam: true }, 200, { 'Set-Cookie': cerezYaz('', 0) });
}

async function sifreDegistir(env, req, o, ip) {
  const g = await govdeOku(req);
  const eAnahtar = 'e:' + o.eposta;
  const kilit = await kilitKontrol(env, eAnahtar, EPOSTA_SINIR);
  if (kilit) return kilitYaniti(kilit, 'bu hesap');
  const k = await env.DB.prepare('SELECT sifre FROM kullanici WHERE id = ?').bind(o.kullaniciId).first();
  if (!(await sifreDogrula(String(g.mevcut || ''), k.sifre))) {
    await denemeKaydet(env, [eAnahtar, 'ip:' + ip]);
    return hata('Mevcut şifre yanlış.', 403);
  }
  const kural = sifreKuraliHatasi(g.yeni);
  if (kural) return hata(kural, 400);
  const hash = await sifreHashle(g.yeni);
  // Diğer tüm oturumlar silinir, bu cihaz için yeni oturum açılır
  await env.DB.batch([
    env.DB.prepare('UPDATE kullanici SET sifre = ? WHERE id = ?').bind(hash, o.kullaniciId),
    env.DB.prepare('DELETE FROM oturum WHERE kullanici_id = ?').bind(o.kullaniciId),
  ]);
  const cerez = await oturumAc(env, o.kullaniciId);
  return json({ tamam: true }, 200, { 'Set-Cookie': cerez });
}

// ---------- Yönlendirici ----------

async function api(env, req, yol, ip) {
  const m = req.method;
  // CSRF: GET dışındaki her API isteğinde özel başlık zorunlu
  if (m !== 'GET' && m !== 'HEAD' && req.headers.get('X-Uygulama') !== '1') {
    return hata('Geçersiz istek (X-Uygulama başlığı eksik).', 403);
  }

  if (yol === '/api/oturum/durum' && m === 'GET') return durum(env, req);
  if (yol === '/api/oturum/kurulum' && m === 'POST') return kurulum(env, req, ip);
  if (yol === '/api/oturum/giris' && m === 'POST') return giris(env, req, ip);

  const o = await oturumBul(env, req);
  if (!o) return hata('Oturum gerekli.', 401);

  let yanit;
  if (yol === '/api/oturum/cikis' && m === 'POST') return cikis(env, o);
  else if (yol === '/api/oturum/sifre' && m === 'POST') return sifreDegistir(env, req, o, ip);
  else if (yol === '/api/oturum/ben' && m === 'GET') yanit = json({ eposta: o.eposta });
  else yanit = hata('Bulunamadı.', 404);

  if (o.yeniCerez) yanit.headers.append('Set-Cookie', o.yeniCerez);
  return yanit;
}

async function isle(req, env) {
  const url = new URL(req.url);
  const yol = url.pathname;
  const ip = req.headers.get('CF-Connecting-IP') || 'yerel';

  if (!env.DB) {
    return guvenlikBasliklari(new Response(
      "D1 veritabanı bağlı değil: wrangler.jsonc içindeki d1_databases ayarını kontrol edin.",
      { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } }
    ));
  }
  await semaKur(env.DB);

  if (yol.startsWith('/api/')) {
    try {
      return guvenlikBasliklari(await api(env, req, yol, ip), { 'Cache-Control': 'no-store' });
    } catch (e) {
      if (e instanceof IstekHatasi) return guvenlikBasliklari(hata(e.message, e.durum));
      console.error(e);
      return guvenlikBasliklari(hata('Sunucu hatası.', 500));
    }
  }

  if (req.method !== 'GET' && req.method !== 'HEAD') {
    return guvenlikBasliklari(new Response('İzin verilmeyen yöntem', { status: 405 }));
  }

  const o = await oturumBul(env, req);

  if (!o) {
    if (ACIK_DOSYALAR.has(yol)) return guvenlikBasliklari(await env.ASSETS.fetch(req), { 'Cache-Control': 'no-cache' });
    return guvenlikBasliklari(yonlendir('/giris.html'));
  }

  if (yol === '/giris.html') return guvenlikBasliklari(yonlendir('/'));

  // Oturum var: statik dosya
  const hedef = new URL(req.url);
  if (yol === '/' || yol === '') hedef.pathname = '/index.html';
  let res = await env.ASSETS.fetch(new Request(hedef, req));
  if (res.status === 404) res = new Response('Bulunamadı', { status: 404 });
  const r = guvenlikBasliklari(res, { 'Cache-Control': 'private, no-cache' });
  if (o.yeniCerez) r.headers.append('Set-Cookie', o.yeniCerez);
  return r;
}

export default {
  async fetch(req, env) {
    try {
      return await isle(req, env);
    } catch (e) {
      console.error(e);
      return guvenlikBasliklari(new Response('Sunucu hatası', { status: 500 }));
    }
  },
};
