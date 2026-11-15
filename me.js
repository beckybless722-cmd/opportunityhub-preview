
const COOKIE = "oh_admin";
async function sign(value, secret) {
  const key = await crypto.subtle.importKey("raw", new TextEncoder().encode(secret), {name:"HMAC",hash:"SHA-256"}, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(value));
  return btoa(String.fromCharCode(...new Uint8Array(sig))).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}
async function valid(request, env) {
  const raw=(request.headers.get("Cookie")||"").split(";").map(x=>x.trim()).find(x=>x.startsWith(COOKIE+"="));
  if(!raw||!env.SESSION_SECRET) return false;
  const value=decodeURIComponent(raw.slice(COOKIE.length+1)).split(".");
  if(value.length!==2) return false;
  const [payload,sig]=value;
  if(await sign(payload,env.SESSION_SECRET)!==sig) return false;
  try { const p=JSON.parse(atob(payload)); return p.exp>Date.now(); } catch { return false; }
}
function json(data,status=200,headers={}) { return new Response(JSON.stringify(data),{status,headers:{"Content-Type":"application/json; charset=utf-8","Cache-Control":"no-store",...headers}}); }
function cookie(value,maxAge=86400){return `${COOKIE}=${encodeURIComponent(value)}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${maxAge}`;}
async function body(req){try{return await req.json()}catch{return {}}}
async function ensure(env){if(!env.DB)throw Error("Database binding DB is missing. Follow README-SETUP.txt.");}
async function admin(req,env){return valid(req,env);}

export async function onRequestGet({request,env}){return await admin(request,env)?json({ok:true}):json({error:"Not signed in"},401);}
