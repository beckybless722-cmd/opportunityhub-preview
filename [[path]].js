
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

export async function onRequest({request,env}) {
 try {
 await ensure(env); const method=request.method;
 if(method==="GET"){
  const isAdmin=await admin(request,env), all=new URL(request.url).searchParams.get("all")==="1";
  if(all&&!isAdmin)return json({error:"Not authorised"},401);
  const where=all?"":"WHERE expires_at IS NULL OR expires_at >= date('now')";
  const sql=all
   ? `SELECT *, CASE WHEN type='job' AND featured=1 AND payment_status='paid' AND featured_until IS NOT NULL AND date(featured_until)>=date('now') THEN 1 ELSE 0 END AS featured_active FROM opportunities ORDER BY featured_active DESC, created_at DESC`
   : `SELECT id,type,title,org,location,level,deadline,description,url,expires_at,CASE WHEN type='job' AND featured=1 AND payment_status='paid' AND featured_until IS NOT NULL AND date(featured_until)>=date('now') THEN 1 ELSE 0 END AS featured,created_at FROM opportunities WHERE expires_at IS NULL OR date(expires_at)>=date('now') ORDER BY featured DESC, created_at DESC`;
  const rows=await env.DB.prepare(sql).all();
  return json({opportunities:rows.results||[]});
 }
 if(!await admin(request,env))return json({error:"Not authorised"},401);
 if(method==="POST"){
  const b=await body(request);
  if(!["job","scholarship","internship"].includes(b.type)||!b.title||!b.org||!b.description||!b.url)return json({error:"Complete the required listing fields."},400);
  const expires=b.expires_at|| ((b.type==="job"||b.type==="internship")?new Date(Date.now()+30*86400000).toISOString().slice(0,10):(b.deadline||null));
  const featured=b.type==="job"&&!!b.featured;
  const r=await env.DB.prepare(`INSERT INTO opportunities(type,title,org,location,level,deadline,description,url,expires_at,featured,featured_until,promotion_fee,payment_status,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,datetime('now'))`).bind(b.type,b.title,b.org,b.location||"",b.level||"",b.deadline||null,b.description,b.url,expires,featured?1:0,b.featured_until||null,Number(b.promotion_fee||0),b.payment_status||"not_applicable").run();
  return json({ok:true,id:r.meta.last_row_id},201);
 }
 const id=new URL(request.url).pathname.split("/").pop();
 if(method==="PUT"){
  const b=await body(request);
  const old=await env.DB.prepare("SELECT * FROM opportunities WHERE id=?").bind(id).first();
  if(!old)return json({error:"Listing not found."},404);
  const v={...old,...b};
  if(!["job","scholarship","internship"].includes(v.type)||!v.title||!v.org||!v.description||!v.url)return json({error:"Complete the required listing fields."},400);
  await env.DB.prepare(`UPDATE opportunities SET type=?,title=?,org=?,location=?,level=?,deadline=?,description=?,url=?,expires_at=?,featured=?,featured_until=?,promotion_fee=?,payment_status=? WHERE id=?`).bind(v.type,v.title,v.org,v.location||"",v.level||"",v.deadline||null,v.description,v.url,v.expires_at||null,(v.type==="job"&&v.featured)?1:0,v.featured_until||null,Number(v.promotion_fee||0),v.payment_status||"not_applicable",id).run();
  return json({ok:true});
 }
 if(method==="DELETE"){await env.DB.prepare("DELETE FROM opportunities WHERE id=?").bind(id).run();return json({ok:true});}
 return json({error:"Method not allowed"},405);
 } catch(e){return json({error:e.message||"Server error"},500);}
}
