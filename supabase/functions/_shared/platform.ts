import { createClient } from 'npm:@supabase/supabase-js@2.118.0';

export const site = 'https://lss-1024.github.io/feishu-workspace/';
export const project = Deno.env.get('SUPABASE_URL')!;
export const callback = `${project}/functions/v1/fa-oauth`;
const backendKey = JSON.parse(Deno.env.get('SUPABASE_SECRET_KEYS') || '{}').default || Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!;
export const db = createClient(project, backendKey, { auth: { persistSession:false, autoRefreshToken:false } });
export const cors = { 'Access-Control-Allow-Origin':'https://lss-1024.github.io', 'Access-Control-Allow-Headers':'authorization, apikey, content-type, x-client-info', 'Access-Control-Allow-Methods':'POST, OPTIONS', 'Vary':'Origin' };
export function json(data:unknown,status=200) { return Response.json(data,{status,headers:{...cors,'Cache-Control':'no-store'}}); }
export function assert(test:unknown,message:string):asserts test { if(!test) throw new Error(message); }
export async function checked<T>(result:PromiseLike<{data:T,error:any}>):Promise<T> { const {data,error}=await result; if(error) throw new Error(`数据库操作失败 (${error.code||'unknown'})`); return data; }
const encoder = new TextEncoder();
function b64(v:Uint8Array) { return btoa(String.fromCharCode(...v)); }
function un64(v:string) { return Uint8Array.from(atob(v),c=>c.charCodeAt(0)); }
async function key() { const seed=Deno.env.get('FA_ENCRYPTION_KEY'); assert(seed,'后台加密配置尚未完成'); return crypto.subtle.importKey('raw',un64(seed),'AES-GCM',false,['encrypt','decrypt']); }
export async function seal(v:unknown) { const iv=crypto.getRandomValues(new Uint8Array(12)); const bytes=await crypto.subtle.encrypt({name:'AES-GCM',iv},await key(),encoder.encode(JSON.stringify(v))); return b64(iv)+'.'+b64(new Uint8Array(bytes)); }
export async function open(v:string) { const [iv,bytes]=v.split('.'); return JSON.parse(new TextDecoder().decode(await crypto.subtle.decrypt({name:'AES-GCM',iv:un64(iv)},await key(),un64(bytes)))); }
export async function secret(k:string,consume=false) { const v=await checked(db.rpc('fa_secret_get',{k,consume})); return v ? await open(v as string):null; }
export async function saveSecret(k:string,v:unknown,expiry:string|null=null) { await checked(db.rpc('fa_secret_set',{k,v:await seal(v),expiry})); }
export async function digest(value:unknown) { return Array.from(new Uint8Array(await crypto.subtle.digest('SHA-256',encoder.encode(JSON.stringify(value))))).map(v=>v.toString(16).padStart(2,'0')).join(''); }
export async function user(req:Request) { const token=(req.headers.get('authorization')||'').replace(/^Bearer /i,''); assert(token,'请先登录'); const {data,error}=await db.auth.getUser(token); assert(!error&&data.user?.email_confirmed_at,'请先登录并验证邮箱'); return data.user!; }
export async function member(workspace:string,uid:string,roles=['admin','operator','viewer']) { const m=await checked(db.from('fa_members').select('*').eq('workspace_id',workspace).eq('user_id',uid).maybeSingle()); assert(m&&roles.includes(m.role),'当前账号没有此工作区的操作权限'); return m; }
export async function log(workspace:string,actor:string,type:string,detail:unknown={},job:string|null=null) { await checked(db.from('fa_events').insert({workspace_id:workspace,actor_id:actor,event_type:type,detail,job_id:job})); }
export async function feishu(token:string,path:string,body?:unknown) {
 assert(path.startsWith('/open-apis/'),'无效接口路径');
 const response=await fetch('https://open.feishu.cn'+path,{method:body===undefined?'GET':'POST',headers:{Authorization:`Bearer ${token}`,'Content-Type':'application/json'},body:body===undefined?undefined:JSON.stringify(body),signal:AbortSignal.timeout(25000)});
 const data=await response.json();
 assert(response.ok && data.code===0,`飞书接口失败 (${data.code??response.status})，请核对授权、应用权限与表格访问权限`);
 return data.data;
}
export async function accessToken(w:string,uid:string) {
 const k=`user:${w}:${uid}`, c=await secret(k); assert(c,'请先在“飞书授权”连接个人飞书账号');
 if(c.expires_at>Date.now()+120000) return c.access_token;
 const app=await secret(`app:${w}`); assert(app,'管理员尚未配置飞书应用');
 const r=await fetch('https://open.feishu.cn/open-apis/authen/v2/oauth/token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({grant_type:'refresh_token',client_id:app.app_id,client_secret:app.app_secret,refresh_token:c.refresh_token}),signal:AbortSignal.timeout(20000)});
 const t=await r.json(); assert(r.ok&&t.access_token,'飞书授权已过期，请重新连接');
 await saveSecret(k,{...t,refresh_token:t.refresh_token||c.refresh_token,expires_at:Date.now()+t.expires_in*1000}); return t.access_token;
}
export function col(n:number):string { let s='';for(;n;n=Math.floor((n-1)/26))s=String.fromCharCode(65+(n-1)%26)+s; return s; }
export async function resolveLink(token:string,link:string,header=1) {
 const u=new URL(link); assert(u.protocol==='https:'&& /(^|\.)feishu\.cn$/.test(u.hostname),'请填写完整的飞书 HTTPS 链接');
 const m=u.pathname.match(/^\/(wiki|base|sheets)\/([A-Za-z0-9]+)/); assert(m,'仅支持 Wiki、多维表格或电子表格链接');
 let kind=m[1], id=m[2];
 if(kind==='wiki') { const d=await feishu(token,`/open-apis/wiki/v2/spaces/get_node?token=${encodeURIComponent(id)}`); kind=d.node.obj_type==='bitable'?'base':d.node.obj_type; id=d.node.obj_token; }
 if(kind==='base') {
  const tables=await feishu(token,`/open-apis/bitable/v1/apps/${id}/tables?page_size=100`);
  const tableId=u.searchParams.get('table');
  assert(tableId||tables.items?.length===1,'该链接包含多个数据表，请在飞书打开具体数据表后复制带 table= 的链接');
  return {kind:'base',token:id,table:tableId||tables.items[0].table_id,url:link};
 }
 assert(kind==='sheets'||kind==='sheet','该 Wiki 节点不是可读取的表格');
 const data=await feishu(token,`/open-apis/sheets/v3/spreadsheets/${id}/sheets/query`);
 const sid=u.searchParams.get('sheet')||data.sheets?.[0]?.sheet_id; assert(sid,'电子表格没有工作表');
 return {kind:'sheet',token:id,table:sid,url:link,header};
}
export async function fields(token:string,source:any) {
 if(source.kind==='base') {
  const result:any[]=[];let page='';const seen=new Set();
  do { const d=await feishu(token,`/open-apis/bitable/v1/apps/${source.token}/tables/${source.table}/fields?page_size=100${page?'&page_token='+encodeURIComponent(page):''}`); result.push(...d.items); if(!d.has_more) break; assert(d.page_token&&!seen.has(d.page_token),'字段分页异常');seen.add(d.page_token);page=d.page_token; } while(result.length<2000);
  assert(result.length<2000,'字段过多');
  return result.map(f=>({id:f.field_id,name:f.field_name,type:f.type,ui_type:f.ui_type,writable:[1,2,3,4,5,7,13].includes(f.type)&&!['Formula','Lookup','CreatedTime','ModifiedTime','AutoNumber'].includes(f.ui_type)}));
 }
 const meta=await feishu(token,`/open-apis/sheets/v3/spreadsheets/${source.token}/sheets/query`); const s=meta.sheets.find((x:any)=>x.sheet_id===source.table); assert(s,'工作表不存在');
 const width=s.grid_properties.column_count;assert(width>0&&width<=500,'电子表格支持最多 500 列');
 const h=source.header||1; const range=`${source.table}!A${h}:${col(width)}${h}`;
 const d=await feishu(token,`/open-apis/sheets/v2/spreadsheets/${source.token}/values/${encodeURIComponent(range)}?valueRenderOption=ToString`);
 const names=(d.valueRange.values?.[0]||[]).map((v:any,i:number)=>String(v??'').trim()||`未命名列 ${col(i+1)}`);
 return Array.from({length:width},(_,i)=>({id:'sheetcol_'+col(i+1),name:names[i]||`未命名列 ${col(i+1)}`,type:/日期|时间/.test(names[i]||'')?5:1,writable:false,column:i+1,revision:d.revision}));
}
