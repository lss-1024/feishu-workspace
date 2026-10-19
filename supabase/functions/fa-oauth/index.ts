import {callback,site,json,secret,saveSecret,assert} from '../_shared/platform.ts';

Deno.serve(async req=>{
 try {
  const url=new URL(req.url);const state=url.searchParams.get('state');assert(state&&state.length>20,'授权状态无效或已过期');
  const record=await secret(`state:${state}`,true);assert(record,'授权链接已失效，请回到工作区重新连接');
  const code=url.searchParams.get('code');assert(code,'授权未完成，请重新连接');
  const app=await secret(`app:${record.workspace}`);assert(app,'应用配置不存在');
  const response=await fetch('https://open.feishu.cn/open-apis/authen/v2/oauth/token',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({grant_type:'authorization_code',client_id:app.app_id,client_secret:app.app_secret,code,redirect_uri:callback}),signal:AbortSignal.timeout(20000)});
  const token=await response.json();assert(response.ok&&token.access_token&&token.refresh_token,'飞书授权换取失败，请核对应用权限及 offline_access');
  await saveSecret(`user:${record.workspace}:${record.user}`,{...token,expires_at:Date.now()+token.expires_in*1000});
  return new Response(null,{status:303,headers:{Location:site+'?connected=1','Cache-Control':'no-store','Referrer-Policy':'no-referrer'}});
 }catch(e){return json({error:(e as Error).message},400);}
});
