import {db,json,cors,assert,checked,user,member,secret,saveSecret,log,callback,accessToken,resolveLink,fields,feishu,col,digest} from '../_shared/platform.ts';
import {scalar,text,blank,matches,apiFilter,convert,equal} from '../_shared/engine.ts';
import {preview,confirm,writeStep} from '../_shared/transfer.ts';

const now=()=>new Date().toISOString();
async function table(id:string,w:string){const t=await checked(db.from('fa_tables').select('*').eq('id',id).eq('workspace_id',w).is('archived_at',null).single());assert(t,'表格不存在或已归档');return t;}
async function job(id:string,w:string){return await checked(db.from('fa_jobs').select('*').eq('id',id).eq('workspace_id',w).single());}
async function fresh(t:any,token:string){return await fields(token,t.source);}
async function updateJob(id:string,values:any){return await checked(db.from('fa_jobs').update({...values,updated_at:now()}).eq('id',id).select().single());}

Deno.serve(async req=>{
 if(req.method==='OPTIONS')return new Response('ok',{headers:cors});
 if(req.method!=='POST')return json({error:'仅支持 POST'},405);
 let uid='',w='',claimed:any=null;
 try {
  const u=await user(req);uid=u.id;
  assert(Number(req.headers.get('content-length')||0)<10*1024*1024,'请求过大');
  const body=await req.text();assert(body.length<10*1024*1024,'请求过大');const b=JSON.parse(body);const a=b.action;w=b.workspace;
  if(a==='bootstrap') {
   const invites=await checked(db.from('fa_invites').select('*').eq('email',u.email!.toLowerCase()));
   for(const i of invites||[]) {await checked(db.from('fa_members').upsert({workspace_id:i.workspace_id,user_id:uid,role:i.role}));await checked(db.from('fa_invites').delete().eq('workspace_id',i.workspace_id).eq('email',i.email));}
   const memberships=await checked(db.from('fa_members').select('workspace_id,role,fa_workspaces(id,name)').eq('user_id',uid));return json({email:u.email,memberships});
  }
  const role=(await member(w,uid)).role;
  const edit=()=>assert(['admin','operator'].includes(role),'查看者不能修改工作区');
  const admin=()=>assert(role==='admin','仅管理员可操作');
  if(a==='overview') {
   const tables=await checked(db.from('fa_tables').select('*').eq('workspace_id',w).order('updated_at',{ascending:false}));
   const profiles=await checked(db.from('fa_profiles').select('*').eq('workspace_id',w));
   const jobs=await checked(db.from('fa_jobs').select('id,table_id,action,state,diagnostics,created_at,updated_at').eq('workspace_id',w).order('created_at',{ascending:false}).limit(40));
   return json({tables,profiles,jobs,role});
  }
  if(a==='auth_status') {const app=await secret(`app:${w}`), c=await secret(`user:${w}:${uid}`);return json({configured:!!app,app_id:app?.app_id||'',connected:!!c,callback,scopes:app?.scopes||'',role});}
  if(a==='app_save') {admin();assert(/^cli_[a-zA-Z0-9]+$/.test(b.app_id),'应用 ID 格式不正确');assert(typeof b.app_secret==='string'&&b.app_secret.length>=16,'请填写 App Secret');const scopes=text(b.scopes).trim();assert(scopes.includes('offline_access'),'需要 offline_access 以便刷新授权');await saveSecret(`app:${w}`,{app_id:b.app_id,app_secret:b.app_secret,scopes});await log(w,uid,'app_config_updated');return json({ok:true});}
  if(a==='auth_start') {edit();const app=await secret(`app:${w}`);assert(app,'管理员尚未配置飞书应用');const state=crypto.randomUUID()+crypto.randomUUID();await saveSecret(`state:${state}`,{workspace:w,user:uid},new Date(Date.now()+600000).toISOString());const url=new URL('https://accounts.feishu.cn/open-apis/authen/v1/authorize');url.search=new URLSearchParams({client_id:app.app_id,redirect_uri:callback,response_type:'code',scope:app.scopes,state}).toString();return json({url:url.href});}
  if(a==='auth_disconnect') {await saveSecret(`user:${w}:${uid}`,null,new Date(0).toISOString());await log(w,uid,'feishu_disconnected');return json({ok:true});}
  if(a==='members') {admin();return json({members:await checked(db.from('fa_members').select('*').eq('workspace_id',w)),invites:await checked(db.from('fa_invites').select('*').eq('workspace_id',w))});}
  if(a==='invite') {admin();const email=text(b.email).trim().toLowerCase();assert(/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email),'邮箱格式无效');assert(['admin','operator','viewer'].includes(b.role),'角色无效');await checked(db.from('fa_invites').upsert({workspace_id:w,email,role:b.role}));await log(w,uid,'member_invited',{email,role:b.role});return json({ok:true});}
  if(a==='remove_member') {admin();assert(b.user_id!==uid,'不能移除自己的管理员权限');await checked(db.from('fa_members').delete().eq('workspace_id',w).eq('user_id',b.user_id));await log(w,uid,'member_removed',{user_id:b.user_id});return json({ok:true});}
  if(a==='cancel_invite') {admin();await checked(db.from('fa_invites').delete().eq('workspace_id',w).eq('email',b.email));return json({ok:true});}
  if(a==='events')return json({events:await checked(db.from('fa_events').select('*').eq('workspace_id',w).order('created_at',{ascending:false}).limit(100))});
  if(a==='table_save'||a==='fields_refresh') {
   edit();const token=await accessToken(w,uid);let t=b.id?await table(b.id,w):null;
   const source=a==='fields_refresh'?t.source:await resolveLink(token,b.url,Number(b.header||1));const schema=await fields(token,source);
   if(a==='fields_refresh'){await checked(db.from('fa_tables').update({config:{...t.config,fields:schema,fields_at:now()},version:t.version+1,updated_at:now()}).eq('id',t.id).eq('version',t.version));return json({fields:schema});}
   const changed=t&&(t.source.token!==source.token||t.source.table!==source.table||t.source.kind!==source.kind);
   assert(!changed||b.confirm_relink===true,'此链接对应不同表格。确认后将清除旧表的模板、规则和预览，请勾选更换表格确认');
   assert(text(b.name).trim().length>0&&text(b.name).length<=100,'任务名称长度应为 1–100');
   const roles=(b.roles||[]).filter((r:string)=>['audit','source','target'].includes(r));assert(roles.length,'请至少选择一种用途');
   const values={workspace_id:w,name:text(b.name).trim(),source,roles,config:{...(changed?{}:t?.config||{}),fields:schema,fields_at:now()},version:(t?.version||0)+1,updated_at:now()};
   const saved=t?await checked(db.from('fa_tables').update(values).eq('id',t.id).eq('version',b.version).select().single()):await checked(db.from('fa_tables').insert(values).select().single());
   if(changed) {await checked(db.from('fa_profiles').delete().eq('workspace_id',w).eq('table_id',t.id));await checked(db.from('fa_jobs').update({state:'cancelled'}).eq('workspace_id',w).eq('table_id',t.id).in('state',['queued','preview']));}
   await log(w,uid,t?'table_updated':'table_added',{table_id:saved.id,source_kind:source.kind,field_count:schema.length});return json({table:saved});
  }
  if(a==='table_archive') {edit();await table(b.id,w);await checked(db.from('fa_tables').update({archived_at:now(),updated_at:now()}).eq('id',b.id).eq('workspace_id',w));await checked(db.from('fa_jobs').update({state:'cancelled'}).eq('workspace_id',w).eq('table_id',b.id).in('state',['queued','preview']));await log(w,uid,'table_archived',{table_id:b.id});return json({ok:true});}
  if(a==='table_restore') {edit();await checked(db.from('fa_tables').update({archived_at:null,updated_at:now()}).eq('id',b.id).eq('workspace_id',w));return json({ok:true});}
  if(a==='profile_save') {edit();await table(b.table_id,w);assert(['import_mapping','bridge_mapping','bridge_plan','audit_rules'].includes(b.kind),'模板类型无效');assert(text(b.name).trim(),'请填写模板名称');const v={workspace_id:w,table_id:b.table_id,name:text(b.name).slice(0,100),kind:b.kind,payload:b.payload,version:(b.version||0)+1,updated_at:now()};return json({profile:b.id?await checked(db.from('fa_profiles').update(v).eq('id',b.id).eq('workspace_id',w).eq('version',b.version).select().single()):await checked(db.from('fa_profiles').insert(v).select().single())});}
  if(a==='profile_delete') {edit();await checked(db.from('fa_profiles').delete().eq('id',b.id).eq('workspace_id',w));return json({ok:true});}
  if(a==='read_start') {
   edit();const t=await table(b.table_id,w),token=await accessToken(w,uid),fs=await fresh(t,token);assert((b.conditions||[]).length<=40,'最多支持 40 条条件');
   for(const c of b.conditions||[])assert(fs.some((f:any)=>f.id===c.field),'筛选列已变更，请刷新字段');
   const cp:any={source:t.source,fields:fs,revision:fs[0]?.revision,conditions:b.conditions||[],mode:b.mode==='any'?'any':'all',rows:[],page:'',next_row:(t.source.header||1)+1,requests:0,scanned:0,table_version:t.version};
   if(t.source.kind==='sheet'){const m=await feishu(token,`/open-apis/sheets/v3/spreadsheets/${t.source.token}/sheets/query`);const s=m.sheets.find((x:any)=>x.sheet_id===t.source.table);assert(s,'工作表不存在');cp.row_count=s.grid_properties.row_count;assert(cp.row_count*fs.length<=2000000,'电子表格超过 200 万单元格，请拆分后读取');cp.phase=cp.conditions.length?'scan':'full';cp.scan_fields=[...new Set(cp.conditions.map((c:any)=>c.field))];cp.scan_index=0;cp.partial={};cp.candidates=[];cp.full_index=0;}
   const j=await checked(db.from('fa_jobs').insert({workspace_id:w,table_id:t.id,requested_by:uid,action:'read',checkpoint:cp}).select('id,state').single());return json({job:j});
  }
  if(a==='read_step') {
   edit();const j=await job(b.id,w);assert(j.action==='read'&&j.state==='queued','该读取已完成、正在执行或需要重新读取');
   const lease=await checked(db.rpc('fa_claim_job',{j:j.id,expected:'queued',next_state:'running'}));assert(lease?.length,'另一个操作正在读取');claimed=j;
   const cp=j.checkpoint,t=await table(j.table_id,w);assert(t.version===cp.table_version,'任务表格已修改，请重新读取');const token=await accessToken(w,uid);let done=false;
   if(cp.source.kind==='base') {
    const filter=apiFilter(cp.conditions,cp.mode,cp.fields);const query=new URLSearchParams({page_size:'500'});if(cp.page)query.set('page_token',cp.page);
    const d=await feishu(token,`/open-apis/bitable/v1/apps/${cp.source.token}/tables/${cp.source.table}/records/search?${query}`,{automatic_fields:false,...(filter?{filter}:{})});
    assert(Array.isArray(d.items)&&typeof d.has_more==='boolean','飞书返回分页结构无效');
    assert(Number.isInteger(d.total)&&d.total>=0,'飞书分页总数缺失');if(cp.total!==undefined)assert(cp.total===d.total,'读取期间总数发生变化，请重新读取');cp.total=d.total;
    const seen=new Set(cp.seen_ids||[]);
    for(const r of d.items){assert(!seen.has(r.record_id),'分页记录重复，请重新读取');assert(Object.keys(r.fields).every(name=>cp.fields.some((f:any)=>f.name===name)),'读取过程中表头发生变化，请重新读取');seen.add(r.record_id);const values=Object.fromEntries(cp.fields.map((f:any)=>[f.id,scalar(r.fields[f.name]??null)]));cp.scanned++;if(matches(values,cp.conditions,cp.mode,cp.fields))cp.rows.push({record_id:r.record_id,values});}
    cp.seen_ids=[...seen];done=!d.has_more;if(done)assert(cp.scanned===cp.total,'完整分页条数与总数不一致');assert(done||(d.page_token&&d.page_token!==cp.page),'分页游标没有推进');cp.page=d.page_token||'';cp.transport=filter?'飞书接口筛选后分页读取':'完整分页后本地筛选';
   }else{
    const width=cp.fields.length,block=Math.min(50,Math.max(1,Math.floor(5000/width))),first=(cp.source.header||1)+1;
    const getRange=async(range:string)=>{const d=await feishu(token,`/open-apis/sheets/v2/spreadsheets/${cp.source.token}/values/${encodeURIComponent(range)}?valueRenderOption=UnformattedValue&dateTimeRenderOption=SerialNumber`);assert(d.revision!==undefined,'电子表格未返回版本');if(cp.revision!==undefined)assert(cp.revision===d.revision,'电子表格版本变化，请重新读取');cp.revision=d.revision;return d.valueRange?.values||[];};
    if(cp.phase==='scan'){
     const f=cp.fields.find((f:any)=>f.id===cp.scan_fields[cp.scan_index]),end=Math.min(cp.next_row+999,cp.row_count);
     if(cp.next_row<=end){const rows=await getRange(`${cp.source.table}!${col(f.column)}${cp.next_row}:${col(f.column)}${end}`);for(let i=0;i<=end-cp.next_row;i++){const n=cp.next_row+i;cp.partial[n]||={};cp.partial[n][f.id]=scalar(rows[i]?.[0]??null);}}
     cp.scan_index++;
     if(cp.scan_index>=cp.scan_fields.length){for(let n=cp.next_row;n<=end;n++){if(matches(cp.partial[n],cp.conditions,cp.mode,cp.fields))cp.candidates.push(n);}cp.scanned+=Math.max(0,end-cp.next_row+1);cp.partial={};cp.scan_index=0;cp.next_row=end+1;}
     if(cp.next_row>cp.row_count){cp.windows=[...new Set(cp.candidates.map((n:number)=>Math.floor((n-first)/block)))].map((n:any)=>[first+n*block,Math.min(first+(n+1)*block-1,cp.row_count)]);cp.phase='full';done=cp.windows.length===0;}
    }else{
     const start=cp.conditions.length?cp.windows[cp.full_index]?.[0]:cp.next_row,end=cp.conditions.length?cp.windows[cp.full_index]?.[1]:Math.min(start+block-1,cp.row_count);
     if(start&&start<=end){const rows=await getRange(`${cp.source.table}!A${start}:${col(width)}${end}`);const candidates=new Set(cp.candidates);for(let i=0;i<rows.length;i++){const n=start+i;if(cp.conditions.length&&!candidates.has(n))continue;const values=Object.fromEntries(cp.fields.map((f:any,k:number)=>[f.id,scalar(rows[i][k]??null)]));if(!cp.conditions.length)cp.scanned++;if(Object.values(values).some(v=>!blank(v))&&matches(values,cp.conditions,cp.mode,cp.fields))cp.rows.push({record_id:'sheetrow_'+n,values});}}
     if(cp.conditions.length){cp.full_index++;done=cp.full_index>=cp.windows.length;}else{cp.next_row=end+1;done=cp.next_row>cp.row_count;}
    }
    cp.transport=cp.conditions.length?'Sheets 先扫描筛选列，再补读命中行全部字段':'Sheets 无筛选，批量读取全部字段';
    if(done){const h=cp.source.header||1;await getRange(`${cp.source.table}!A${h}:A${h}`);cp.requests++;}
   }
   cp.requests++;assert(cp.rows.length<=50000,'本次读取超过 5 万条，请缩小条件');
   const diagnostics={rows:cp.rows.length,scanned:cp.scanned,requests:cp.requests,complete:done,transport:cp.transport,consistency:cp.source.kind==='base'?'跨页非事务快照':'版本一致性校验'};
   await updateJob(j.id,{state:done?'complete':'queued',checkpoint:cp,diagnostics});claimed=null;return json({id:j.id,state:done?'complete':'queued',diagnostics});
  }
  if(a==='job_data') {return json({job:await job(b.id,w)});}
  if(a==='audit') {
   edit();const j=await job(b.id,w);assert(j.action==='read'&&j.state==='complete','先完整读取检查范围');const cp=j.checkpoint;const f=cp.fields.find((f:any)=>f.id===b.field);assert(f,'检查字段不存在');const issues=cp.rows.filter((r:any)=>b.check==='allowed'?!((b.allowed||[]).map(text).includes(text(r.values[f.id]))):blank(r.values[f.id]));return json({issues,scope_rows:cp.rows.length,field:f,read_at:j.updated_at});
  }
  if(a==='preview') {edit();const t=await table(b.table_id,w);const token=await accessToken(w,uid);return json({job:await preview(w,uid,b,t,token,job)});}
  if(a==='confirm') {edit();const j=await job(b.id,w);return json({job:await confirm(w,uid,j,b.digest)});}
  if(a==='write_step') {
   edit();const j=await job(b.id,w);assert(j.action==='write'&&j.state==='queued'&&j.confirmed_by===uid,'此写入不可执行或需要人工核查');
   const lease=await checked(db.rpc('fa_claim_job',{j:j.id,expected:'queued',next_state:'running'}));assert(lease?.length,'另一个操作正在执行');claimed=j;
   const t=await table(j.table_id,w),token=await accessToken(w,uid);const result=await writeStep(j,token,t);await updateJob(j.id,result);claimed=null;await log(w,uid,'write_batch_verified',{written:result.diagnostics.written,verified:result.diagnostics.verified},j.id);return json({id:j.id,state:result.state,diagnostics:result.diagnostics});
  }
  throw new Error('当前操作尚未接入云端');
 }catch(e){if(claimed){await updateJob(claimed.id,{state:claimed.action==='write'?'needs_review':'failed',diagnostics:{...claimed.diagnostics,error:(e as Error).message}}).catch(()=>{});}return json({error:(e as Error).message},400);}
});
