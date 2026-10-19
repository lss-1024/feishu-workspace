import {assert,checked,db,fields,feishu,digest,log} from './platform.ts';
import {blank,convert,equal,text,scalar} from './engine.ts';

export async function preview(w:string,uid:string,b:any,target:any,token:string,load:(id:string,w:string)=>Promise<any>) {
 const fs=await fields(token,target.source);assert(target.source.kind==='base','目前仅允许写入多维表格');
 let rows:any[],sourceFields:any[];
 if(b.source_job){const j=await load(b.source_job,w);assert(j.action==='read'&&j.state==='complete','来源尚未完整读取');rows=j.checkpoint.rows;sourceFields=j.checkpoint.fields;}
 else{assert(Array.isArray(b.rows)&&b.rows.length<=20000&&Array.isArray(b.source_fields),'上传文件结构无效或超过 2 万行');rows=b.rows;sourceFields=b.source_fields;}
 const maps=(b.mapping||[]).filter((m:any)=>m.target);assert(maps.length>0&&maps.length<=200,'请选择 1–200 个写入字段');
 assert(new Set(maps.map((m:any)=>m.target)).size===maps.length,'同一个目标字段不能重复映射');
 for(const m of maps){assert(sourceFields.some(f=>f.id===m.source),'来源映射字段不存在');assert(fs.some(f=>f.id===m.target&&f.writable),'目标字段已变更或不允许写入，请刷新字段');}
 const mode=b.mode==='update'?'update':'append',plan:any[]=[],stats:any={source_rows:rows.length,target_rows:0,unmatched:0,empty_keys:0,unchanged:0,comparison_skipped:0};
 let targets:any[]=[],targetFields:any[]=[],pairs=b.pairs||[];
 if(mode==='update'){
  const j=await load(b.target_job,w);assert(j.action==='read'&&j.state==='complete'&&j.table_id===target.id,'请先读取目标更正范围');targets=j.checkpoint.rows;targetFields=j.checkpoint.fields;stats.target_rows=targets.length;
  assert(pairs.length>0&&pairs.length<=5,'请选择 1–5 组匹配字段');
  for(const p of pairs)assert(sourceFields.some(f=>f.id===p.source)&&fs.some(f=>f.id===p.target),'匹配字段无效');
 }
 const key=(r:any,side:string)=>{
  const vals=pairs.map((p:any)=>{const v=r.values[p[side]];if(blank(v))return null;const f=fs.find(f=>f.id===p.target);return f?.type===2?convert(v,f):text(v).trim();});return vals.some(v=>v===null)?null:JSON.stringify(vals);
 };
 const index=new Map<string,any[]>(),sourceKeys=new Set<string>();
 for(const r of targets){const k=key(r,'target');if(k)index.set(k,[...(index.get(k)||[]),r]);}
 const comparisons=b.comparisons||[];assert(comparisons.length<=20,'最多支持 20 条列比对');
 for(const c of comparisons)assert(sourceFields.some(f=>f.id===c.source)&&fs.some(f=>f.id===c.target)&&['eq','ne','target_empty','empty_or_ne'].includes(c.op),'列比对条件无效');
 for(const r of rows){
  let hits:any[]=[null];
  if(mode==='update') {const k=key(r,'source');if(!k){stats.empty_keys++;continue;}assert(!sourceKeys.has(k),'来源匹配键重复，请先处理重复记录');sourceKeys.add(k);hits=index.get(k)||[];if(!hits.length){stats.unmatched++;continue;}assert(hits.length===1||b.allow_multiple===true,'目标匹配键重复，请处理重复或明确允许同值更正多条目标');}
  for(const hit of hits){
   if(hit&&comparisons.length){const results=comparisons.map((c:any)=>{const a=r.values[c.source],v=hit.values[c.target];return c.op==='target_empty'?blank(v):c.op==='empty_or_ne'?blank(v)||!equal(a,v,c.type):c.op==='eq'?equal(a,v,c.type):!equal(a,v,c.type);});if(!(b.comparison_mode==='any'?results.some(Boolean):results.every(Boolean))){stats.comparison_skipped++;continue;}}
   const values:any={},old:any={};
   for(const m of maps){const f=fs.find(f=>f.id===m.target);const raw=r.values[m.source];if(blank(raw)&&!b.clear_empty)continue;const v=convert(raw,f);if(hit&&equal(v,hit.values[f.id],f.type===2?'number':f.type===5?'date':'text'))continue;values[f.name]=v;old[f.name]=hit?.values[f.id]??null;}
   if(!Object.keys(values).length){stats.unchanged++;continue;}
   plan.push({record_id:hit?.record_id||null,fields:values,old,source_record:r.record_id});
  }
 }
 assert(plan.length<=5000,'本次预览超过 5000 条，请缩小范围分批处理');
 const checkpoint={mode,source:target.source,target_version:target.version,fields:fs,plan,cursor:0,verified:0};
 const hash=await digest(checkpoint);const j=await checked(db.from('fa_jobs').insert({workspace_id:w,table_id:target.id,requested_by:uid,action:mode==='update'?'preview_update':'preview_append',state:plan.length?'preview':'no_changes',plan_digest:hash,checkpoint,diagnostics:{...stats,planned:plan.length}}).select().single());
 await log(w,uid,'write_preview_created',{job_id:j.id,mode,planned:plan.length,source_rows:rows.length,target_rows:targets.length},j.id);return j;
}

export async function confirm(w:string,uid:string,j:any,hash:string){
 assert(j.state==='preview'&&['preview_append','preview_update'].includes(j.action),'此预览已确认或已过期，请重新生成');
 assert(j.requested_by===uid,'请由生成预览的操作者确认');assert(hash===j.plan_digest&&hash===await digest(j.checkpoint),'预览摘要不一致');
 assert(Date.now()-Date.parse(j.created_at)<30*60000,'预览已超过 30 分钟，请重新生成');
 const claimed=await checked(db.rpc('fa_claim_job',{j:j.id,expected:'preview',next_state:'running'}));assert(claimed.length,'此预览已被其他操作确认');
 await checked(db.from('fa_jobs').update({action:'write',state:'queued',confirmed_by:uid,confirmed_at:new Date().toISOString()}).eq('id',j.id));
 await log(w,uid,'write_confirmed',{digest:hash,count:j.checkpoint.plan.length},j.id);return {id:j.id,state:'queued'};
}

export async function writeStep(j:any,token:string,target:any){
 const cp=j.checkpoint;assert(target.version===cp.target_version,'目标任务已修改，请停止并重新预览');
 const schema=await fields(token,target.source);
 for(const old of cp.fields){const f=schema.find(f=>f.id===old.id);assert(f&&f.name===old.name&&f.type===old.type&&f.writable===old.writable,'飞书表头或字段类型发生变化，请重新预览');}
 const batch=cp.plan.slice(cp.cursor,cp.cursor+5);assert(batch.length,'写入已完成');
 cp.inflight={start:cp.cursor,count:batch.length,at:new Date().toISOString(),target_record_ids:batch.map((p:any)=>p.record_id)};
 await checked(db.from('fa_jobs').update({checkpoint:cp,updated_at:new Date().toISOString()}).eq('id',j.id));
 const base=`/open-apis/bitable/v1/apps/${target.source.token}/tables/${target.source.table}/records`;
 if(cp.mode==='update') for(const p of batch){const d=await feishu(token,`${base}/${p.record_id}`);for(const [name,v] of Object.entries(p.old)){const f=schema.find(f=>f.name===name);assert(equal(v,scalar(d.record.fields[name]??null),f?.type===2?'number':f?.type===5?'date':'text'),`目标记录已变更，停止写入 (${p.record_id})`);}}
 // Any exception after this point is uncertain: caller marks needs_review, never retries.
 const result=await feishu(token,`${base}/${cp.mode==='update'?'batch_update':'batch_create'}`,{records:batch.map((p:any)=>({...cp.mode==='update'?{record_id:p.record_id}:{},fields:p.fields}))});
 assert(Array.isArray(result.records)&&result.records.length===batch.length,'飞书写入返回数量不符，请核查');
 cp.last_result_ids=result.records.map((r:any)=>r.record_id);
 await checked(db.from('fa_jobs').update({checkpoint:cp,updated_at:new Date().toISOString()}).eq('id',j.id));
 for(let i=0;i<batch.length;i++){const id=cp.mode==='update'?batch[i].record_id:result.records[i].record_id;const d=await feishu(token,`${base}/${id}`);for(const [name,v] of Object.entries(batch[i].fields)){const f=schema.find(f=>f.name===name);assert(equal(v,scalar(d.record.fields[name]??null),f?.type===2?'number':f?.type===5?'date':'text'),`写入回读不一致，请核查 (${id})`);}}
 cp.cursor+=batch.length;cp.verified+=batch.length;cp.inflight=null;return {checkpoint:cp,state:cp.cursor===cp.plan.length?'complete':'queued',diagnostics:{...j.diagnostics,written:cp.cursor,verified:cp.verified}};
}
