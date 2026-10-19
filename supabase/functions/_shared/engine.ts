// Shared pure semantics for filters, joins and field conversion.
export function scalar(v:any):any {
 if(v&&typeof v==='object'&&!Array.isArray(v)) { if('value' in v) return scalar(v.value); if('text' in v) return v.text; }
 if(Array.isArray(v)) { if(v.every(x=>x?.text!==undefined))return v.map(x=>x.text).join('');return v.map(scalar); }
 return v;
}
export function text(v:any):string { v=scalar(v);return v==null?'':Array.isArray(v)?v.map(text).join(','):String(v); }
export const blank=(v:any)=>!text(v).trim();
export function number(v:any):number { const s=text(v).trim().normalize('NFKC').replace(/,/g,'');if(!/^[+-]?(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?$/.test(s))throw new Error('需要有效数字或数字文本');const n=Number(s);if(!Number.isFinite(n))throw new Error('数字超出范围');return n; }
export function date(v:any):number {
 v=scalar(v);if(Array.isArray(v)&&v.length===1)v=v[0];
 if(typeof v==='number'||/^\d+(?:\.\d+)?$/.test(String(v))) {const n=Number(v); if(n>1e12)return n;if(n>1e9)return n*1000;if(n>1&&n<100000)return Date.UTC(1899,11,30)+Math.round(n*86400000)-8*3600000;}
 const s=text(v).trim().replace(/[年月/]/g,'-').replace(/日/g,'');
 const m=s.match(/^(\d{4})-(\d{1,2})-(\d{1,2})(?:[ T](\d{1,2}):(\d{1,2})(?::(\d{1,2})(?:\.(\d+))?)?)?$/);
 if(m) {const [y,mo,d,h,mi,se]=m.slice(1,7).map(x=>Number(x||0));const t=Date.UTC(y,mo-1,d,h,mi,se)-28800000;const c=new Date(t+28800000);if(c.getUTCFullYear()===y&&c.getUTCMonth()===mo-1&&c.getUTCDate()===d&&h<24&&mi<60&&se<60)return t;}
 if(/T.*(?:Z|[+-]\d\d:\d\d)$/.test(s)) {const t=Date.parse(s);if(Number.isFinite(t))return t;}
 throw new Error('日期无效，请使用完整日期或时间戳');
}
export function day(v:any):string {return new Date(date(v)+28800000).toISOString().slice(0,10);}
export function condition(row:any,c:any,fs:any[]):boolean {
 const f=fs.find(f=>f.id===c.field);if(!f)throw new Error('筛选字段已变更，请刷新字段');
 const v=scalar(row[f.id]); if(c.op==='empty')return blank(v);if(c.op==='not_empty')return !blank(v);if(blank(v))return false;
 if(c.op==='yesterday'||c.op==='today'||c.op==='date_on'||c.op==='date_range') {
  let a=c.value,b=c.end||a;if(c.op==='yesterday'||c.op==='today') a=b=new Date(Date.now()+28800000-(c.op==='yesterday'?86400000:0)).toISOString().slice(0,10);
  try {const d=day(v);return d>=a&&d<=b;}catch{return false;}
 }
 let a:any=text(v).trim(),b:any=text(c.value).trim();if(f.type===2){a=number(v);b=number(c.value);}
 return c.op==='eq'?a===b:c.op==='ne'?a!==b:c.op==='contains'?a.includes(b):c.op==='not_contains'?!a.includes(b):c.op==='gt'?a>b:c.op==='gte'?a>=b:c.op==='lt'?a<b:c.op==='lte'?a<=b:false;
}
export function matches(row:any,conditions:any[],mode:string,fs:any[]) {return !conditions.length||(mode==='any'?conditions.some(c=>condition(row,c,fs)):conditions.every(c=>condition(row,c,fs)));}
export function convert(value:any,field:any):any {
 if(!field.writable)throw new Error(`${field.name} 是公式、计算或未支持的字段，不能写入`);
 const v=scalar(value); if(blank(v))return null;
 if(field.type===2)return number(v);if(field.type===5)return date(v);
 if(field.type===7) {if(typeof v==='boolean')return v;const s=text(v).trim().toLowerCase();if(['1','true','是'].includes(s))return true;if(['0','false','否'].includes(s))return false;throw new Error('复选框需要 true/false');}
 if(field.type===4)return Array.isArray(v)?v.map(text):text(v).split(/[,，]/).map(s=>s.trim()).filter(Boolean);
 if(typeof v==='object')throw new Error('复杂单元格不能转换为文本');return text(v);
}
export function equal(a:any,b:any,mode='text') {if(blank(a)&&blank(b))return true;if(blank(a)||blank(b))return false;return mode==='number'?number(a)===number(b):mode==='date'?date(a)===date(b):text(a).trim()===text(b).trim();}
export function apiFilter(conditions:any[],mode:string,fs:any[]) {
 const ops:any={eq:'is',ne:'isNot',contains:'contains',not_contains:'doesNotContain',empty:'isEmpty',not_empty:'isNotEmpty',gt:'isGreater',gte:'isGreaterEqual',lt:'isLess',lte:'isLessEqual'};
 // Unsupported predicates are evaluated locally after a complete scoped read.
 // In OR mode no partial pushdown is safe.
 const supported=conditions.filter(c=>{
  const f=fs.find(f=>f.id===c.field);if(!f||!ops[c.op])return false;
  if(f.type===2)return true;
  // Feishu isEmpty does not include whitespace-only strings, while our empty
  // check does. Trimmed equality can also match rows missed by exact API is.
  // Only predicates proven to be safe supersets are pushed for text fields.
  return [1,3,13].includes(f.type)&&['contains','not_empty','ne'].includes(c.op);
 });
 if(mode==='any'&&supported.length!==conditions.length)return null;
 if(!supported.length)return null;
 return {conjunction:mode==='any'?'or':'and',conditions:supported.map(c=>({field_name:fs.find(f=>f.id===c.field).name,operator:ops[c.op],value:['empty','not_empty'].includes(c.op)?[]:[text(c.value).trim()]}))};
}
