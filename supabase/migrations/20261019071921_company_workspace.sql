-- Company workspace foundation, isolated from the reminder application.
-- Only fa_* objects are added. No reminder table or existing bucket is changed.
begin;
create schema if not exists fa_private;
revoke all on schema fa_private from public, anon, authenticated;

create table if not exists public.fa_workspaces (
 id uuid primary key default gen_random_uuid(),
 name text not null check(length(name) between 1 and 100),
 created_by uuid not null references auth.users(id),
 created_at timestamptz not null default now()
);
create table if not exists public.fa_members (
 workspace_id uuid not null references public.fa_workspaces(id),
 user_id uuid not null references auth.users(id),
 role text not null check(role in ('admin','operator','viewer')),
 created_at timestamptz not null default now(),
 primary key(workspace_id,user_id)
);
-- Credential ciphertext is backend-only, never exposed through public tables.
create table if not exists fa_private.feishu_credentials (
 workspace_id uuid not null references public.fa_workspaces(id),
 user_id uuid not null references auth.users(id),
 encrypted_payload text not null,
 expires_at timestamptz not null,
 updated_at timestamptz not null default now(),
 primary key(workspace_id,user_id)
);
create table if not exists public.fa_tables (
 id uuid primary key default gen_random_uuid(),
 workspace_id uuid not null references public.fa_workspaces(id),
 name text not null check(length(name) between 1 and 100),
 source jsonb not null,
 roles text[] not null default array['audit','source','target'],
 config jsonb not null default '{}'::jsonb,
 version bigint not null default 1,
 archived_at timestamptz,
 updated_at timestamptz not null default now(),
 unique(workspace_id,id),
 check(roles <@ array['audit','source','target']::text[] and cardinality(roles)>0)
);
create table if not exists public.fa_profiles (
 id uuid primary key default gen_random_uuid(),
 workspace_id uuid not null references public.fa_workspaces(id),
 table_id uuid not null,
 name text not null check(length(name) between 1 and 100),
 kind text not null check(kind in ('import_mapping','bridge_mapping','bridge_plan','audit_rules')),
 payload jsonb not null,
 version bigint not null default 1,
 updated_at timestamptz not null default now(),
 foreign key(workspace_id,table_id) references public.fa_tables(workspace_id,id)
);
-- Durable checkpoints permit short bounded Edge invocations, not one long request.
create table if not exists public.fa_jobs (
 id uuid primary key default gen_random_uuid(),
 workspace_id uuid not null references public.fa_workspaces(id),
 table_id uuid not null,
 requested_by uuid not null references auth.users(id),
 action text not null check(action in ('read','audit','preview_append','preview_update','write')),
 state text not null default 'queued' check(state in ('queued','running','preview','no_changes','complete','failed','cancelled','needs_review')),
 plan_digest text,
 confirmed_by uuid references auth.users(id),
 confirmed_at timestamptz,
 checkpoint jsonb not null default '{}'::jsonb,
 diagnostics jsonb not null default '{}'::jsonb,
 lease_until timestamptz,
 created_at timestamptz not null default now(),
 updated_at timestamptz not null default now(),
 foreign key(workspace_id,table_id) references public.fa_tables(workspace_id,id),
 check(action <> 'write' or (confirmed_by is not null and confirmed_at is not null and plan_digest is not null))
);
create table if not exists public.fa_events (
 id bigint generated always as identity primary key,
 workspace_id uuid not null references public.fa_workspaces(id),
 actor_id uuid references auth.users(id),
 job_id uuid references public.fa_jobs(id),
 event_type text not null,
 detail jsonb not null default '{}'::jsonb,
 created_at timestamptz not null default now()
);

-- Security-definer membership lookup avoids recursive policies on fa_members.
create or replace function fa_private.has_role(w uuid, wanted text[])
returns boolean language sql stable security definer set search_path=''
as $$ select exists(select 1 from public.fa_members m
 where m.workspace_id=w and m.user_id=(select auth.uid()) and m.role=any(wanted)); $$;
revoke all on function fa_private.has_role(uuid,text[]) from public;
grant usage on schema fa_private to authenticated;
grant execute on function fa_private.has_role(uuid,text[]) to authenticated;
revoke all on fa_private.feishu_credentials from public, anon, authenticated;
grant usage on schema fa_private to service_role;
grant all on fa_private.feishu_credentials to service_role;

alter table fa_private.feishu_credentials enable row level security;
alter table public.fa_workspaces enable row level security;
alter table public.fa_members enable row level security;
alter table public.fa_tables enable row level security;
alter table public.fa_profiles enable row level security;
alter table public.fa_jobs enable row level security;
alter table public.fa_events enable row level security;
revoke all on public.fa_workspaces,public.fa_members,public.fa_tables,public.fa_profiles,public.fa_jobs,public.fa_events from anon,authenticated;
-- Mutations go through the authenticated Edge API, with role/version checks and
-- append-only operator logs. Clients cannot forge membership or confirmed writes.
grant select on public.fa_workspaces,public.fa_members,public.fa_tables,public.fa_profiles,public.fa_jobs,public.fa_events to authenticated;
grant all on public.fa_workspaces,public.fa_members,public.fa_tables,public.fa_profiles,public.fa_jobs,public.fa_events to service_role;
grant usage,select on sequence public.fa_events_id_seq to service_role;
create policy fa_workspace_read on public.fa_workspaces for select to authenticated
 using(fa_private.has_role(id,array['admin','operator','viewer']));
create policy fa_member_read on public.fa_members for select to authenticated
 using(fa_private.has_role(workspace_id,array['admin','operator','viewer']));
create policy fa_table_read on public.fa_tables for select to authenticated
 using(fa_private.has_role(workspace_id,array['admin','operator','viewer']));
create policy fa_profile_read on public.fa_profiles for select to authenticated
 using(fa_private.has_role(workspace_id,array['admin','operator','viewer']));
create policy fa_job_read on public.fa_jobs for select to authenticated
 using(fa_private.has_role(workspace_id,array['admin','operator','viewer']));
create policy fa_event_read on public.fa_events for select to authenticated
 using(fa_private.has_role(workspace_id,array['admin','operator','viewer']));
create index if not exists fa_members_user on public.fa_members(user_id,workspace_id);
create index if not exists fa_profiles_workspace on public.fa_profiles(workspace_id,table_id);
create index if not exists fa_jobs_workspace on public.fa_jobs(workspace_id,created_at desc);
create index if not exists fa_events_workspace on public.fa_events(workspace_id,created_at desc);
create index if not exists fa_jobs_queue on public.fa_jobs(state,lease_until,created_at);
create index if not exists fa_tables_workspace on public.fa_tables(workspace_id,archived_at);
insert into storage.buckets(id,name,public,file_size_limit)
 values('fa-workspace-files','fa-workspace-files',false,20971520)
 on conflict(id) do nothing;
-- Private files are delivered with short-lived signed URLs only after Edge membership checks.
create table fa_private.secrets (
 key text primary key,
 ciphertext text not null,
 expires_at timestamptz,
 updated_at timestamptz not null default now()
);
alter table fa_private.secrets enable row level security;
revoke all on fa_private.secrets from public,anon,authenticated;
grant all on fa_private.secrets to service_role;
create function public.fa_secret_get(k text, consume boolean default false)
returns text language plpgsql security definer set search_path='' as $$
declare v text;
begin
 if consume then
  delete from fa_private.secrets where key=k and (expires_at is null or expires_at>now()) returning ciphertext into v;
 else
  select ciphertext into v from fa_private.secrets where key=k and (expires_at is null or expires_at>now());
 end if;
 return v;
end $$;
create function public.fa_secret_set(k text,v text,expiry timestamptz default null)
returns void language sql security definer set search_path='' as $$
 insert into fa_private.secrets(key,ciphertext,expires_at) values(k,v,expiry)
 on conflict(key) do update set ciphertext=excluded.ciphertext,expires_at=excluded.expires_at,updated_at=now();
$$;
revoke all on function public.fa_secret_get(text,boolean),public.fa_secret_set(text,text,timestamptz) from public,anon,authenticated;
grant execute on function public.fa_secret_get(text,boolean),public.fa_secret_set(text,text,timestamptz) to service_role;

create table public.fa_invites (
 workspace_id uuid not null references public.fa_workspaces(id),
 email text not null check(email=lower(email)),
 role text not null check(role in ('operator','viewer','admin')),
 created_at timestamptz not null default now(),
 primary key(workspace_id,email)
);
alter table public.fa_invites enable row level security;
revoke all on public.fa_invites from public,anon,authenticated;
grant select on public.fa_invites to authenticated;
grant all on public.fa_invites to service_role;
create policy fa_invite_admin_read on public.fa_invites for select to authenticated
 using(fa_private.has_role(workspace_id,array['admin']));
-- Only the backend can claim a job. A claimed write is never retried automatically.
create function public.fa_claim_job(j uuid, expected text, next_state text)
returns setof public.fa_jobs language sql security invoker set search_path='' as $$
 update public.fa_jobs set state=next_state,updated_at=now()
 where id=j and state=expected returning *;
$$;
revoke all on function public.fa_claim_job(uuid,text,text) from public,anon,authenticated;
grant execute on function public.fa_claim_job(uuid,text,text) to service_role;
commit;
