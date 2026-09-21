create extension if not exists pgcrypto with schema extensions;

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text not null,
  name text not null,
  role text not null check (role in ('teacher','psy','admin')),
  must_change_password boolean not null default true,
  created_at timestamptz not null default now()
);

create table public.reports (
  id uuid primary key default gen_random_uuid(),
  code text not null unique,
  type text not null default 'other' check (type in ('physical','verbal','cyber','boycott','threat','property','other','chat')),
  place text,
  when_text text,
  body text not null check (char_length(body) between 1 and 5000),
  urgent boolean not null default false,
  status text not null default 'new' check (status in ('new','work','done')),
  assignee uuid references public.profiles(id) on delete set null,
  staff_seen boolean not null default false,
  created_at timestamptz not null default now()
);
create index reports_assignee_idx on public.reports(assignee);
create index reports_created_idx on public.reports(created_at desc);

create table public.messages (
  id bigint generated always as identity primary key,
  report_id uuid not null references public.reports(id) on delete cascade,
  sender text not null check (sender in ('student','staff','ai')),
  by_name text,
  body text not null check (char_length(body) between 1 and 5000),
  created_at timestamptz not null default now()
);
create index messages_report_idx on public.messages(report_id, created_at);

create table public.events (
  id bigint generated always as identity primary key,
  report_id uuid not null references public.reports(id) on delete cascade,
  text text not null,
  seen boolean not null default false,
  created_at timestamptz not null default now()
);
create index events_report_idx on public.events(report_id);

create table public.attachments (
  id uuid primary key default gen_random_uuid(),
  report_id uuid not null references public.reports(id) on delete cascade,
  path text not null,
  name text not null,
  kind text not null check (kind in ('image','video','file')),
  size bigint,
  created_at timestamptz not null default now()
);

create table public.activity_log (
  id bigint generated always as identity primary key,
  actor uuid,
  actor_name text,
  text text not null,
  created_at timestamptz not null default now()
);

create table public.settings (
  key text primary key,
  value jsonb not null
);
insert into public.settings(key, value) values
  ('ai_enabled', 'true'::jsonb),
  ('help_text', to_jsonb(E'Детский телефон доверия (Казахстан): 111\nДетский телефон доверия (Россия): 8-800-2000-122\nЭкстренная помощь: 112'::text));

alter table public.profiles enable row level security;
alter table public.reports enable row level security;
alter table public.messages enable row level security;
alter table public.events enable row level security;
alter table public.attachments enable row level security;
alter table public.activity_log enable row level security;
alter table public.settings enable row level security;

create or replace function public.my_role() returns text
language sql stable security definer set search_path = public as $$
  select role from public.profiles where id = auth.uid() and must_change_password = false
$$;

create or replace function public.can_access_report(p_id uuid) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (
    select 1 from public.reports r
    where r.id = p_id
      and (public.my_role() in ('psy','admin')
           or (public.my_role() = 'teacher' and r.assignee = auth.uid()))
  )
$$;

create or replace function public.detect_urgent(t text) returns boolean
language sql immutable as $$
  select coalesce(t, '') ~* '(суицид|самоубий|убить себя|убью себя|покончить с собой|не хочу жить|хочу умереть|повеси|вскрыть вены|порезать себя|режу себя|навредить себе|принесу нож|принесу оружие|принесу пистолет|застрелю|убью их|убью его|взорву школ)'
$$;

create or replace function public.log_action(p_text text) returns void
language sql security definer set search_path = public as $$
  insert into public.activity_log(actor, actor_name, text)
  select auth.uid(), coalesce((select name from public.profiles where id = auth.uid()), 'Система'), p_text
$$;

create policy profiles_self on public.profiles for select to authenticated
  using (id = auth.uid());
create policy profiles_staff_view on public.profiles for select to authenticated
  using (public.my_role() in ('psy','admin'));

create policy reports_read on public.reports for select to authenticated
  using (public.my_role() in ('psy','admin')
         or (public.my_role() = 'teacher' and assignee = auth.uid()));

create policy messages_read on public.messages for select to authenticated
  using (exists (select 1 from public.reports r where r.id = messages.report_id));
create policy events_read on public.events for select to authenticated
  using (exists (select 1 from public.reports r where r.id = events.report_id));
create policy attachments_read on public.attachments for select to authenticated
  using (exists (select 1 from public.reports r where r.id = attachments.report_id));

create policy log_read on public.activity_log for select to authenticated
  using (public.my_role() = 'admin');
create policy settings_read on public.settings for select to authenticated
  using (true);

revoke all on public.profiles, public.reports, public.messages, public.events,
  public.attachments, public.activity_log, public.settings from anon, authenticated;
grant select on public.profiles, public.reports, public.messages, public.events,
  public.attachments, public.activity_log, public.settings to authenticated;

insert into storage.buckets (id, name, public)
values ('attachments', 'attachments', false)
on conflict (id) do nothing;

create policy "staff read attachments" on storage.objects for select to authenticated
  using (
    bucket_id = 'attachments'
    and exists (
      select 1 from public.reports r
      where r.id::text = (storage.foldername(name))[1]
        and public.can_access_report(r.id)
    )
  );
