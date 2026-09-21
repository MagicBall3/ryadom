create or replace function public.submit_report(
  p_type text, p_place text, p_when text, p_body text, p_urgent boolean default false
) returns text
language plpgsql security definer set search_path = public, extensions as $$
declare
  v_alphabet constant text := 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  v_code text;
  v_bytes bytea;
  v_type text := p_type;
begin
  if p_body is null or char_length(btrim(p_body)) < 3 or char_length(p_body) > 5000 then
    raise exception 'invalid_body';
  end if;
  if v_type is null or v_type not in ('physical','verbal','cyber','boycott','threat','property','other','chat') then
    v_type := 'other';
  end if;
  if (select count(*) from public.reports where created_at > now() - interval '1 minute') >= 40 then
    raise exception 'too_many_requests';
  end if;
  loop
    v_bytes := gen_random_bytes(8);
    v_code := '';
    for i in 0..7 loop
      v_code := v_code || substr(v_alphabet, (get_byte(v_bytes, i) % 32) + 1, 1);
      if i = 3 then v_code := v_code || '-'; end if;
    end loop;
    exit when not exists (select 1 from public.reports where code = v_code);
  end loop;
  insert into public.reports(code, type, place, when_text, body, urgent)
  values (v_code, v_type, left(p_place, 100), left(p_when, 100), p_body,
          coalesce(p_urgent, false) or public.detect_urgent(p_body));
  return v_code;
end $$;

create or replace function public.get_report(p_code text) returns jsonb
language plpgsql security definer set search_path = public as $$
declare r public.reports;
begin
  select * into r from public.reports where code = upper(btrim(p_code));
  if not found then return null; end if;
  return jsonb_build_object(
    'code', r.code, 'type', r.type, 'place', r.place, 'when', r.when_text,
    'body', r.body, 'urgent', r.urgent, 'status', r.status, 'created_at', r.created_at,
    'messages', coalesce((select jsonb_agg(jsonb_build_object(
        'sender', m.sender, 'by', m.by_name, 'body', m.body, 'created_at', m.created_at)
        order by m.created_at, m.id)
      from public.messages m where m.report_id = r.id), '[]'::jsonb)
  );
end $$;

create or replace function public.get_reports_by_codes(p_codes text[]) returns jsonb
language sql stable security definer set search_path = public as $$
  select coalesce(jsonb_agg(jsonb_build_object(
    'code', r.code, 'type', r.type, 'status', r.status, 'urgent', r.urgent,
    'created_at', r.created_at, 'preview', left(r.body, 90),
    'unseen', (select count(*) from public.events e where e.report_id = r.id and not e.seen)
  ) order by r.created_at desc), '[]'::jsonb)
  from public.reports r
  where r.code in (select upper(btrim(c)) from unnest(p_codes[1:30]) c)
$$;

create or replace function public.get_events(p_codes text[]) returns jsonb
language sql stable security definer set search_path = public as $$
  select coalesce(jsonb_agg(jsonb_build_object(
    'id', e.id, 'code', r.code, 'text', e.text, 'seen', e.seen, 'created_at', e.created_at
  ) order by e.created_at desc), '[]'::jsonb)
  from public.events e join public.reports r on r.id = e.report_id
  where r.code in (select upper(btrim(c)) from unnest(p_codes[1:30]) c)
$$;

create or replace function public.student_add_message(p_code text, p_body text) returns void
language plpgsql security definer set search_path = public as $$
declare v_id uuid;
begin
  if p_body is null or char_length(btrim(p_body)) < 1 or char_length(p_body) > 5000 then
    raise exception 'invalid_body';
  end if;
  update public.reports
     set staff_seen = false, urgent = urgent or public.detect_urgent(p_body)
   where code = upper(btrim(p_code))
   returning id into v_id;
  if v_id is null then raise exception 'not_found'; end if;
  insert into public.messages(report_id, sender, body) values (v_id, 'student', p_body);
end $$;

create or replace function public.mark_events_seen(p_code text) returns void
language sql security definer set search_path = public as $$
  update public.events set seen = true
   where report_id = (select id from public.reports where code = upper(btrim(p_code)))
$$;

create or replace function public.get_public_settings() returns jsonb
language sql stable security definer set search_path = public as $$
  select coalesce(jsonb_object_agg(key, value), '{}'::jsonb)
  from public.settings where key in ('ai_enabled', 'help_text')
$$;

create or replace function public.staff_mark_seen(p_code text) returns void
language sql security definer set search_path = public as $$
  update public.reports set staff_seen = true
   where code = upper(btrim(p_code)) and public.can_access_report(id)
$$;

create or replace function public.staff_set_status(p_code text, p_status text) returns void
language plpgsql security definer set search_path = public as $$
declare v_id uuid; v_old text; v_code text; v_label text;
begin
  if p_status not in ('new','work','done') then raise exception 'bad_status'; end if;
  select id, status, code into v_id, v_old, v_code
    from public.reports where code = upper(btrim(p_code)) and public.can_access_report(id);
  if v_id is null then raise exception 'forbidden'; end if;
  v_label := case p_status when 'new' then 'Получено' when 'work' then 'В работе' else 'Решено' end;
  update public.reports set status = p_status where id = v_id;
  if v_old <> p_status then
    insert into public.events(report_id, text) values (v_id, 'Статус обращения ' || v_code || ': ' || v_label);
    perform public.log_action('Статус ' || v_code || ' → ' || v_label);
  end if;
end $$;

create or replace function public.staff_reply(p_code text, p_body text) returns void
language plpgsql security definer set search_path = public as $$
declare v_id uuid; v_code text; v_label text;
begin
  if p_body is null or char_length(btrim(p_body)) < 1 or char_length(p_body) > 5000 then
    raise exception 'invalid_body';
  end if;
  select id, code into v_id, v_code
    from public.reports where code = upper(btrim(p_code)) and public.can_access_report(id);
  if v_id is null then raise exception 'forbidden'; end if;
  v_label := case public.my_role() when 'teacher' then 'Учитель' when 'psy' then 'Психолог' else 'Администрация' end;
  insert into public.messages(report_id, sender, by_name, body) values (v_id, 'staff', v_label, p_body);
  insert into public.events(report_id, text) values (v_id, 'Ответ школы по обращению ' || v_code);
  update public.reports
     set staff_seen = true, status = case when status = 'new' then 'work' else status end
   where id = v_id;
  perform public.log_action('Ответ на ' || v_code);
end $$;

create or replace function public.staff_assign(p_code text, p_user uuid) returns void
language plpgsql security definer set search_path = public as $$
declare v_code text;
begin
  if coalesce(public.my_role(), '') not in ('psy','admin') then raise exception 'forbidden'; end if;
  if p_user is not null and not exists (
    select 1 from public.profiles where id = p_user and role in ('teacher','psy')
  ) then raise exception 'bad_assignee'; end if;
  update public.reports set assignee = p_user where code = upper(btrim(p_code)) returning code into v_code;
  if v_code is null then raise exception 'not_found'; end if;
  perform public.log_action('Обращение ' || v_code || ' назначено');
end $$;

create or replace function public.admin_delete_report(p_code text) returns void
language plpgsql security definer set search_path = public as $$
declare v_code text;
begin
  if coalesce(public.my_role(), '') <> 'admin' then raise exception 'forbidden'; end if;
  delete from public.reports where code = upper(btrim(p_code)) returning code into v_code;
  if v_code is not null then perform public.log_action('Удалено обращение ' || v_code); end if;
end $$;

create or replace function public.admin_set_setting(p_key text, p_value jsonb) returns void
language plpgsql security definer set search_path = public as $$
begin
  if coalesce(public.my_role(), '') <> 'admin' then raise exception 'forbidden'; end if;
  if p_key not in ('ai_enabled', 'help_text') then raise exception 'bad_key'; end if;
  insert into public.settings(key, value) values (p_key, p_value)
  on conflict (key) do update set value = excluded.value;
  perform public.log_action('Изменена настройка ' || p_key);
end $$;

create or replace function public.clear_must_change_password() returns trigger
language plpgsql security definer set search_path = public as $$
begin
  update public.profiles set must_change_password = false where id = new.id;
  return new;
end $$;

drop trigger if exists on_auth_password_change on auth.users;
create trigger on_auth_password_change
  after update of encrypted_password on auth.users
  for each row
  when (old.encrypted_password is distinct from new.encrypted_password)
  execute function public.clear_must_change_password();

revoke execute on all functions in schema public from public, anon, authenticated;

grant execute on function public.submit_report(text, text, text, text, boolean) to anon, authenticated;
grant execute on function public.get_report(text) to anon, authenticated;
grant execute on function public.get_reports_by_codes(text[]) to anon, authenticated;
grant execute on function public.get_events(text[]) to anon, authenticated;
grant execute on function public.student_add_message(text, text) to anon, authenticated;
grant execute on function public.mark_events_seen(text) to anon, authenticated;
grant execute on function public.get_public_settings() to anon, authenticated;

grant execute on function public.my_role() to authenticated;
grant execute on function public.can_access_report(uuid) to authenticated;
grant execute on function public.staff_mark_seen(text) to authenticated;
grant execute on function public.staff_set_status(text, text) to authenticated;
grant execute on function public.staff_reply(text, text) to authenticated;
grant execute on function public.staff_assign(text, uuid) to authenticated;
grant execute on function public.admin_delete_report(text) to authenticated;
grant execute on function public.admin_set_setting(text, jsonb) to authenticated;
