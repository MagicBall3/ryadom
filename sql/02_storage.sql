-- 02_storage.sql: загрузка файлов учениками (анонимно) и просмотр сотрудниками.
-- Путь файла в хранилище: <КОД-ОБРАЩЕНИЯ>/<случайное-имя>.<расширение>
-- Например: ABCD-EFGH/9f3a...c1.jpg

-- 1. Ограничения бакета: до 50 МБ на файл, только фото, видео и PDF.
update storage.buckets
   set file_size_limit = 52428800,
       allowed_mime_types = array[
         'image/jpeg','image/png','image/webp','image/gif',
         'video/mp4','video/webm','video/quicktime',
         'application/pdf'
       ]
 where id = 'attachments';

-- 2. Проверка: существует ли обращение с таким кодом (ученик знает только код).
create or replace function public.upload_allowed(p_code text) returns boolean
language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.reports where code = upper(btrim(p_code)))
$$;

revoke execute on function public.upload_allowed(text) from public;
grant execute on function public.upload_allowed(text) to anon, authenticated;

-- 3. Ученик может загружать файлы только в папку своего существующего обращения.
drop policy if exists "students upload attachments" on storage.objects;
create policy "students upload attachments" on storage.objects
  for insert to anon, authenticated
  with check (
    bucket_id = 'attachments'
    and public.upload_allowed((storage.foldername(name))[1])
  );

-- 4. Сотрудники читают файлы по коду в имени папки (вместо id).
drop policy if exists "staff read attachments" on storage.objects;
create policy "staff read attachments" on storage.objects
  for select to authenticated
  using (
    bucket_id = 'attachments'
    and exists (
      select 1 from public.reports r
      where r.code = (storage.foldername(name))[1]
        and public.can_access_report(r.id)
    )
  );

-- 5. Запись о вложении в таблицу attachments (после успешной загрузки файла).
create or replace function public.add_attachment(
  p_code text, p_path text, p_name text, p_kind text, p_size bigint
) returns void
language plpgsql security definer set search_path = public as $$
declare
  v_code text := upper(btrim(p_code));
  v_id uuid;
begin
  if p_kind not in ('image','video','file') then
    raise exception 'bad_kind';
  end if;
  if split_part(p_path, '/', 1) <> v_code then
    raise exception 'bad_path';
  end if;
  select id into v_id from public.reports where code = v_code;
  if v_id is null then
    raise exception 'not_found';
  end if;
  if (select count(*) from public.attachments where report_id = v_id) >= 10 then
    raise exception 'too_many_files';
  end if;
  insert into public.attachments(report_id, path, name, kind, size)
  values (v_id, p_path, left(coalesce(p_name, 'file'), 200), p_kind, p_size);
end $$;

revoke execute on function public.add_attachment(text, text, text, text, bigint) from public;
grant execute on function public.add_attachment(text, text, text, text, bigint) to anon, authenticated;
