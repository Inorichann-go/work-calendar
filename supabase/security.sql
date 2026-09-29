-- 업무 캘린더 보안 설정
-- Supabase 대시보드 → SQL Editor 에 붙여넣고 실행하세요.
-- 실행 후에는 "로그인했고, 아래 allowed_users 에 이메일이 등록된 사용자"만
-- calendar_data 를 읽고 쓸 수 있어요. (로그인 기능이 들어간 사이트를 먼저 배포한 뒤 실행)

-- 1) 접근 허용 이메일 목록 -------------------------------------------------
create table if not exists public.allowed_users (
  email text primary key
);
alter table public.allowed_users enable row level security;
-- 정책을 만들지 않으므로 API로는 이 목록을 읽거나 바꿀 수 없어요 (대시보드에서만 관리).
revoke all on public.allowed_users from anon, authenticated;

-- ▼ 사용할 사람 이메일로 바꾸세요 (여러 명이면 줄을 추가)
insert into public.allowed_users (email) values
  ('you@example.com')
on conflict do nothing;

-- 2) 로그인한 사용자가 허용 목록에 있는지 확인하는 함수 ---------------------
create or replace function public.is_allowed_user()
returns boolean
language sql
stable
security definer
set search_path = public
as $$
  select exists (
    select 1 from public.allowed_users
    where lower(email) = lower(auth.jwt() ->> 'email')
  );
$$;
revoke execute on function public.is_allowed_user() from public, anon;
grant execute on function public.is_allowed_user() to authenticated;

-- 3) calendar_data 잠그기 --------------------------------------------------
alter table public.calendar_data enable row level security;

-- 기존 정책(익명 허용 등)을 모두 제거
do $$
declare pol record;
begin
  for pol in select policyname from pg_policies
             where schemaname = 'public' and tablename = 'calendar_data'
  loop
    execute format('drop policy %I on public.calendar_data', pol.policyname);
  end loop;
end $$;

-- 익명(anon) 키만으로는 아무것도 못 하게
revoke all on public.calendar_data from anon;
grant select, insert, update on public.calendar_data to authenticated;

create policy "allowed users can read" on public.calendar_data
  for select to authenticated using (public.is_allowed_user());
create policy "allowed users can insert" on public.calendar_data
  for insert to authenticated with check (public.is_allowed_user());
create policy "allowed users can update" on public.calendar_data
  for update to authenticated using (public.is_allowed_user()) with check (public.is_allowed_user());
