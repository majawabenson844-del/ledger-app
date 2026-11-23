-- Run this once in Supabase Dashboard > SQL Editor.
-- In Authentication settings, disable public sign-ups and invite users by email.

create table if not exists public.shared_ledger (
  id integer primary key check (id = 1),
  revision bigint not null check (revision > 0),
  salt text not null,
  iv text not null,
  ciphertext text not null,
  updated_at timestamptz not null default now(),
  updated_by uuid not null references auth.users(id)
);

alter table public.shared_ledger enable row level security;

drop policy if exists "Signed-in users can read shared ledger" on public.shared_ledger;
create policy "Signed-in users can read shared ledger"
  on public.shared_ledger
  for select
  to authenticated
  using ((select auth.uid()) is not null);

revoke all on table public.shared_ledger from anon, authenticated;
grant select on table public.shared_ledger to authenticated;

create or replace function public.save_shared_ledger(
  p_expected_revision bigint,
  p_salt text,
  p_iv text,
  p_ciphertext text
)
returns bigint
language plpgsql
security definer
set search_path = ''
as $$
declare
  saved_revision bigint;
  current_user_id uuid := auth.uid();
begin
  if current_user_id is null then
    raise exception 'Sign in is required to save the ledger.'
      using errcode = '42501';
  end if;

  if p_salt is null or length(p_salt) > 100
    or p_iv is null or length(p_iv) > 100
    or p_ciphertext is null or length(p_ciphertext) > 5000000 then
    raise exception 'Invalid encrypted ledger payload.'
      using errcode = '22023';
  end if;

  if p_expected_revision = 0 then
    insert into public.shared_ledger (
      id, revision, salt, iv, ciphertext, updated_by
    )
    values (
      1, 1, p_salt, p_iv, p_ciphertext, current_user_id
    )
    on conflict (id) do nothing
    returning revision into saved_revision;

    if saved_revision is null then
      raise exception 'The shared ledger was created by another user. Reload it before saving.'
        using errcode = '40001';
    end if;
  else
    update public.shared_ledger
    set revision = revision + 1,
        salt = p_salt,
        iv = p_iv,
        ciphertext = p_ciphertext,
        updated_at = now(),
        updated_by = current_user_id
    where id = 1 and revision = p_expected_revision
    returning revision into saved_revision;

    if saved_revision is null then
      raise exception 'Another user updated the shared ledger. Reload it before saving.'
        using errcode = '40001';
    end if;
  end if;

  return saved_revision;
end;
$$;

revoke all on function public.save_shared_ledger(bigint, text, text, text) from public, anon;
grant execute on function public.save_shared_ledger(bigint, text, text, text) to authenticated;

do $$
begin
  if not exists (
    select 1
    from pg_publication_tables
    where pubname = 'supabase_realtime'
      and schemaname = 'public'
      and tablename = 'shared_ledger'
  ) then
    alter publication supabase_realtime add table public.shared_ledger;
  end if;
end
$$;

create table if not exists public.ledger_members (
  user_id uuid primary key references auth.users(id) on delete cascade,
  role text not null check (role in ('owner', 'no_loans')),
  created_at timestamptz not null default now()
);

alter table public.ledger_members enable row level security;

create or replace function public.current_ledger_role()
returns text
language sql
stable
security definer
set search_path = ''
as $$
  select role
  from public.ledger_members
  where user_id = auth.uid()
  limit 1;
$$;

revoke all on table public.ledger_members from anon, authenticated;
grant select on table public.ledger_members to authenticated;
grant execute on function public.current_ledger_role() to authenticated;

drop policy if exists "Users can read their ledger role" on public.ledger_members;
create policy "Users can read their ledger role"
  for select
  to authenticated
  using (user_id = (select auth.uid()));

-- Existing users need no-loans access only if you insert a row below.
-- Replace the UUID with the Supabase Authentication user ID:
-- insert into public.ledger_members (user_id, role)
-- values ('USER_UUID', 'no_loans')
-- on conflict (user_id) do update set role = excluded.role;
-- Owner users can be added the same way with role 'owner'.
