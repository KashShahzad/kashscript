-- The clean fixture's database: a person's own profile, public listings, a closed audit log, and one count served
-- through floor_suppress.

create table public.profiles (
  id uuid primary key,
  display_name text not null
);
alter table public.profiles enable row level security;
create policy "own profile" on public.profiles for select to authenticated using (id = (select auth.uid()));

create table public.listings (
  id uuid primary key,
  title text not null
);
alter table public.listings enable row level security;
create policy "anyone reads listings" on public.listings for select using (true);

create table public.audit_log (
  id uuid primary key,
  note text
);
alter table public.audit_log enable row level security;

create or replace function public.floor_suppress(n numeric, k integer default 5)
returns numeric
language plpgsql
immutable
as $$
begin
  if k is null or k < 5 then
    raise exception 'floor_suppress: k must be at least 5 (d97(i)); got %', k;
  end if;
  if n is null or n < k then
    return null;
  end if;
  return n;
end;
$$;

create or replace function public.listing_count() returns numeric language sql stable as $$
  select floor_suppress(count(*)) from public.listings
$$;
