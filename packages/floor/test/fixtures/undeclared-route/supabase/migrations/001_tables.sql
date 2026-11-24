-- Open to every client: PostgREST serves it, so it must be declared.
create table public.people_directory (
  id uuid primary key,
  name text
);

-- Row-level security and no policy: closed, so the floor declares it closed itself.
create table public.secrets (
  id uuid primary key
);
alter table public.secrets enable row level security;
