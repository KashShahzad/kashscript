-- floor_suppress — the floor's display rule for a count computed in SQL (ECOSYSTEM d97(i): k = 5; d85(b)11).
-- @kashscript/floor ships this file; a repository copies it into a migration of its own. The floor's scanner then
-- requires every count( and sum( in a declared SQL aggregate to sit inside floor_suppress(…).
--
-- A count at or above k comes back as it is; below k it comes back null, which the display reads "fewer than k".
-- k below 5 is refused. This is the display half of the founder's ruling of 2026-11-20 (noise first, then k as
-- display); the noise is KS-Q7's and not built.

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
