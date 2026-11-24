create or replace function public.region_stats() returns bigint language sql stable as $$
  select count(*) from listings
$$;
