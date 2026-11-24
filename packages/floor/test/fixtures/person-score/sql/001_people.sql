create table profiles (
  id uuid primary key,
  reputation numeric,
  total_pkr numeric
);

create table trip_members (
  trip_id uuid not null,
  user_id uuid not null references profiles (id),
  streak int not null default 0
);

-- Keyed only to who wrote it: an actor column, not the row's subject.
create table kumak_reports (
  id uuid primary key,
  created_by uuid references profiles (id),
  endorsement_count int
);
