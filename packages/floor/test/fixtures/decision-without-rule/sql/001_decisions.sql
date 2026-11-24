create table decisions (
  id uuid primary key,
  outcome text not null,
  rule_version int
);
