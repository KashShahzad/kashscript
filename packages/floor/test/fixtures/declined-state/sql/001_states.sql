create table approvals (
  id uuid primary key,
  state text not null check (state in ('sent', 'opened', 'refused'))
);

-- A booking's events: a host who cannot take it, and who came — commerce, not a person's decline of proof.
create table agreement_events (
  id uuid primary key,
  event text not null,
  constraint agreement_events_event check (event in ('declined', 'came', 'not_come'))
);
