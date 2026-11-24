import { describe, expect, test } from "bun:test";
import {
  clientSelectPolicies,
  columnValues,
  countsIn,
  emptySqlModel,
  everyCountWrapped,
  functionClosed,
  readSql,
  relationClosed,
  relationSelf,
  statements,
  type SqlModel,
} from "../src/scan/sql.js";

function model(sql: string): SqlModel {
  const m = emptySqlModel();
  readSql(m, "m.sql", sql);
  return m;
}

describe("statements", () => {
  test("semicolons inside dollar bodies, strings and comments do not split", () => {
    const s = statements("create function f() returns int as $body$ select 1; select 2; $body$ language sql;\r\nselect 'a;b'; /* c; /* nested; */ d; */ select E'it\\'s;' ; -- e;\r\nselect 3");
    expect(s.length).toBe(4);
    expect(s[0]).toContain("$body$ select 1; select 2; $body$");
    expect(s[1]).toBe("select 'a;b'");
    expect(s[2]).toContain("E'it\\'s;'");
    expect(s[3]).toBe("select 3");
  });
});

describe("tables and columns", () => {
  test("columns, not null, references, inline and named checks", () => {
    const m = model(`
      create table if not exists public."Invites" (
        id uuid primary key,
        user_id uuid not null references public.profiles (id),
        status text check (status in ('sent', 'it''s declined')),
        kind text,
        constraint invites_kind check (kind = any (array['a', 'b']))
      );`);
    const t = m.relations.get("public.Invites")!;
    expect([...t.columns.keys()]).toEqual(["id", "user_id", "status", "kind"]);
    expect(t.columns.get("user_id")?.notNull).toBe(true);
    expect(t.columns.get("user_id")?.references).toBe("profiles");
    expect(columnValues(m, t, t.columns.get("status")!)).toEqual(["sent", "it's declined"]);
    expect(columnValues(m, t, t.columns.get("kind")!)).toEqual(["a", "b"]);
  });

  test("alter table: add, rename, drop, constraints, not null, rename and move the table", () => {
    const m = model(`
      create table t (a int);
      alter table t add column if not exists b text check (b in ('x')), add constraint b2 check (b in ('y'));
      alter table t rename column b to c;
      alter table t alter column a set not null;
      alter table t drop constraint b2;
      alter table t rename to u;
      alter table only u drop column if exists a;`);
    expect(m.relations.has("public.t")).toBe(false);
    const u = m.relations.get("public.u")!;
    expect([...u.columns.keys()]).toEqual(["c"]);
    expect(columnValues(m, u, u.columns.get("c")!)).toEqual(["x"]);
  });

  test("an enum type gives a column its values, and alter type adds to them", () => {
    const m = model(`
      create type invite_state as enum ('sent', 'accepted');
      alter type invite_state add value if not exists 'declined';
      create table invites (state invite_state not null);`);
    const t = m.relations.get("public.invites")!;
    expect(columnValues(m, t, t.columns.get("state")!)).toEqual(["sent", "accepted", "declined"]);
  });

  test("drop table and drop function", () => {
    const m = model("create table a (x int); create function f() returns int as $$ select 1 $$ language sql; drop table if exists a cascade; drop function f();");
    expect(m.relations.size).toBe(0);
    expect(m.functions.size).toBe(0);
  });
});

describe("who can read: row-level security, policies, grants", () => {
  test("a table is open by default and closed by row-level security with no policy", () => {
    const m = model("create table a (x int); create table b (x int); alter table b enable row level security;");
    expect(relationClosed(m.relations.get("public.a")!)).toBe(false);
    expect(relationClosed(m.relations.get("public.b")!)).toBe(true);
  });

  test("a policy to public, anon or authenticated opens it; one to service_role does not", () => {
    const m = model(`
      create table a (x int); alter table a enable row level security;
      create policy p on a for select to service_role using (true);
      create table b (x int); alter table b enable row level security;
      create policy q on b as permissive for all using (x = 1);`);
    expect(relationClosed(m.relations.get("public.a")!)).toBe(true);
    expect(relationClosed(m.relations.get("public.b")!)).toBe(false);
    expect(clientSelectPolicies(m.relations.get("public.b")!).map((p) => p.name)).toEqual(["q"]);
  });

  test("drop and alter policy", () => {
    const m = model(`
      create table a (x int); alter table a enable row level security;
      create policy p on a for select to anon using (true);
      alter policy p on a to service_role;
      create table b (x int); alter table b enable row level security;
      create policy q on b for select using (true);
      drop policy if exists q on b;`);
    expect(relationClosed(m.relations.get("public.a")!)).toBe(true);
    expect(relationClosed(m.relations.get("public.b")!)).toBe(true);
  });

  test("revoking select from the client roles closes a table, granting opens it again", () => {
    const m = model("create table a (x int); create table b (x int); revoke all on all tables in schema public from anon, authenticated; grant select on table b to authenticated;");
    expect(relationClosed(m.relations.get("public.a")!)).toBe(true);
    expect(relationClosed(m.relations.get("public.b")!)).toBe(false);
  });

  test("rows keyed to the caller only when every client read policy uses auth.uid()", () => {
    const m = model(`
      create table own (id uuid); alter table own enable row level security;
      create policy p on own for select using (id = auth.uid());
      create table mixed (id uuid); alter table mixed enable row level security;
      create policy p on mixed for select using (id = auth.uid());
      create policy q on mixed for select to anon using (true);`);
    expect(relationSelf(m.relations.get("public.own")!)).toBe(true);
    expect(relationSelf(m.relations.get("public.mixed")!)).toBe(false);
  });

  test("a function is closed only when public, anon and authenticated all lose execute", () => {
    const m = model(`
      create function public.a() returns int as $$ select 1 $$ language sql;
      create function public.b() returns int as $$ select 1 $$ language sql;
      revoke execute on function public.a() from public;
      revoke all on function public.b() from public, anon, authenticated;
      create or replace function public.b() returns int as $$ select 2 $$ language sql;`);
    expect(functionClosed(m.functions.get("public.a")!)).toBe(false);
    expect(functionClosed(m.functions.get("public.b")!)).toBe(true);
    expect(m.functions.get("public.b")!.body).toContain("select 2");
  });

  test("a trigger function is marked", () => {
    const m = model("create function public.t() returns trigger language plpgsql as $$ begin return new; end $$;");
    expect(m.functions.get("public.t")?.trigger).toBe(true);
  });
});

describe("counts in SQL", () => {
  test("count and sum, but not inside a string", () => {
    expect(countsIn("select count(*) from t")).toBe(true);
    expect(countsIn("select sum (x) from t")).toBe(true);
    expect(countsIn("select 'count(*)' as label")).toBe(false);
  });

  test("every count inside floor_suppress", () => {
    expect(everyCountWrapped("select floor_suppress(count(*)), floor_suppress(sum(x), 7) from t").wrapped).toBe(true);
    expect(everyCountWrapped("select floor_suppress(count(*)), count(*) from t")).toEqual({ wrapped: false, bare: 1 });
  });
});
