import { describe, expect, test } from "bun:test";
import { emptySchema, prismaNonNull, readPrisma, resolveRelations } from "../src/scan/prisma.js";

describe("Prisma", () => {
  test("several files make one schema; relations resolve across them", () => {
    const s = emptySchema();
    readPrisma(s, "a.prisma", 'model Account {\n  id String @id @default("http://x//y") // a URL in a string is not a comment\n  seats Seat[]\n}');
    readPrisma(s, "b.prisma", "model Seat {\n  id String @id\n  account Account @relation(fields: [accountId], references: [id])\n  accountId String\n  label String?\n  @@map(\"seats\")\n}");
    resolveRelations(s);
    const seat = s.models.get("Seat")!;
    expect(seat.dbName).toBe("seats");
    expect(seat.file).toBe("b.prisma");
    expect(seat.fields.find((f) => f.name === "account")?.relation).toBe(true);
    expect(seat.fields.find((f) => f.name === "accountId")?.relation).toBe(false);
    const label = seat.fields.find((f) => f.name === "label")!;
    expect(label.optional).toBe(true);
    expect(prismaNonNull(label)).toBe(false);
    const account = s.models.get("Account")!;
    expect(account.fields.map((f) => f.name)).toEqual(["id", "seats"]);
    expect(account.fields.find((f) => f.name === "seats")?.list).toBe(true);
  });

  test("enums: one per line or several, @map ignored", () => {
    const s = emptySchema();
    readPrisma(s, "e.prisma", 'enum A {\n  YES\n  NOT_YET @map("not-yet")\n  @@map("a")\n}\nenum B { ONE TWO }');
    expect(s.enums.get("A")).toEqual(["YES", "NOT_YET"]);
    expect(s.enums.get("B")).toEqual(["ONE", "TWO"]);
  });

  test("views and composite types are read; generator and datasource blocks are not", () => {
    const s = emptySchema();
    readPrisma(s, "v.prisma", 'generator client {\n  provider = "prisma-client-js"\n}\nview Totals {\n  n Int\n}\ntype Address {\n  city String\n}');
    expect(s.models.get("Totals")?.kind).toBe("view");
    expect(s.models.get("Address")?.kind).toBe("type");
    expect(s.models.has("client")).toBe(false);
  });
});
