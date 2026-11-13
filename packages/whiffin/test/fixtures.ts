// Example program fixture for the whiffin test suite — stands in for the
// venture's SegmentPolicy CONTENT / DEMO_PROGRAMS (which stay venture-side,
// ADR-0016 guard b) so the tests never import across repos (ECOSYSTEM).

import type { Program, SegmentPolicy } from "../src/mandate/types";

export const EXAMPLE_VENDORS = ["did:kash:vendor-canteen", "did:kash:vendor-grocer"] as const;

export function exampleProgram(): Program {
  const programId = "prog_example";
  const policy: SegmentPolicy = {
    programId,
    segmentTag: "INSTITUTIONAL_GIVING",
    funderEntityType: "FOUNDATION",
    beneficiaryEntityType: "HOUSEHOLD",
    purposeCodes: ["MEAL", "GROCERY"],
    vendorRule: "ALLOWLIST",
    bindingRule: "BENEFICIARY_DID",
    reporting: { visibility: "FUNDER_VISIBLE" },
  };
  return {
    programId,
    funderDid: "did:kash:funder-example",
    displayName: "Example Meals Program",
    policy,
    approvedVendorDids: [...EXAMPLE_VENDORS],
    defaultExpirySeconds: 30 * 86_400,
    status: "ACTIVE",
    createdAtUnix: 1_700_000_000,
  };
}
