/**
 * ISIC Revision 5 — the UN's International Standard Industrial Classification
 * of All Economic Activities, endorsed by the UN Statistical Commission at its
 * 54th session (2023). A rule's sector is one of its 22 sections or 87
 * divisions (d85(c)).
 *
 * Source: UN Statistics Division, `ISIC_Rev_5_english_structure.csv`
 * (https://unstats.un.org/unsd/classifications/Econ/Download/In%20Text/ISIC_Rev_5_english_structure.csv),
 * read 2026-10-28. Sections and divisions only — groups and classes are finer
 * than a rule's address needs.
 */

export const ISIC_REV5: Readonly<Record<string, { readonly title: string; readonly divisions: readonly string[] }>> = {
  A: { title: "Agriculture, forestry and fishing", divisions: ["01", "02", "03"] },
  B: { title: "Mining and quarrying", divisions: ["05", "06", "07", "08", "09"] },
  C: { title: "Manufacturing", divisions: ["10", "11", "12", "13", "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26", "27", "28", "29", "30", "31", "32", "33"] },
  D: { title: "Electricity, gas, steam and air conditioning supply", divisions: ["35"] },
  E: { title: "Water supply; sewerage, waste management and remediation activities", divisions: ["36", "37", "38", "39"] },
  F: { title: "Construction", divisions: ["41", "42", "43"] },
  G: { title: "Wholesale and retail trade", divisions: ["46", "47"] },
  H: { title: "Transportation and storage", divisions: ["49", "50", "51", "52", "53"] },
  I: { title: "Accommodation and food service activities", divisions: ["55", "56"] },
  J: { title: "Publishing, broadcasting, and content production and distribution activities", divisions: ["58", "59", "60"] },
  K: { title: "Telecommunications, computer programming, consultancy, computing infrastructure, and other information service activities", divisions: ["61", "62", "63"] },
  L: { title: "Financial and insurance activities", divisions: ["64", "65", "66"] },
  M: { title: "Real estate activities", divisions: ["68"] },
  N: { title: "Professional, scientific and technical activities", divisions: ["69", "70", "71", "72", "73", "74", "75"] },
  O: { title: "Administrative and support service activities", divisions: ["77", "78", "79", "80", "81", "82"] },
  P: { title: "Public administration and defence; compulsory social security", divisions: ["84"] },
  Q: { title: "Education", divisions: ["85"] },
  R: { title: "Human health and social work activities", divisions: ["86", "87", "88"] },
  S: { title: "Arts, sports and recreation", divisions: ["90", "91", "92", "93"] },
  T: { title: "Other service activities", divisions: ["94", "95", "96"] },
  U: { title: "Activities of households as employers; undifferentiated goods- and services-producing activities of households for own use", divisions: ["97", "98"] },
  V: { title: "Activities of extraterritorial organizations and bodies", divisions: ["99"] },
};

/** The section a code belongs to — itself for a section, its parent for a division — or null when it is neither. */
export function isicSection(code: string): string | null {
  if (Object.prototype.hasOwnProperty.call(ISIC_REV5, code)) return code;
  for (const [section, s] of Object.entries(ISIC_REV5)) if (s.divisions.includes(code)) return section;
  return null;
}
