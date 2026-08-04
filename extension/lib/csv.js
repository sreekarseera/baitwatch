// CSV export.
//
// Values are quoted and internal quotes doubled per RFC 4180. Fields that
// begin with =, +, -, or @ are additionally prefixed with a single quote:
// without that, a scam message starting with "=" is interpreted by Excel and
// Sheets as a formula. Exporting attacker-controlled text into a spreadsheet
// is exactly the situation CSV injection was invented for.

const FORMULA_PREFIX = /^[=+\-@\t\r]/;

function escapeCell(value) {
  const str = value === null || value === undefined ? "" : String(value);
  const guarded = FORMULA_PREFIX.test(str) ? `'${str}` : str;
  return `"${guarded.replace(/"/g, '""')}"`;
}

/**
 * @param {object[]} rows
 * @param {string[]} [columns] explicit column order; defaults to the keys of
 *   the first row (chrome.storage returns keys alphabetically, which is rarely
 *   the order a human wants to read).
 */
export function toCsv(rows, columns) {
  if (!rows.length) return "";
  const headers = columns?.length ? columns : Object.keys(rows[0]);
  const lines = [headers.map(escapeCell).join(",")];
  for (const row of rows) {
    lines.push(
      headers
        .map((h) => escapeCell(Array.isArray(row[h]) ? row[h].join(" | ") : row[h]))
        .join(",")
    );
  }
  return lines.join("\r\n");
}

export function downloadCsv(csv, filename) {
  // BOM so Excel opens UTF-8 correctly — scam messages are frequently
  // non-Latin, and without it they arrive as mojibake.
  const blob = new Blob(["﻿" + csv], { type: "text/csv;charset=utf-8" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  a.click();
  URL.revokeObjectURL(url);
}
