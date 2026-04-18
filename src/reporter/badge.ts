import type { ScanResult } from "../types.js";

function gradeColor(grade: string): string {
  if (grade === "A") return "brightgreen";
  if (grade === "B") return "green";
  if (grade === "C") return "yellow";
  if (grade === "D") return "orange";
  return "red";
}

export function renderBadgeUrl(result: ScanResult): string {
  const label = "MCPScan";
  const message = `${result.grade} (${result.score}/100)`;
  const color = gradeColor(result.grade);
  const encoded = encodeURIComponent(message);
  return `https://img.shields.io/badge/${label}-${encoded}-${color}`;
}

export function renderBadgeSvg(result: ScanResult): string {
  const colors: Record<string, string> = {
    brightgreen: "#4c1",
    green: "#97ca00",
    yellow: "#dfb317",
    orange: "#fe7d37",
    red: "#e05d44",
  };
  const color = colors[gradeColor(result.grade)] ?? "#e05d44";
  const label = "MCPScan";
  const message = `${result.grade} (${result.score}/100)`;
  const labelWidth = 70;
  const messageWidth = 90;
  const totalWidth = labelWidth + messageWidth;

  return `<svg xmlns="http://www.w3.org/2000/svg" width="${totalWidth}" height="20">
  <linearGradient id="b" x2="0" y2="100%">
    <stop offset="0" stop-color="#bbb" stop-opacity=".1"/>
    <stop offset="1" stop-opacity=".1"/>
  </linearGradient>
  <mask id="a">
    <rect width="${totalWidth}" height="20" rx="3" fill="#fff"/>
  </mask>
  <g mask="url(#a)">
    <rect width="${labelWidth}" height="20" fill="#555"/>
    <rect x="${labelWidth}" width="${messageWidth}" height="20" fill="${color}"/>
    <rect width="${totalWidth}" height="20" fill="url(#b)"/>
  </g>
  <g fill="#fff" text-anchor="middle" font-family="DejaVu Sans,Verdana,Geneva,sans-serif" font-size="11">
    <text x="${labelWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${label}</text>
    <text x="${labelWidth / 2}" y="14">${label}</text>
    <text x="${labelWidth + messageWidth / 2}" y="15" fill="#010101" fill-opacity=".3">${message}</text>
    <text x="${labelWidth + messageWidth / 2}" y="14">${message}</text>
  </g>
</svg>`;
}

export function renderBadge(result: ScanResult): { url: string; svg: string } {
  return {
    url: renderBadgeUrl(result),
    svg: renderBadgeSvg(result),
  };
}
