export const NODE_COLORS: Record<string, string> = {
  IP: '#2563eb',
  Domain: '#0f766e',
  URL: '#0891b2',
  Hash: '#7c3aed',
  Email: '#db2777',
  CVE: '#b91c1c',
  File: '#4b5563',
  Malware: '#dc2626',
  Command: '#9333ea',
  Alert: '#ea580c',
  'MITRE Technique': '#be123c',
  ASN: '#64748b',
  Country: '#16a34a',
  Source: '#ca8a04',
};

const fallbackColor = '#6b7280';

export function nodeTypeColor(type: string): string {
  return NODE_COLORS[type] || fallbackColor;
}
