const DISCORD_CHANNEL_REGIONS: Record<string, string> = {
  '1519746035294146723': 'Brasil',
  '1523215881218424852': 'Europe',
  '1523215924814024724': 'East Asia',
  '1523423991895687381': 'India Central',
};

export function displaySource(
  source: string | null | undefined,
  metadata?: Record<string, unknown> | null,
): string {
  const region = metadataRegion(metadata);
  if (region) return region;

  const channelId = discordChannelId(source);
  if (channelId && DISCORD_CHANNEL_REGIONS[channelId]) {
    return DISCORD_CHANNEL_REGIONS[channelId];
  }

  return source || '-';
}

function metadataRegion(metadata?: Record<string, unknown> | null): string | null {
  if (!metadata) return null;
  for (const key of ['region', 'vmRegion', 'vm_region']) {
    const value = metadata[key];
    if (typeof value === 'string' && value.trim()) return value.trim();
  }
  return null;
}

function discordChannelId(source: string | null | undefined): string | null {
  const match = String(source || '').match(/^discord-channel:(\d{17,20})$/);
  return match ? match[1] : null;
}
