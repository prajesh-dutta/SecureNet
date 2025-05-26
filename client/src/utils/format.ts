/**
 * Utility functions for formatting data
 */

/**
 * Format bytes to human readable string with appropriate unit
 */
export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Format bytes to Mbps (megabits per second) for network speed display
 * Assumes the input is bytes per second
 */
export function formatBytesToMbps(bytesPerSecond: number): string {
  if (bytesPerSecond === 0) return '0 Mbps';
  
  // Convert bytes to bits (multiply by 8) then to megabits (divide by 1,000,000)
  const mbps = (bytesPerSecond * 8) / 1000000;
  
  if (mbps >= 1000) {
    return (mbps / 1000).toFixed(2) + ' Gbps';
  } else if (mbps >= 1) {
    return mbps.toFixed(2) + ' Mbps';
  } else {
    const kbps = mbps * 1000;
    return kbps.toFixed(2) + ' Kbps';
  }
}

/**
 * Format total bytes to appropriate throughput unit
 * This is for displaying cumulative/total bandwidth usage
 */
export function formatBandwidthUsage(totalBytes: number): string {
  if (totalBytes === 0) return '0 B';
  
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(totalBytes) / Math.log(k));
  
  return parseFloat((totalBytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

/**
 * Format uptime in seconds to human readable string
 */
export function formatUptime(seconds: number): string {
  if (!seconds || seconds < 60) {
    return `${Math.floor(seconds || 0)}s`;
  }
  
  const days = Math.floor(seconds / 86400);
  const hours = Math.floor((seconds % 86400) / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  
  if (days > 0) {
    return `${days}d ${hours}h ${minutes}m`;
  } else if (hours > 0) {
    return `${hours}h ${minutes}m`;
  } else {
    return `${minutes}m`;
  }
}

/**
 * Format a number with thousands separators
 */
export function formatNumber(num: number): string {
  return num.toLocaleString();
}

/**
 * Calculate bandwidth rate from cumulative bytes
 * Note: For real-time rates, this would need previous measurements
 * For now, this provides a rough estimate based on typical usage patterns
 */
export function estimateBandwidthRate(totalBytes: number): string {
  // This is a simplified estimation - in production you'd track deltas over time
  // Assuming data represents activity over the last hour for rate calculation
  const estimatedBytesPerSecond = totalBytes / 3600; // rough estimate
  return formatBytesToMbps(estimatedBytesPerSecond);
}
