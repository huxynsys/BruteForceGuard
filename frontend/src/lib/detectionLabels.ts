export const DETECTION_LABELS: Record<string, string> = {
  single_account: 'Single Account Brute Force',
  single_account_bruteforce: 'Single Account Brute Force',
  password_spray: 'Password Spray',
  distributed: 'Distributed Brute Force',
  distributed_bruteforce: 'Distributed Brute Force',
  failed_success: 'Failed -> Success',
  failed_then_success: 'Failed -> Success',
  credential_stuffing: 'Credential Stuffing',
  low_and_slow: 'Low & Slow Attack',
}

export function detectionLabel(key: string): string {
  return DETECTION_LABELS[key] ?? key
}
