/**
 * Phase 7 - Security Intelligence API client.
 *
 * Wraps the FastAPI intelligence endpoints.
 */

import { api } from './client'
import type {
  MitreContext,
  ReputationResult,
  ThreatIndicator,
  ThreatIndicatorCreate,
  ThreatIntelLookup,
} from '../types/intelligence'

/** Look up threat-intelligence data for an IP address. */
export async function lookupIp(ip: string): Promise<ThreatIntelLookup> {
  const response = await api.get<ThreatIntelLookup>(`/api/v1/intelligence/ip/${ip}`)
  return response.data
}

/** Return the internal behavioral reputation for a source IP. */
export async function getReputation(ip: string): Promise<ReputationResult> {
  const response = await api.get<ReputationResult>(`/api/v1/intelligence/reputation/${ip}`)
  return response.data
}

/** Return MITRE ATT&CK context for a technique id. */
export async function getMitre(techniqueId: string): Promise<MitreContext> {
  const response = await api.get<MitreContext>(`/api/v1/intelligence/mitre/${techniqueId}`)
  return response.data
}

/** List all supported MITRE mappings. */
export async function listMitreMappings(): Promise<MitreContext[]> {
  const response = await api.get<MitreContext[]>('/api/v1/intelligence/mitre')
  return response.data
}

/** List stored threat indicators (local IOC store). */
export async function listIndicators(params?: {
  indicator_type?: string
  active_only?: boolean
  limit?: number
}): Promise<ThreatIndicator[]> {
  const response = await api.get<ThreatIndicator[]>('/api/v1/intelligence/indicators', {
    params: params as Record<string, unknown>,
  })
  return response.data
}

/** Create a new local threat indicator (development-only). */
export async function createIndicator(data: ThreatIndicatorCreate): Promise<ThreatIndicator> {
  const response = await api.post<ThreatIndicator>('/api/v1/intelligence/indicators', data)
  return response.data
}

/** Delete a threat indicator (development-only). */
export async function deleteIndicator(indicatorId: number): Promise<void> {
  await api.delete(`/api/v1/intelligence/indicators/${indicatorId}`)
}