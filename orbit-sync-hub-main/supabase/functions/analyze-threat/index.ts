import { serve } from "https://deno.land/std@0.168.0/http/server.ts";

const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'authorization, x-client-info, apikey, content-type',
};

interface LogEntry {
  timestamp?: string;
  source_ip?: string;
  destination_ip?: string;
  event_type?: string;
  severity_status?: string;
  details?: string;
}

interface ThreatPrediction {
  is_threat: boolean;
  threat_score: number;
  confidence: number;
  indicators: string[];
}

function extractFeaturesFromLog(logEntry: LogEntry) {
  const eventTypes: Record<string, number> = {
    'BruteForce': 5,
    'Malware': 10,
    'DataLeak': 8,
    'PortScan': 4,
    'UnauthorizedAccess': 7,
    'Normal': 0
  };

  const severityLevels: Record<string, number> = {
    'Critical': 10,
    'High': 7,
    'Medium': 4,
    'Low': 2,
    'Info': 0
  };

  const features: Record<string, number> = {};

  // Get event type score
  const eventType = logEntry.event_type || 'Normal';
  features.event_severity = eventTypes[eventType] || 0;

  // Get severity level
  const severity = logEntry.severity_status || 'Info';
  features.severity_level = severityLevels[severity] || 0;

  // IP-based features
  const srcIp = logEntry.source_ip || '0.0.0.0';
  const dstIp = logEntry.destination_ip || '0.0.0.0';

  features.src_external = srcIp.startsWith('192.168.') || srcIp.startsWith('10.') || srcIp.startsWith('172.') ? 0 : 1;
  features.dst_internal = dstIp.startsWith('192.168.') || dstIp.startsWith('10.') || dstIp.startsWith('172.') ? 1 : 0;

  // Threat indicators from details
  const details = (logEntry.details || '').toLowerCase();
  features.has_failed_login = details.includes('failed') || details.includes('login') ? 1 : 0;
  features.has_malware = details.includes('malware') || details.includes('trojan') || details.includes('virus') ? 1 : 0;
  features.has_data_leak = details.includes('data') || details.includes('leak') || details.includes('outbound') ? 1 : 0;
  features.has_scan = details.includes('scan') || details.includes('port') ? 1 : 0;
  features.has_unauthorized = details.includes('unauthorized') || details.includes('restricted') ? 1 : 0;

  return features;
}

function parseLogData(logContent: string) {
  const records: Array<{ raw: LogEntry; features: Record<string, number> }> = [];

  // Try parsing as full JSON object first
  try {
    const jsonData = JSON.parse(logContent);
    
    // Helper function to detect and convert threat report format
    const isThreatReport = (obj: any) => {
      return obj.threat_id || obj.severity_level || obj.risk_score || 
             obj.threat_details || obj.affected_systems;
    };

    const convertThreatReport = (report: any): LogEntry => {
      // Map severity_level (numeric) to severity status
      let severity = 'Critical'; // Default to Critical for threat reports
      const severityNum = report.severity_level || report.severity || 0;
      if (severityNum >= 8) severity = 'Critical';
      else if (severityNum >= 6) severity = 'High';
      else if (severityNum >= 4) severity = 'High';
      else if (severityNum >= 2) severity = 'Medium';
      else severity = 'Low';

      // Determine event type - threat reports should always be classified as threats
      let eventType = 'Malware'; // Default to Malware for threat reports
      const riskScore = report.risk_score || report.score || 0;
      
      // Any threat report with risk score or severity should be flagged
      if (riskScore >= 70 || severityNum >= 7) {
        eventType = 'Malware';
      } else if (riskScore >= 50 || severityNum >= 5) {
        eventType = 'UnauthorizedAccess';
      } else if (report.threat_details?.attack_vector_code || report.attack_vector) {
        eventType = 'UnauthorizedAccess';
      } else if (report.affected_systems > 3) {
        eventType = 'DataLeak';
      } else if (riskScore >= 30 || severityNum >= 3) {
        eventType = 'BruteForce';
      }

      // Build detailed description with threat indicators
      const details = `THREAT REPORT - ID=${report.threat_id || 'Unknown'}, Risk Score=${riskScore}, Severity=${severityNum}, Affected Systems=${report.affected_systems || 0}, Malware Detected, ${JSON.stringify(report.threat_details || {})}`;

      return {
        timestamp: report.timestamp || report.detected_at || new Date().toISOString(),
        source_ip: report.source_ip || report.origin || '192.168.1.100',
        destination_ip: report.target_ip || report.destination || '10.0.0.1',
        event_type: eventType,
        severity_status: severity,
        details: details
      };
    };

    if (Array.isArray(jsonData)) {
      // Array of entries
      for (const entry of jsonData) {
        let logEntry: LogEntry;
        
        if (isThreatReport(entry)) {
          logEntry = convertThreatReport(entry);
        } else {
          logEntry = {
            timestamp: entry.timestamp || entry.time || new Date().toISOString(),
            source_ip: entry.source_ip || entry.src_ip || entry.source || 'Unknown',
            destination_ip: entry.destination_ip || entry.dst_ip || entry.destination || 'Unknown',
            event_type: entry.event_type || entry.event || entry.type || 'Unknown',
            severity_status: entry.severity_status || entry.severity || entry.level || 'Medium',
            details: entry.details || entry.message || entry.description || JSON.stringify(entry)
          };
        }
        const features = extractFeaturesFromLog(logEntry);
        records.push({ raw: logEntry, features });
      }
      return records;
    } else if (typeof jsonData === 'object') {
      // Single JSON object
      let logEntry: LogEntry;
      
      if (isThreatReport(jsonData)) {
        logEntry = convertThreatReport(jsonData);
      } else {
        logEntry = {
          timestamp: jsonData.timestamp || jsonData.time || new Date().toISOString(),
          source_ip: jsonData.source_ip || jsonData.src_ip || jsonData.source || 'Unknown',
          destination_ip: jsonData.destination_ip || jsonData.dst_ip || jsonData.destination || 'Unknown',
          event_type: jsonData.event_type || jsonData.event || jsonData.type || 'Unknown',
          severity_status: jsonData.severity_status || jsonData.severity || jsonData.level || 'Medium',
          details: jsonData.details || jsonData.message || jsonData.description || JSON.stringify(jsonData)
        };
      }
      const features = extractFeaturesFromLog(logEntry);
      records.push({ raw: logEntry, features });
      return records;
    }
  } catch {
    // Not valid JSON, continue to line-by-line parsing
  }

  // Parse line by line
  const lines = logContent.trim().split('\n');
  const startIdx = lines[0]?.toLowerCase().includes('timestamp') ? 1 : 0;

  for (let i = startIdx; i < lines.length; i++) {
    const line = lines[i].trim();
    if (!line) continue;

    // Try JSON line
    try {
      const record = JSON.parse(line) as LogEntry;
      const features = extractFeaturesFromLog(record);
      records.push({ raw: record, features });
      continue;
    } catch {
      // Not JSON, try other formats
    }

    // Try CSV format
    if (line.includes(',')) {
      const parts = line.split(',');
      if (parts.length >= 5) {
        const logEntry: LogEntry = {
          timestamp: parts[0]?.trim(),
          source_ip: parts[1]?.trim(),
          destination_ip: parts[2]?.trim(),
          event_type: parts[3]?.trim(),
          severity_status: parts[4]?.trim(),
          details: parts.slice(5).join(',').trim()
        };
        const features = extractFeaturesFromLog(logEntry);
        records.push({ raw: logEntry, features });
        continue;
      }
    }

    // Try syslog format (e.g., "Nov 18 10:42:51 firewall kernel: ...")
    const syslogMatch = line.match(/^(\w+\s+\d+\s+[\d:]+)\s+(\S+)\s+(.+)$/);
    if (syslogMatch) {
      const [, timestamp, host, message] = syslogMatch;
      
      // Extract IP addresses
      const srcMatch = message.match(/SRC=([\d.]+)/);
      const dstMatch = message.match(/DST=([\d.]+)/);
      
      // Determine event type from message content
      let eventType = 'Unknown';
      let severity = 'Medium';
      
      if (message.toLowerCase().includes('brute') || message.toLowerCase().includes('failed')) {
        eventType = 'BruteForce';
        severity = 'High';
      } else if (message.toLowerCase().includes('malware') || message.toLowerCase().includes('trojan') || message.toLowerCase().includes('virus')) {
        eventType = 'Malware';
        severity = 'Critical';
      } else if (message.toLowerCase().includes('scan')) {
        eventType = 'PortScan';
        severity = 'Medium';
      } else if (message.toLowerCase().includes('unauthorized') || message.toLowerCase().includes('denied')) {
        eventType = 'UnauthorizedAccess';
        severity = 'High';
      } else if (message.toLowerCase().includes('alert') || message.toLowerCase().includes('warning')) {
        severity = 'High';
      }

      const logEntry: LogEntry = {
        timestamp,
        source_ip: srcMatch ? srcMatch[1] : 'Unknown',
        destination_ip: dstMatch ? dstMatch[1] : 'Unknown',
        event_type: eventType,
        severity_status: severity,
        details: message
      };
      const features = extractFeaturesFromLog(logEntry);
      records.push({ raw: logEntry, features });
      continue;
    }

    // Plain text - treat as generic log entry
    if (line.length > 10) {
      // Extract any IP addresses from the line
      const ipMatches = line.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/g);
      
      let eventType = 'Unknown';
      let severity = 'Medium';
      
      // Determine threat level from keywords
      if (line.toLowerCase().includes('brute') || line.toLowerCase().includes('failed login')) {
        eventType = 'BruteForce';
        severity = 'High';
      } else if (line.toLowerCase().includes('malware') || line.toLowerCase().includes('trojan') || line.toLowerCase().includes('virus')) {
        eventType = 'Malware';
        severity = 'Critical';
      } else if (line.toLowerCase().includes('leak') || line.toLowerCase().includes('data')) {
        eventType = 'DataLeak';
        severity = 'High';
      } else if (line.toLowerCase().includes('scan')) {
        eventType = 'PortScan';
        severity = 'Medium';
      } else if (line.toLowerCase().includes('unauthorized') || line.toLowerCase().includes('access denied')) {
        eventType = 'UnauthorizedAccess';
        severity = 'High';
      }

      const logEntry: LogEntry = {
        timestamp: new Date().toISOString(),
        source_ip: ipMatches?.[0] || 'Unknown',
        destination_ip: ipMatches?.[1] || 'Unknown',
        event_type: eventType,
        severity_status: severity,
        details: line
      };
      const features = extractFeaturesFromLog(logEntry);
      records.push({ raw: logEntry, features });
    }
  }

  return records;
}

function predictThreat(record: { raw: LogEntry; features: Record<string, number> }): ThreatPrediction {
  const { features, raw } = record;

  let ruleScore = 0;
  const threatIndicators: string[] = [];

  // Check extracted features
  if (features.event_severity >= 5) {
    ruleScore += 0.3;
    threatIndicators.push(`High-risk event: ${raw.event_type || 'Unknown'}`);
  }

  if (features.severity_level >= 7) {
    ruleScore += 0.3;
    threatIndicators.push(`High severity: ${raw.severity_status || 'Unknown'}`);
  }

  if (features.has_malware === 1) {
    ruleScore += 0.4;
    threatIndicators.push('Malware detected in details');
  }

  if (features.has_data_leak === 1) {
    ruleScore += 0.3;
    threatIndicators.push('Data leak indicators');
  }

  if (features.has_failed_login === 1) {
    ruleScore += 0.2;
    threatIndicators.push('Failed login attempts');
  }

  if (features.has_scan === 1) {
    ruleScore += 0.2;
    threatIndicators.push('Port scanning activity');
  }

  if (features.has_unauthorized === 1) {
    ruleScore += 0.3;
    threatIndicators.push('Unauthorized access attempt');
  }

  // Cap at 1.0
  const threatScore = Math.min(ruleScore, 1.0);

  return {
    is_threat: threatScore > 0.5,
    threat_score: threatScore,
    confidence: threatScore > 0.5 ? Math.min(threatScore * 1.5, 1.0) : (1.0 - threatScore),
    indicators: threatIndicators
  };
}

serve(async (req) => {
  if (req.method === 'OPTIONS') {
    return new Response(null, { headers: corsHeaders });
  }

  try {
    console.log('Threat analysis function called');

    const { log_content, file_type } = await req.json();

    console.log(`Received ${log_content?.length || 0} bytes of log content`);

    if (!log_content) {
      return new Response(
        JSON.stringify({ error: 'No log content provided' }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Parse log records
    const records = parseLogData(log_content);

    console.log(`Parsed ${records.length} records`);

    if (records.length === 0) {
      return new Response(
        JSON.stringify({ 
          error: 'Could not parse log data. Supported formats: CSV, JSON, syslog, or plain text with threat indicators.' 
        }),
        { status: 400, headers: { ...corsHeaders, 'Content-Type': 'application/json' } }
      );
    }

    // Analyze each record
    const results = [];
    const threatDetails = [];
    let threatCount = 0;
    let totalThreatScore = 0;

    for (let idx = 0; idx < records.length; idx++) {
      const prediction = predictThreat(records[idx]);
      const rawData = records[idx].raw;

      const resultEntry = {
        record_index: idx + 1,
        is_threat: prediction.is_threat,
        threat_score: Math.round(prediction.threat_score * 10000) / 10000,
        confidence: Math.round(prediction.confidence * 100 * 100) / 100
      };

      results.push(resultEntry);

      if (prediction.is_threat) {
        threatCount++;
        threatDetails.push({
          record_number: idx + 1,
          threat_score: Math.round(prediction.threat_score * 100 * 100) / 100,
          confidence: Math.round(prediction.confidence * 100 * 100) / 100,
          threat_type: rawData.event_type || 'Unknown',
          severity: rawData.severity_status || 'Unknown',
          source_ip: rawData.source_ip || 'Unknown',
          indicators: prediction.indicators,
          flagged_values: records[idx].features,
          sample_data: {
            timestamp: rawData.timestamp || '',
            event: rawData.event_type || '',
            severity: rawData.severity_status || '',
            details: (rawData.details || '').substring(0, 100)
          }
        });
      }

      totalThreatScore += prediction.threat_score;
    }

    // Calculate overall statistics
    const avgThreatScore = results.length > 0 ? totalThreatScore / results.length : 0;
    const avgConfidence = results.length > 0 
      ? results.reduce((sum, r) => sum + r.confidence, 0) / results.length 
      : 0;

    const response = {
      threat_status: threatCount > 0 ? 'threat' : 'safe',
      threat_score: Math.round(avgThreatScore * 10000) / 10000,
      total_records: results.length,
      threat_count: threatCount,
      safe_count: results.length - threatCount,
      average_confidence: Math.round(avgConfidence * 100) / 100,
      threat_details: threatDetails.slice(0, 10),
      summary: results.slice(0, 20)
    };

    console.log(`Analysis complete: ${threatCount} threats found in ${results.length} records`);

    return new Response(
      JSON.stringify(response),
      { 
        status: 200, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    );

  } catch (error) {
    console.error('Error in handler:', error);
    const errorMessage = error instanceof Error ? error.message : 'Unknown error occurred';
    return new Response(
      JSON.stringify({ error: errorMessage }),
      { 
        status: 500, 
        headers: { ...corsHeaders, 'Content-Type': 'application/json' } 
      }
    );
  }
});
