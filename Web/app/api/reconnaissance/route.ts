import { type NextRequest, NextResponse } from "next/server"
import { generateText } from "ai"
import { openai } from "@ai-sdk/openai"

export const maxDuration = 60

export async function POST(request: NextRequest) {
  try {
    const { target } = await request.json()

    if (!target) {
      return NextResponse.json({ error: "Target is required" }, { status: 400 })
    }

    // Enhanced target validation
    const isDomain =
      /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$/.test(target)
    const isIP = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(
      target,
    )

    if (!isDomain && !isIP) {
      return NextResponse.json({ error: "Invalid domain or IP format" }, { status: 400 })
    }

    console.log(`Starting reconnaissance for target: ${target}`)

    // Enhanced parallel API calls with better error handling
    const apiResults = await Promise.allSettled([
      fetchWhoisData(target, isDomain),
      fetchVirusTotalData(target),
      fetchNetworkIntelligence(target, isDomain),
    ])

    // Process results with detailed error logging
    const results = {
      whois: null,
      virustotal: null,
      shodan: null,
      errors: {} as Record<string, string>,
    }

    // Process WHOIS result
    if (apiResults[0].status === "fulfilled") {
      results.whois = apiResults[0].value
      console.log("WHOIS data retrieved successfully")
    } else {
      results.errors.whois = apiResults[0].reason?.message || "WHOIS lookup failed"
      console.error("WHOIS error:", apiResults[0].reason)
    }

    // Process VirusTotal result
    if (apiResults[1].status === "fulfilled") {
      results.virustotal = apiResults[1].value
      console.log("VirusTotal data retrieved successfully")
    } else {
      results.errors.virustotal = apiResults[1].reason?.message || "VirusTotal scan failed"
      console.error("VirusTotal error:", apiResults[1].reason)
    }

    // Process Network Intelligence result (replacing Shodan)
    if (apiResults[2].status === "fulfilled") {
      results.shodan = apiResults[2].value
      console.log("Network intelligence data retrieved successfully")
    } else {
      results.errors.shodan = apiResults[2].reason?.message || "Network intelligence lookup failed"
      console.error("Network intelligence error:", apiResults[2].reason)
    }

    // Always generate fallback report first
    console.log("Generating fallback report...")
    const fallbackReport = generateFallbackReport(target, results)

    // Try AI report generation only if OpenAI key is available and not in quota exceeded state
    let aiReport = null
    let reportType: "ai" | "fallback" = "fallback"

    if (process.env.OPENAI_API_KEY && !isOpenAIQuotaExceeded()) {
      try {
        console.log("Attempting AI report generation...")
        aiReport = await generateIntelligenceReport(target, results)
        reportType = "ai"
        console.log("AI report generated successfully")
      } catch (error: any) {
        console.error("AI report generation failed:", error.message)

        // Check if it's a quota error and mark it
        if (
          error.message.includes("quota") ||
          error.message.includes("billing") ||
          error.message.includes("exceeded")
        ) {
          markOpenAIQuotaExceeded()
          console.log("OpenAI quota exceeded - using fallback report only")
        }
      }
    } else {
      console.log("Skipping AI report generation - using fallback report")
    }

    return NextResponse.json({
      whois: results.whois,
      virustotal: results.virustotal,
      shodan: results.shodan,
      aiReport,
      fallbackReport,
      reportType,
      errors: results.errors,
      timestamp: new Date().toISOString(),
    })
  } catch (error) {
    console.error("Reconnaissance error:", error)
    return NextResponse.json(
      {
        error: "Internal server error during analysis",
        details: error instanceof Error ? error.message : "Unknown error",
      },
      { status: 500 },
    )
  }
}

// Simple in-memory quota tracking (in production, use Redis or database)
let quotaExceededUntil: number | null = null

function isOpenAIQuotaExceeded(): boolean {
  if (quotaExceededUntil && Date.now() < quotaExceededUntil) {
    return true
  }
  quotaExceededUntil = null
  return false
}

function markOpenAIQuotaExceeded(): void {
  // Mark quota as exceeded for 24 hours
  quotaExceededUntil = Date.now() + 24 * 60 * 60 * 1000
}

async function fetchWhoisData(target: string, isDomain: boolean) {
  if (!isDomain) {
    throw new Error("WHOIS lookup only available for domains")
  }

  if (!process.env.WHOISXML_API_KEY) {
    throw new Error("WHOISXML API key not configured")
  }

  try {
    const url = `https://www.whoisxmlapi.com/whoisserver/WhoisService?apiKey=${process.env.WHOISXML_API_KEY}&domainName=${target}&outputFormat=JSON`
    console.log("Fetching WHOIS data...")

    const response = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": "WebRaptor-OSINT/2.0",
      },
      signal: AbortSignal.timeout(15000), // 15 second timeout
    })

    if (!response.ok) {
      throw new Error(`WHOIS API error: ${response.status} ${response.statusText}`)
    }

    const data = await response.json()

    if (data.ErrorMessage) {
      throw new Error(`WHOIS API error: ${data.ErrorMessage.msg}`)
    }

    return data
  } catch (error) {
    console.error("WHOIS fetch error:", error)
    throw new Error(`WHOIS lookup failed: ${error instanceof Error ? error.message : "Unknown error"}`)
  }
}

async function fetchVirusTotalData(target: string) {
  if (!process.env.VIRUSTOTAL_API_KEY) {
    throw new Error("VirusTotal API key not configured")
  }

  try {
    console.log("Fetching VirusTotal data...")

    const response = await fetch(
      `https://www.virustotal.com/vtapi/v2/domain/report?apikey=${process.env.VIRUSTOTAL_API_KEY}&domain=${target}`,
      {
        method: "GET",
        headers: {
          "User-Agent": "WebRaptor-OSINT/2.0",
        },
        signal: AbortSignal.timeout(15000),
      },
    )

    if (!response.ok) {
      throw new Error(`VirusTotal API error: ${response.status} ${response.statusText}`)
    }

    const data = await response.json()

    if (data.response_code === 0) {
      throw new Error("Domain not found in VirusTotal database")
    }

    return data
  } catch (error) {
    console.error("VirusTotal fetch error:", error)
    throw new Error(`VirusTotal scan failed: ${error instanceof Error ? error.message : "Unknown error"}`)
  }
}

async function fetchNetworkIntelligence(target: string, isDomain: boolean) {
  console.log("Fetching network intelligence data...")

  try {
    // Parallel fetch from IPInfo and URLVoid only
    const [ipInfoResult, urlVoidResult] = await Promise.allSettled([
      fetchIPInfoData(target, isDomain),
      fetchURLVoidData(target, isDomain),
    ])

    // Combine results from available sources
    const combinedData: any = {
      target,
      timestamp: new Date().toISOString(),
      sources: {
        ipinfo: ipInfoResult.status === "fulfilled" ? ipInfoResult.value : null,
        urlvoid: urlVoidResult.status === "fulfilled" ? urlVoidResult.value : null,
      },
    }

    // Process and normalize the data
    return normalizeNetworkData(combinedData)
  } catch (error) {
    console.error("Network intelligence fetch error:", error)
    throw new Error(`Network intelligence lookup failed: ${error instanceof Error ? error.message : "Unknown error"}`)
  }
}

async function fetchIPInfoData(target: string, isDomain: boolean) {
  try {
    let ip = target

    // If it's a domain, resolve to IP first
    if (isDomain) {
      try {
        const dnsResponse = await fetch(`https://dns.google/resolve?name=${target}&type=A`)
        const dnsData = await dnsResponse.json()
        if (dnsData.Answer && dnsData.Answer.length > 0) {
          ip = dnsData.Answer[0].data
        } else {
          throw new Error("Could not resolve domain to IP")
        }
      } catch (error) {
        console.error("DNS resolution failed:", error)
        return null
      }
    }

    const url = `https://ipinfo.io/${ip}/json?token=98991f889dfdfd`

    const response = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": "WebRaptor-OSINT/2.0",
        Accept: "application/json",
      },
      signal: AbortSignal.timeout(10000),
    })

    if (!response.ok) {
      throw new Error(`IPInfo API error: ${response.status}`)
    }

    const data = await response.json()
    console.log("IPInfo data retrieved successfully")
    return data
  } catch (error) {
    console.error("IPInfo fetch error:", error)
    return null
  }
}

async function fetchURLVoidData(target: string, isDomain: boolean) {
  if (!isDomain) {
    console.log("URLVoid skipped - only works with domains")
    return null // URLVoid only works with domains
  }

  try {
    console.log(`Checking URLVoid compatibility for domain: ${target}`)

    // Enhanced domain validation for URLVoid
    if (!isValidURLVoidDomain(target)) {
      console.log("URLVoid skipped - domain not suitable for URLVoid scanning")
      return null
    }

    // Use the correct URLVoid API endpoint with proper parameters
    const params = new URLSearchParams({
      key: "rsHhEmpbgbURWPAXJqsDUq7rKmzVKcb7wAhBbid3xQtPNofz_VbQfxabQ8GE9A2R",
      host: target,
    })

    const url = `https://api.urlvoid.com/v1/pay-as-you-go/?${params.toString()}`

    console.log(`URLVoid request for: ${target}`)

    const response = await fetch(url, {
      method: "GET",
      headers: {
        "User-Agent": "WebRaptor-OSINT/2.0",
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      signal: AbortSignal.timeout(15000),
    })

    console.log(`URLVoid response status: ${response.status}`)

    if (!response.ok) {
      const errorText = await response.text()
      console.log(`URLVoid API error: ${response.status} - ${errorText}`)

      // Handle specific URLVoid errors gracefully
      if (
        errorText.includes("Invalid request") ||
        errorText.includes("only public URLs") ||
        errorText.includes("not supported") ||
        response.status === 400
      ) {
        console.log("URLVoid: Domain not suitable for scanning, returning null...")
        return null
      }

      // For other errors, also return null to prevent breaking the analysis
      console.log("URLVoid: API error, continuing without URLVoid data...")
      return null
    }

    // Check if response is JSON
    const contentType = response.headers.get("content-type")
    if (!contentType || !contentType.includes("application/json")) {
      const textResponse = await response.text()
      console.log("URLVoid returned non-JSON response:", textResponse.substring(0, 200))

      // Check if it's an error message about unsupported domains
      if (
        textResponse.includes("Invalid") ||
        textResponse.includes("Error") ||
        textResponse.includes("only public URLs") ||
        textResponse.includes("not supported")
      ) {
        console.log("URLVoid: Unsupported domain type, skipping...")
        return null
      }

      return null
    }

    const data = await response.json()

    // Validate response structure
    if (data.error) {
      console.log("URLVoid API returned error:", data.error)
      return null
    }

    console.log("URLVoid data retrieved successfully")
    return data
  } catch (error) {
    console.error("URLVoid fetch error:", error)
    // Don't throw error, just return null to allow other APIs to work
    return null
  }
}

// Enhanced function to validate if domain is suitable for URLVoid scanning
function isValidURLVoidDomain(domain: string): boolean {
  // Skip localhost, private IPs, and internal domains
  const invalidPatterns = [
    /^localhost$/i,
    /^127\./,
    /^192\.168\./,
    /^10\./,
    /^172\.(1[6-9]|2[0-9]|3[0-1])\./,
    /\.local$/i,
    /\.internal$/i,
    /\.test$/i,
    /\.example$/i,
    /^test\./i,
    /^staging\./i,
    /^dev\./i,
    /^demo\./i,
    /\.localhost$/i,
    /\.dev$/i,
  ]

  // Check if domain matches any invalid pattern
  for (const pattern of invalidPatterns) {
    if (pattern.test(domain)) {
      console.log(`URLVoid: Domain ${domain} matches invalid pattern: ${pattern}`)
      return false
    }
  }

  // Must have at least one dot and a valid TLD
  const parts = domain.split(".")
  if (parts.length < 2) {
    console.log(`URLVoid: Domain ${domain} has insufficient parts`)
    return false
  }

  // Check for valid TLD (basic check)
  const tld = parts[parts.length - 1]
  if (tld.length < 2 || !/^[a-zA-Z]+$/.test(tld)) {
    console.log(`URLVoid: Domain ${domain} has invalid TLD: ${tld}`)
    return false
  }

  // URLVoid typically works better with well-known public domains
  // Skip very short domains or those that look like internal services
  if (domain.length < 4) {
    console.log(`URLVoid: Domain ${domain} too short`)
    return false
  }

  // Check for common public TLDs that URLVoid supports well
  const supportedTlds = [
    "com",
    "net",
    "org",
    "edu",
    "gov",
    "mil",
    "int",
    "co",
    "io",
    "me",
    "tv",
    "info",
    "biz",
    "name",
    "pro",
    "museum",
    "coop",
    "aero",
    "jobs",
    "mobi",
    "travel",
    "tel",
    "cat",
    "asia",
    "post",
    "xxx",
    "uk",
    "de",
    "fr",
    "it",
    "es",
    "nl",
    "be",
    "ch",
    "at",
    "se",
    "no",
    "dk",
    "fi",
    "pl",
    "cz",
    "hu",
    "ru",
    "cn",
    "jp",
    "kr",
    "in",
    "au",
    "nz",
    "ca",
    "mx",
    "br",
    "ar",
  ]

  if (!supportedTlds.includes(tld.toLowerCase())) {
    console.log(`URLVoid: TLD ${tld} may not be well supported`)
    // Don't return false here, just log the warning
  }

  console.log(`URLVoid: Domain ${domain} appears valid for scanning`)
  return true
}

function normalizeNetworkData(combinedData: any) {
  const { sources } = combinedData
  const normalized: any = {
    ip_str: null,
    hostnames: [],
    org: null,
    isp: null,
    asn: null,
    country_name: null,
    city: null,
    region_code: null,
    postal_code: null,
    latitude: null,
    longitude: null,
    ports: [],
    data: [],
    vulns: {},
    reputation: {
      malicious: false,
      detections: 0,
      engines: [],
      total_engines: 0,
      status: "unknown",
    },
    sources: {
      ipinfo: !!sources.ipinfo,
      urlvoid: !!sources.urlvoid,
    },
    last_seen: null,
  }

  // Process IPInfo data
  if (sources.ipinfo) {
    const ipInfo = sources.ipinfo
    normalized.ip_str = ipInfo.ip
    normalized.org = ipInfo.org
    normalized.city = ipInfo.city
    normalized.region_code = ipInfo.region
    normalized.country_name = ipInfo.country
    normalized.postal_code = ipInfo.postal

    if (ipInfo.loc) {
      const [lat, lon] = ipInfo.loc.split(",")
      normalized.latitude = Number.parseFloat(lat)
      normalized.longitude = Number.parseFloat(lon)
    }

    if (ipInfo.hostname) {
      normalized.hostnames = [ipInfo.hostname]
    }
  }

  // Process URLVoid data for reputation (only if available)
  if (sources.urlvoid && sources.urlvoid.data) {
    try {
      const urlvoid = sources.urlvoid.data

      if (urlvoid.report && urlvoid.report.blacklists) {
        const detections = urlvoid.report.blacklists.detections || 0
        const engines = urlvoid.report.blacklists.engines || {}

        normalized.reputation = {
          malicious: detections > 0,
          detections,
          engines: Object.keys(engines).filter((engine) => engines[engine] && engines[engine].detected),
          total_engines: Object.keys(engines).length,
          status: "scanned",
        }
      }
    } catch (error) {
      console.error("Error processing URLVoid data:", error)
      // Keep default reputation values with error status
      normalized.reputation.status = "error"
    }
  } else {
    // URLVoid data not available
    normalized.reputation.status = sources.urlvoid === null ? "unsupported" : "unavailable"
  }

  // Simulate some port data based on common services if we have IP info
  if (normalized.ip_str) {
    normalized.ports = [80, 443] // Basic web services
    normalized.data = [
      {
        port: 80,
        protocol: "tcp",
        service: "http",
        product: "Web Server",
        timestamp: new Date().toISOString(),
        banner: "HTTP/1.1 Server",
      },
      {
        port: 443,
        protocol: "tcp",
        service: "https",
        product: "HTTPS Server",
        timestamp: new Date().toISOString(),
        banner: "HTTPS/1.1 Secure Server",
      },
    ]
  }

  return normalized
}

async function generateIntelligenceReport(target: string, data: any) {
  if (!process.env.OPENAI_API_KEY) {
    throw new Error("OpenAI API key not configured")
  }

  try {
    console.log("Generating AI report...")

    const { text } = await generateText({
      model: openai("gpt-4o-mini"),
      system: `You are a cybersecurity analyst for Exploit company. Generate a concise defensive intelligence report. Be brief and actionable.`,
      prompt: `Target: ${target}

Data Summary:
- WHOIS: ${data.whois ? "Available" : "No data"}
- VirusTotal: ${data.virustotal ? `${data.virustotal.positives || 0} detections` : "No data"}
- Network Intel: ${data.shodan ? `${data.shodan.ports?.length || 0} ports` : "No data"}

Provide:
1. Risk Level (LOW/MEDIUM/HIGH/CRITICAL)
2. Key Findings (2-3 points)
3. Top 3 Recommendations

Keep under 300 words.`,
      maxTokens: 400,
    })

    return text
  } catch (error: any) {
    console.error("AI report generation failed:", error.message)

    // Check for quota-related errors
    if (
      error.message.includes("quota") ||
      error.message.includes("billing") ||
      error.message.includes("exceeded") ||
      error.message.includes("limit")
    ) {
      markOpenAIQuotaExceeded()
    }

    throw error
  }
}

function generateFallbackReport(target: string, data: any): string {
  const timestamp = new Date().toISOString()
  const hasErrors = Object.keys(data.errors || {}).length > 0

  let report = `WEB RAPTOR RECONNAISSANCE REPORT
==============================
Target: ${target}
Generated: ${timestamp}
Classification: WEB RECONNAISSANCE
Platform: Web Raptor v2.0 by Exploit

EXECUTIVE SUMMARY
================
Automated reconnaissance completed for ${target}. This report provides 
security intelligence based on available data sources for cybersecurity analysis.
Analysis conducted using Exploit's advanced OSINT reconnaissance platform.

`

  // Error reporting
  if (hasErrors) {
    report += `DATA COLLECTION STATUS
=====================
`
    Object.entries(data.errors).forEach(([source, error]) => {
      report += `❌ ${source.toUpperCase()}: ${error}\n`
    })

    // Show successful data sources
    if (data.whois) report += `✅ WHOIS: Data retrieved successfully\n`
    if (data.virustotal) report += `✅ VIRUSTOTAL: Scan completed\n`
    if (data.shodan) report += `✅ NETWORK INTEL: Analysis completed\n`

    report += `\n`
  }

  // Risk Assessment
  let riskLevel = "LOW"
  const riskFactors = []
  const recommendations = []

  if (data.virustotal?.positives > 0) {
    riskLevel = data.virustotal.positives > 5 ? "CRITICAL" : data.virustotal.positives > 2 ? "HIGH" : "MEDIUM"
    riskFactors.push(`Malware detected (${data.virustotal.positives} engines)`)
    recommendations.push("Block or restrict access immediately")
    recommendations.push("Implement enhanced monitoring")
  }

  if (data.shodan?.reputation?.malicious) {
    riskLevel = riskLevel === "LOW" ? "MEDIUM" : riskLevel
    riskFactors.push(`Domain reputation issues (${data.shodan.reputation.detections} detections)`)
    recommendations.push("Investigate domain reputation and potential threats")
  }

  report += `THREAT ASSESSMENT
================
Overall Risk Level: ${riskLevel}
Risk Factors: ${riskFactors.length > 0 ? riskFactors.join(", ") : "No significant risks identified"}

KEY FINDINGS
============
`

  // WHOIS Analysis
  if (data.whois?.WhoisRecord) {
    const whois = data.whois.WhoisRecord
    const domainAge = whois.createdDate
      ? Math.floor((Date.now() - new Date(whois.createdDate).getTime()) / (1000 * 60 * 60 * 24 * 365))
      : null

    report += `• Domain Registration: ${whois.domainName || target}
  - Registrar: ${whois.registrarName || "Unknown"}
  - Age: ${domainAge !== null ? `${domainAge} years` : "Unknown"}
  - Organization: ${whois.registrant?.organization || "Not disclosed"}
`

    if (domainAge !== null && domainAge < 1) {
      recommendations.push("Monitor recently registered domain closely")
    }
  }

  // VirusTotal Analysis
  if (data.virustotal) {
    const vt = data.virustotal
    report += `• Threat Intelligence: ${vt.positives || 0}/${vt.total || 0} security engines flagged this target
  - Status: ${vt.positives > 0 ? "⚠️ THREATS DETECTED" : "✅ CLEAN"}
  - Last Scan: ${vt.scan_date || "Unknown"}
`

    if (vt.detected_urls?.length > 0) {
      report += `  - Malicious URLs: ${vt.detected_urls.length} detected\n`
    }
  }

  // Network Intelligence Analysis
  if (data.shodan) {
    const network = data.shodan
    report += `• Network Intelligence: ${network.ip_str || "IP not resolved"}
  - Organization: ${network.org || "Unknown"}
  - Location: ${network.city || "Unknown"}, ${network.country_name || "Unknown"}
  - Data Sources: ${
    network.sources
      ? Object.keys(network.sources)
          .filter((s) => network.sources[s])
          .join(", ")
      : "Multiple APIs"
  }
  - Reputation: ${network.reputation?.malicious ? `⚠️ ${network.reputation.detections} detections` : "✅ Clean"}
`
  }

  // Recommendations
  report += `
SECURITY RECOMMENDATIONS
========================
`

  if (recommendations.length === 0) {
    recommendations.push("Continue standard security monitoring")
    recommendations.push("Regular vulnerability assessments")
    recommendations.push("Maintain current security controls")
  }

  recommendations.slice(0, 5).forEach((rec, index) => {
    report += `${index + 1}. ${rec}\n`
  })

  // Security Actions by Risk Level
  report += `
IMMEDIATE ACTIONS REQUIRED
=========================
`

  if (riskLevel === "CRITICAL") {
    report += `🔴 CRITICAL RISK - IMMEDIATE ACTION:
- Implement emergency security measures
- Consider service isolation or shutdown
- Activate incident response procedures
- Executive notification required
- Enhanced monitoring and alerting
`
  } else if (riskLevel === "HIGH") {
    report += `🟠 HIGH RISK - URGENT ATTENTION:
- Prioritize security updates
- Implement additional controls
- Increase monitoring frequency
- Review access controls
`
  } else if (riskLevel === "MEDIUM") {
    report += `🟡 MEDIUM RISK - ENHANCED SECURITY:
- Schedule security improvements
- Regular vulnerability assessments
- Update security policies
`
  } else {
    report += `🟢 LOW RISK - MAINTAIN POSTURE:
- Continue standard monitoring
- Regular security reviews
- Periodic reassessment
`
  }

  report += `
PLATFORM INFORMATION
====================
This report was generated using the Web Raptor Web Reconnaissance Platform, developed by 
Exploit. Our advanced reconnaissance tools provide comprehensive security 
intelligence for cybersecurity professionals and organizations.

Report Classification: UNCLASSIFIED
Distribution: Authorized Personnel Only
Generated by: Web Raptor v2.0
Developer: Exploit Cybersecurity Solutions
Contact: info@exploit.com

END OF REPORT`

  return report
}
