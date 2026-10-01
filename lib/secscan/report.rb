# frozen_string_literal: true

require "json"

module Secscan
  module Report
    SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

    module_function

    def to_h(report, reveal_secrets: false)
      {
        "scanner" => report.scanner,
        "version" => report.version,
        "timestamp" => report.timestamp,
        "target" => report.target,
        "totalFiles" => report.total_files,
        "scannedFilesCount" => report.scanned_files_count,
        "ignoredFilesCount" => report.ignored_files_count,
        "findings" => report.findings.map { |finding| finding_hash(finding, reveal_secrets) },
        "apiEndpoints" => report.api_endpoints.map { |endpoint| endpoint_hash(endpoint) },
        "metrics" => metrics_hash(report.metrics),
        "durationMs" => report.duration_ms
      }
    end

    def to_json(report, reveal_secrets: false)
      JSON.pretty_generate(to_h(report, reveal_secrets: reveal_secrets))
    end

    def to_csv(report, reveal_secrets: false)
      rows = [["ID", "Severity", "Rule Name", "Category", "File", "Line", "Column", "Entropy", "Masked Secret", "Remediation"]]
      report.findings.each do |finding|
        shown = reveal_secrets ? finding.matched_secret : finding.masked_secret
        rows << [
          finding.id, finding.severity, finding.rule_name, finding.category, finding.file,
          finding.line, finding.column, finding.entropy, shown, finding.remediation
        ]
      end
      rows.map { |row| row.map { |cell| csv_cell(cell) }.join(",") }.join("\n") + "\n"
    end

    def csv_cell(value)
      text = value.to_s
      return text unless text.match?(/[",\n]/)

      "\"#{text.gsub('"', '""')}\""
    end

    def to_sarif(report, reveal_secrets: false)
      rules = []
      seen = {}
      report.findings.each do |finding|
        next if seen[finding.rule_id]

        seen[finding.rule_id] = true
        level = %w[CRITICAL HIGH].include?(finding.severity) ? "error" : "warning"
        rules << {
          "id" => finding.rule_id,
          "name" => finding.rule_name,
          "shortDescription" => { "text" => finding.description },
          "help" => { "text" => finding.remediation },
          "defaultConfiguration" => { "level" => level }
        }
      end

      results = report.findings.map do |finding|
        level = %w[CRITICAL HIGH].include?(finding.severity) ? "error" : "warning"
        shown = reveal_secrets ? finding.matched_secret : finding.masked_secret
        {
          "ruleId" => finding.rule_id,
          "level" => level,
          "message" => { "text" => "#{finding.rule_name}. Value: #{shown}" },
          "locations" => [
            {
              "physicalLocation" => {
                "artifactLocation" => { "uri" => finding.file },
                "region" => {
                  "startLine" => finding.line,
                  "startColumn" => finding.column,
                  "snippet" => { "text" => finding.public_snippet(reveal_secrets) }
                }
              }
            }
          ]
        }
      end

      JSON.pretty_generate(
        "$schema" => SARIF_SCHEMA,
        "version" => "2.1.0",
        "runs" => [
          {
            "tool" => {
              "driver" => {
                "name" => "SecScan",
                "semanticVersion" => report.version,
                "informationUri" => "https://github.com/saulofilho/secscan",
                "rules" => rules
              }
            },
            "results" => results
          }
        ]
      )
    end

    def to_markdown(report, reveal_secrets: false)
      metrics = report.metrics
      findings_md = if report.findings.empty?
                      "_No secrets or sensitive routes found._"
                    else
                      report.findings.map { |finding| finding_markdown(finding, reveal_secrets) }.join("\n\n")
                    end
      routes = if report.api_endpoints.empty?
                 "_No endpoints mapped._"
               else
                 report.api_endpoints.map do |item|
                   suffix = item.is_internal_or_admin ? " **(sensitive)**" : ""
                   "- `#{item.method}` `#{item.path}` in `#{item.file}:#{item.line}`#{suffix}"
                 end.join("\n")
               end

      <<~MARKDOWN
        # SecScan report

        - **Target:** `#{report.target}`
        - **When:** #{report.timestamp}
        - **Files scanned:** #{report.scanned_files_count} (ignored: #{report.ignored_files_count})
        - **Findings:** #{report.findings.length}
        - **Security score:** #{metrics.security_score}/100
        - **Impact score:** #{metrics.security_impact_score}/100 (#{metrics.impact_level})

        ## Severity

        | Severity | Count |
        |---|---|
        | CRITICAL | #{metrics.critical_count} |
        | HIGH | #{metrics.high_count} |
        | MEDIUM | #{metrics.medium_count} |
        | LOW | #{metrics.low_count} |
        | INFO | #{metrics.info_count} |

        ## Findings

        #{findings_md}

        ## Endpoints (#{report.api_endpoints.length})

        #{routes}
      MARKDOWN
    end

    def to_table(report, reveal_secrets: false)
      metrics = report.metrics
      lines = [
        "SecScan Static Security Analysis",
        "Target: #{report.target} | Files: #{report.scanned_files_count} | Findings: #{report.findings.length} | #{report.duration_ms}ms",
        "Impact: #{metrics.security_impact_score}/100 (#{metrics.impact_level}) | Security score: #{metrics.security_score}/100",
        "-" * 72
      ]
      lines << "No exposed secrets or sensitive API paths detected." if report.findings.empty?
      report.findings.each do |finding|
        shown = reveal_secrets ? finding.matched_secret : finding.masked_secret
        lines << format("%-8s [%s]", finding.severity, finding.rule_name)
        lines << "  File:    #{finding.file}:#{finding.line}"
        lines << "  Secret:  #{shown} (entropy #{finding.entropy})"
        lines << "  Snippet: #{finding.public_snippet(reveal_secrets)}"
        lines << "  Info:    #{finding.description}"
        lines << ""
      end
      "#{lines.join("\n")}\n"
    end

    def render(report, format, reveal_secrets: false)
      case format.to_s.downcase
      when "json" then "#{to_json(report, reveal_secrets: reveal_secrets)}\n"
      when "csv" then to_csv(report, reveal_secrets: reveal_secrets)
      when "sarif" then "#{to_sarif(report, reveal_secrets: reveal_secrets)}\n"
      when "markdown" then to_markdown(report, reveal_secrets: reveal_secrets)
      when "table" then to_table(report, reveal_secrets: reveal_secrets)
      else
        raise InputError, "unknown format: #{format}"
      end
    end

    def finding_hash(finding, reveal_secrets)
      item = {
        "id" => finding.id,
        "ruleId" => finding.rule_id,
        "ruleName" => finding.rule_name,
        "category" => finding.category,
        "severity" => finding.severity,
        "file" => finding.file,
        "line" => finding.line,
        "column" => finding.column,
        "snippet" => finding.public_snippet(reveal_secrets),
        "maskedSecret" => finding.masked_secret,
        "entropy" => finding.entropy,
        "description" => finding.description,
        "remediation" => finding.remediation,
        "fileCriticality" => finding.file_criticality,
        "fileCriticalityWeight" => finding.file_criticality_weight,
        "weightedScore" => finding.weighted_score
      }
      item["matchedSecret"] = finding.matched_secret if reveal_secrets
      item
    end

    def endpoint_hash(endpoint)
      {
        "id" => endpoint.id,
        "file" => endpoint.file,
        "line" => endpoint.line,
        "method" => endpoint.method,
        "path" => endpoint.path,
        "isInternalOrAdmin" => endpoint.is_internal_or_admin,
        "snippet" => endpoint.snippet
      }
    end

    def metrics_hash(metrics)
      {
        "criticalCount" => metrics.critical_count,
        "highCount" => metrics.high_count,
        "mediumCount" => metrics.medium_count,
        "lowCount" => metrics.low_count,
        "infoCount" => metrics.info_count,
        "securityScore" => metrics.security_score,
        "securityImpactScore" => metrics.security_impact_score,
        "impactLevel" => metrics.impact_level,
        "totalWeightedRisk" => metrics.total_weighted_risk,
        "averageEntropy" => metrics.average_entropy
      }
    end

    def finding_markdown(finding, reveal_secrets)
      shown = reveal_secrets ? finding.matched_secret : finding.masked_secret
      <<~BLOCK.chomp
        ### [#{finding.severity}] #{finding.rule_name}
        - **File:** `#{finding.file}` (line #{finding.line})
        - **Value:** `#{shown}`
        - **Entropy:** #{finding.entropy}
        - **Description:** #{finding.description}
        - **Remediation:** #{finding.remediation}
      BLOCK
    end
  end
end
