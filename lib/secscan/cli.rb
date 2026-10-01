# frozen_string_literal: true

require "optparse"

module Secscan
  class CLI
    FORMATS = %w[table json sarif csv markdown].freeze
    FAIL_LEVELS = %w[critical high medium low info].freeze

    def self.run(argv = ARGV)
      new.run(argv)
    end

    def run(argv)
      options = {
        format: "table",
        rules: nil,
        ignore: [],
        fail_on: nil,
        max_risk: nil,
        output: nil,
        reveal_secrets: false,
        version: false
      }
      parser = build_parser(options)
      parser.parse!(argv)
      if options[:version]
        puts "secscan #{VERSION}"
        return 0
      end
      target = argv[0] || "."

      rules = options[:rules] ? Scanner.load_rules(options[:rules]) : nil
      report = Scanner.scan_path(target, rules: rules, ignore: options[:ignore])
      text = Report.render(report, options[:format], reveal_secrets: options[:reveal_secrets])

      if options[:output]
        File.write(options[:output], text)
        warn "Report written to #{options[:output]}"
      else
        $stdout.write(text)
      end

      failure = gate_message(report, options[:fail_on], options[:max_risk])
      if failure
        warn failure
        return 1
      end
      0
    rescue OptionParser::ParseError, InputError => e
      warn "Error: #{e.message}"
      2
    end

    def gate_message(report, fail_on, max_risk)
      reasons = []
      if fail_on
        threshold = SEVERITY_RANK.fetch(fail_on.upcase)
        if report.findings.any? { |finding| SEVERITY_RANK.fetch(finding.severity) >= threshold }
          reasons << "findings with severity >= #{fail_on.upcase}"
        end
      end
      if !max_risk.nil? && report.metrics.security_impact_score > max_risk
        reasons << "impact score #{report.metrics.security_impact_score} acima de #{max_risk}"
      end
      return nil if reasons.empty?

      "SecScan quality gate: #{reasons.join('; ')}"
    end

    def build_parser(options)
      OptionParser.new do |opts|
        opts.banner = <<~BANNER
          Usage: secscan [path] [options]

          Static analysis for secrets, entropy, and API paths.

        BANNER
        opts.on("--format FORMAT", FORMATS, "table, json, sarif, csv, markdown") { |value| options[:format] = value }
        opts.on("--rules FILE", "JSON file with extra rules") { |value| options[:rules] = value }
        opts.on("--ignore LIST", "Extra ignore patterns, comma-separated") do |value|
          options[:ignore] = value.split(",").map(&:strip).reject(&:empty?)
        end
        opts.on("--fail-on LEVEL", FAIL_LEVELS, "Exit 1 if a finding meets or exceeds this severity") do |value|
          options[:fail_on] = value
        end
        opts.on("--max-risk SCORE", Float, "Exit 1 if the impact score exceeds the cap") { |value| options[:max_risk] = value }
        opts.on("--output FILE", "Write the report to this file") { |value| options[:output] = value }
        opts.on("--reveal-secrets", "Include the matched value in the report") { options[:reveal_secrets] = true }
        opts.on("-v", "--version", "Print version") { options[:version] = true }
      end
    end
  end
end
