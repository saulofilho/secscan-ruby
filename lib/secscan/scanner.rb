# frozen_string_literal: true

require "json"
require "pathname"
require "time"

module Secscan
  SCAN_SUFFIXES = %w[.js .jsx .ts .tsx .mjs .cjs .json .env .yaml .yml].freeze
  SKIP_DIR_NAMES = %w[.git node_modules vendor dist build out coverage bower_components .cache].freeze
  MAX_FILE_BYTES = 1_048_576
  API_CALL_RE = /(?:app\.(get|post|put|delete|patch)|router\.(get|post|put|delete|patch)|axios\.(get|post|put|delete|patch)|fetch)\s*\(\s*['"`]([^'"`]+)['"`]/i
  SENSITIVE_PATH_RE = /admin|internal|superadmin|debug|token|actuator|secret/i

  Finding = Struct.new(
    :id, :rule_id, :rule_name, :category, :severity, :file, :line, :column,
    :snippet, :matched_secret, :masked_secret, :entropy, :description,
    :remediation, :file_criticality, :file_criticality_weight, :weighted_score,
    keyword_init: true
  ) do
    def public_snippet(reveal = false)
      return snippet if reveal || matched_secret.to_s.empty?

      snippet.gsub(matched_secret, masked_secret)
    end
  end

  ApiEndpoint = Struct.new(
    :id, :file, :line, :method, :path, :is_internal_or_admin, :snippet,
    keyword_init: true
  )

  Metrics = Struct.new(
    :critical_count, :high_count, :medium_count, :low_count, :info_count,
    :security_score, :security_impact_score, :impact_level, :total_weighted_risk,
    :average_entropy,
    keyword_init: true
  )

  ScanReport = Struct.new(
    :scanner, :version, :timestamp, :target, :total_files, :scanned_files_count,
    :ignored_files_count, :findings, :api_endpoints, :metrics, :duration_ms,
    keyword_init: true
  )

  module Scanner
    module_function

    def calculate_entropy(value)
      return 0.0 if value.nil? || value.empty?

      length = value.length.to_f
      entropy = value.each_char.tally.each_value.sum do |count|
        probability = count / length
        -probability * Math.log2(probability)
      end
      format("%.2f", entropy).to_f
    end

    def mask_secret(secret)
      return "" if secret.nil? || secret.empty?

      clean = secret.strip.gsub(/\A['"]|['"]\z/, "")
      return "••••••••" if clean.length <= 8

      hidden = [16, [6, clean.length - 8].max].min
      "#{clean[0, 4]}#{'•' * hidden}#{clean[-4, 4]}"
    end

    def scan_path(path, rules: nil, ignore: [])
      root = File.expand_path(path.to_s)
      raise InputError, "path not found: #{path}" unless File.exist?(root)

      files, seen, ignored = collect_files(root, ignore)
      scan_files(files, rules: rules, ignore: ignore, target: path.to_s, ignored_files_count: ignored, total_files: seen)
    end

    def scan_text(content, path: "snippet", rules: nil, ignore: [])
      scan_files([[path, content]], rules: rules, ignore: ignore, target: path)
    end

    def load_rules(path = nil, replace: false)
      rules = replace ? [] : DEFAULT_RULES.dup
      return rules.select(&:enabled) if path.nil?

      raise InputError, "rules file not found: #{path}" unless File.file?(path)

      begin
        payload = JSON.parse(File.read(path, encoding: "UTF-8"))
      rescue JSON::ParserError
        raise InputError, "rules file is not valid JSON: #{path}"
      end
      raise InputError, "rules file must be a JSON array" unless payload.is_a?(Array)

      payload.each do |item|
        raise InputError, "each rule must be a JSON object" unless item.is_a?(Hash)

        begin
          min_entropy = item.key?("minEntropy") ? item["minEntropy"] : item["min_entropy"]
          rules << Rule.new(
            id: item.fetch("id"),
            name: item.fetch("name"),
            pattern: item.fetch("pattern"),
            severity: item["severity"] || "MEDIUM",
            category: item["category"] || "CUSTOM",
            description: item["description"] || "",
            remediation: item["remediation"] || "",
            flags: item["flags"] || "g",
            min_entropy: min_entropy.nil? ? nil : min_entropy.to_f,
            enabled: item.fetch("enabled", true)
          )
        rescue ArgumentError, KeyError => e
          raise InputError, "invalid rule: #{e.message}"
        end
      end
      rules.select(&:enabled)
    end

    def scan_files(files, rules: nil, ignore: [], target: "memory", ignored_files_count: 0, total_files: nil)
      started = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      active = rules.nil? ? DEFAULT_RULES : rules
      compiled = active.map { |rule| [rule, compile_rule(rule)] }
      findings = []
      endpoints = []
      scanned = 0
      extra_ignored = 0

      files.each do |rel_path, content|
        if ignore_reason(rel_path, ignore)
          extra_ignored += 1
          next
        end
        scanned += 1
        level, weight, = evaluate_file_criticality(rel_path)

        compiled.each do |rule, pattern|
          next if pattern.nil?

          content.scan(pattern) do
            match = Regexp.last_match
            literal = match[0]
            next if literal.nil? || literal.empty?

            entropy = calculate_entropy(literal)
            next if !rule.min_entropy.nil? && entropy < rule.min_entropy

            line, column, snippet = line_column(content, match.begin(0))
            base = SEVERITY_BASE_WEIGHTS.fetch(rule.severity, 5)
            findings << Finding.new(
              id: "finding-#{findings.length + 1}",
              rule_id: rule.id,
              rule_name: rule.name,
              category: rule.category,
              severity: rule.severity,
              file: rel_path,
              line: line,
              column: column,
              snippet: snippet,
              matched_secret: literal,
              masked_secret: mask_secret(literal),
              entropy: entropy,
              description: rule.description,
              remediation: rule.remediation,
              file_criticality: level,
              file_criticality_weight: weight,
              weighted_score: format("%.1f", base * weight).to_f
            )
          end
        end

        content.scan(API_CALL_RE) do
          match = Regexp.last_match
          raw_path = match[4].to_s
          next unless raw_path.start_with?("/") || raw_path.start_with?("http")

          method = (match[1] || match[2] || match[3] || "GET").upcase
          line, = line_column(content, match.begin(0))
          endpoints << ApiEndpoint.new(
            id: "endpoint-#{endpoints.length + 1}",
            file: rel_path,
            line: line,
            method: method,
            path: raw_path,
            is_internal_or_admin: SENSITIVE_PATH_RE.match?(raw_path),
            snippet: line_column(content, match.begin(0))[2]
          )
        end
      end

      counts = SEVERITY_RANK.keys.to_h { |name| [name, 0] }
      findings.each { |finding| counts[finding.severity] += 1 }
      deduction = (counts["CRITICAL"] * 25) + (counts["HIGH"] * 12) + (counts["MEDIUM"] * 5) + (counts["LOW"] * 2)
      security_score = [[100 - deduction, 0].max, 100].min
      impact, weighted, impact_level = calculate_security_impact(findings)
      average = findings.empty? ? 0.0 : format("%.2f", findings.sum(&:entropy) / findings.length.to_f).to_f
      elapsed = ((Process.clock_gettime(Process::CLOCK_MONOTONIC) - started) * 1000).round

      ScanReport.new(
        scanner: "SecScan SAST",
        version: VERSION,
        timestamp: Time.now.utc.iso8601,
        target: target,
        total_files: total_files.nil? ? files.length : total_files,
        scanned_files_count: scanned,
        ignored_files_count: ignored_files_count + extra_ignored,
        findings: findings,
        api_endpoints: endpoints,
        metrics: Metrics.new(
          critical_count: counts["CRITICAL"],
          high_count: counts["HIGH"],
          medium_count: counts["MEDIUM"],
          low_count: counts["LOW"],
          info_count: counts["INFO"],
          security_score: security_score,
          security_impact_score: impact,
          impact_level: impact_level,
          total_weighted_risk: weighted,
          average_entropy: average
        ),
        duration_ms: elapsed
      )
    end

    def calculate_security_impact(findings)
      return [0, 0.0, "NOMINAL"] if findings.empty?

      total = format("%.1f", findings.sum(&:weighted_score)).to_f
      normalized = 100 * (1 - Math.exp(-total / 55.0))
      score = [[normalized.round, 1].max, 100].min
      level = if score >= 80
                "CRITICAL"
              elsif score >= 60
                "HIGH"
              elsif score >= 35
                "ELEVATED"
              elsif score >= 15
                "MODERATE"
              elsif score.positive?
                "LOW"
              else
                "NOMINAL"
              end
      [score, total, level]
    end

    def evaluate_file_criticality(file_path)
      normalized = file_path.to_s.tr("\\", "/").downcase
      file_name = normalized.split("/").last.to_s

      if normalized.include?(".env") || normalized.include?("credentials") || normalized.include?("secret") ||
         normalized.include?("id_rsa") || file_name.end_with?(".pem", ".key", ".pfx", ".keystore") ||
         normalized.start_with?("config/") || normalized.include?("/config/") ||
         file_name.include?("cloudconfig") || file_name.include?("dbconfig") || file_name.include?("database") ||
         file_name == "dockerfile" || file_name.start_with?("docker-compose") ||
         normalized.include?("k8s/") || normalized.include?("kubernetes/") || normalized.include?("helm/") ||
         %w[server.ts server.js].include?(file_name)
        return ["CRITICAL", FILE_CRITICALITY_MULTIPLIERS["CRITICAL"], "CONFIG_INFRA_SECRETS"]
      end

      if normalized.include?("/services/") || normalized.include?("/controllers/") || normalized.include?("/routes/") ||
         normalized.include?("/api/") || normalized.include?("/handlers/") || normalized.include?("/backend/") ||
         normalized.include?("/auth") || normalized.include?("payment") || normalized.include?("checkout") ||
         normalized.include?("webhook") || file_name.include?("authservice") || file_name.include?("paymentcontroller") ||
         normalized.include?("firebase.json") || normalized.include?("cloudbuild") || normalized.include?("terraform")
        return ["HIGH", FILE_CRITICALITY_MULTIPLIERS["HIGH"], "BACKEND_API_SERVICE"]
      end

      if normalized.include?("/test/") || normalized.include?("/tests/") || normalized.include?("/__tests__/") ||
         normalized.include?("/mocks/") || normalized.include?("/fixtures/") || normalized.include?("/docs/") ||
         file_name.end_with?(".test.ts", ".test.js", ".spec.ts", ".spec.js", ".md", ".txt", ".css", ".svg")
        return ["LOW", FILE_CRITICALITY_MULTIPLIERS["LOW"], "TEST_DOC_FIXTURE"]
      end

      ["MEDIUM", FILE_CRITICALITY_MULTIPLIERS["MEDIUM"], "APPLICATION_CLIENT"]
    end

    def matches_ignore_pattern(file_path, raw_pattern)
      return false if raw_pattern.nil? || raw_pattern.empty? || file_path.nil? || file_path.empty?

      pattern = raw_pattern.strip.tr("\\", "/")
      return false if pattern.empty? || pattern.start_with?("#")

      normalized_path = normalize_rel(file_path)
      normalized_pattern = normalize_rel(pattern)
      return true if normalized_path == normalized_pattern

      if normalized_pattern.end_with?("/*", "/**", "/")
        folder = normalized_pattern.sub(%r{(/\*+|/)\z}, "")
        return true if normalized_path == folder || normalized_path.start_with?("#{folder}/") ||
                       "/#{normalized_path}".include?("/#{folder}/")
      end

      if !normalized_pattern.include?("*") && !normalized_pattern.include?(".")
        return true if normalized_path == normalized_pattern || normalized_path.start_with?("#{normalized_pattern}/") ||
                       "/#{normalized_path}".include?("/#{normalized_pattern}/") ||
                       normalized_path.end_with?("/#{normalized_pattern}")
      end

      if normalized_pattern.start_with?("*.")
        suffix = normalized_pattern[1..]
        if suffix.end_with?(".*")
          base = suffix[0..-3]
          return true if normalized_path.include?("#{base}.") || normalized_path.end_with?(base)
        elsif normalized_path.end_with?(suffix)
          return true
        end
      end

      glob_match?(normalized_path, normalized_pattern)
    end

    def ignore_reason(file_path, custom_patterns = [])
      Array(custom_patterns).each do |pattern|
        return "ignore:#{pattern}" if matches_ignore_pattern(file_path, pattern)
      end

      normalized = file_path.to_s.tr("\\", "/").downcase
      padded = "/#{normalized}"
      return "node_modules" if padded.include?("/node_modules/") || normalized.start_with?("node_modules/")
      return "vendor" if padded.include?("/vendor/") || normalized.start_with?("vendor/")
      return "bower_components" if padded.include?("/bower_components/")
      return "git" if padded.include?("/.git/") || normalized.start_with?(".git/")
      return "build" if %w[/dist/ /build/ /out/].any? { |token| padded.include?(token) } ||
                        normalized.start_with?("dist/", "build/", "out/")
      return "bundle" if normalized.end_with?(".min.js", ".bundle.js") || normalized.include?(".chunk.js")
      return "lockfile" if normalized.end_with?("package-lock.json", "yarn.lock", "pnpm-lock.yaml")
      return "cache" if padded.include?("/coverage/") || padded.include?("/.cache/")

      nil
    end

    def normalize_rel(value)
      text = value.to_s.strip.tr("\\", "/")
      text = text[2..] if text.start_with?("./")
      text = text[1..] if text.start_with?("/")
      text.downcase
    end

    def glob_match?(path, pattern)
      parts = []
      index = 0
      while index < pattern.length
        if pattern[index, 2] == "**"
          parts << ".*"
          index += 2
        elsif pattern[index] == "*"
          parts << "[^/]*"
          index += 1
        elsif pattern[index] == "?"
          parts << "."
          index += 1
        else
          parts << Regexp.escape(pattern[index])
          index += 1
        end
      end
      /(?:^|\/)#{parts.join}(?:$|\/)/.match?(path)
    end

    def compile_rule(rule)
      pattern = rule.pattern.to_s.dup
      flags = rule.flags.to_s
      if pattern.start_with?("(?i)")
        pattern = pattern[4..]
        flags += "i" unless flags.include?("i")
      end
      options = flags.include?("i") ? Regexp::IGNORECASE : 0
      Regexp.new(pattern, options)
    rescue RegexpError
      nil
    end

    def line_column(content, index)
      prefix = content[0...index].to_s
      line = prefix.count("\n") + 1
      column = prefix.split("\n", -1).last.to_s.length + 1
      snippet = content.split("\n", -1)[line - 1].to_s.strip
      [line, column, snippet]
    end

    def scannable?(path)
      name = File.basename(path)
      return true if name == ".env" || name.start_with?(".env.")

      SCAN_SUFFIXES.include?(File.extname(name).downcase)
    end

    def collect_files(root, custom_ignores)
      return collect_one(root, custom_ignores) if File.file?(root)

      files = []
      seen = 0
      ignored = 0
      Dir.glob(File.join(root, "**", "*"), File::FNM_DOTMATCH).each do |full|
        next unless File.file?(full)

        relative = Pathname.new(full).relative_path_from(Pathname.new(root)).to_s.tr("\\", "/")
        parts = relative.split("/")
        next if parts.any? { |part| SKIP_DIR_NAMES.include?(part) }
        next unless scannable?(full)

        seen += 1
        if ignore_reason(relative, custom_ignores)
          ignored += 1
          next
        end
        text = read_text(full)
        if text.nil?
          ignored += 1
          next
        end
        files << [relative, text]
      end
      [files, seen, ignored]
    end

    def collect_one(root, custom_ignores)
      relative = root.tr("\\", "/")
      return [[], 1, 1] if ignore_reason(relative, custom_ignores) || !scannable?(root)

      text = read_text(root)
      return [[], 1, 1] if text.nil?

      [[relative, text], 1, 0]
    end

    def read_text(path)
      return nil if File.size(path) > MAX_FILE_BYTES

      data = File.binread(path)
      return nil if data.include?("\0")

      data.force_encoding(Encoding::UTF_8)
      data.valid_encoding? ? data : data.encode("UTF-8", invalid: :replace, undef: :replace)
    rescue SystemCallError
      nil
    end
  end
end
