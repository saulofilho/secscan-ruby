# frozen_string_literal: true

require "fileutils"
require "json"
require "tmpdir"

RSpec.describe Secscan do
  it "computes entropy and masks the literal" do
    expect(described_class.calculate_entropy("")).to eq(0.0)
    expect(described_class.calculate_entropy("AKIAIOSFODNN7EXAMPLE")).to be > 3.5
    masked = described_class.mask_secret("AKIAIOSFODNN7EXAMPLE")
    expect(masked).to start_with("AKIA")
    expect(masked).to end_with("MPLE")
    expect(masked).not_to include("IOSFODNN7EXA")
  end

  it "scores one AWS key as elevated impact" do
    report = described_class.scan_text(AWS_LINE, path: "src/app.js")
    expect(report.findings.map(&:rule_id)).to eq(["sec-aws-akid"])
    expect(report.metrics.critical_count).to eq(1)
    expect(report.metrics.security_impact_score).to eq(37)
    expect(report.metrics.impact_level).to eq("ELEVATED")
    expect(report.findings.first.file_criticality).to eq("MEDIUM")
  end

  it "finds a database URI and an admin route" do
    source = <<~JS
      const db = "postgres://admin:SuperSecretPass123@db.prod.internal:5432/main";
      app.get("/api/v1/admin/users", handler);
    JS
    report = described_class.scan_text(source, path: "src/routes/users.js")
    ids = report.findings.map(&:rule_id)
    expect(ids).to include("sec-db-uri", "sec-sensitive-api-path")
    expect(report.api_endpoints.first.method).to eq("GET")
    expect(report.api_endpoints.first.is_internal_or_admin).to be(true)
  end

  it "skips low-entropy matches and invalid patterns" do
    rules = [
      Secscan::Rule.new(id: "sec-low", name: "Low", pattern: "a+", severity: "HIGH", category: "CUSTOM", description: "low", min_entropy: 4.0),
      Secscan::Rule.new(id: "sec-bad", name: "Bad", pattern: "(", severity: "HIGH", category: "CUSTOM", description: "bad")
    ]
    report = described_class.scan_text("const value = 'aaaaaaa';\n", path: "src/app.js", rules: rules)
    expect(report.findings).to be_empty
  end

  it "keeps literals out of the JSON and SARIF reports" do
    report = described_class.scan_text(AWS_LINE, path: "src/app.js")
    payload = Secscan::Report.to_json(report)
    expect(payload).not_to include("AKIAIOSFODNN7EXAMPLE")
    expect(payload).to include("sec-aws-akid")
    sarif = JSON.parse(Secscan::Report.to_sarif(report))
    expect(sarif["version"]).to eq("2.1.0")
    message = sarif["runs"][0]["results"][0]["message"]["text"]
    expect(message).not_to include("AKIAIOSFODNN7EXAMPLE")
  end

  it "ignores node_modules and a custom tests pattern" do
    Dir.mktmpdir do |dir|
      FileUtils.mkdir_p(File.join(dir, "src"))
      File.write(File.join(dir, "src", "app.js"), AWS_LINE)
      FileUtils.mkdir_p(File.join(dir, "node_modules", "pkg"))
      File.write(File.join(dir, "node_modules", "pkg", "index.js"), AWS_LINE)
      FileUtils.mkdir_p(File.join(dir, "tests"))
      File.write(File.join(dir, "tests", "leak.js"), AWS_LINE)

      report = described_class.scan(dir, ignore: ["tests/*"])
      expect(report.findings.map(&:file)).to eq(["src/app.js"])
    end
  end

  it "merges a custom rules file with the built-in set" do
    Dir.mktmpdir do |dir|
      path = File.join(dir, "rules.json")
      File.write(path, JSON.generate([{
        "id" => "sec-demo",
        "name" => "Demo",
        "pattern" => "SECSCAN_DEMO_[A-Z0-9]{8}",
        "severity" => "LOW",
        "category" => "CUSTOM",
        "description" => "demo",
        "minEntropy" => 1
      }]))
      loaded = described_class.load_rules(path)
      expect(loaded.map(&:id)).to include("sec-aws-akid", "sec-demo")
    end
  end
end
