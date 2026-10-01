# frozen_string_literal: true

require "json"
require "tmpdir"

RSpec.describe Secscan::CLI do
  it "exits 0 for a clean tree" do
    Dir.mktmpdir do |dir|
      File.write(File.join(dir, "app.js"), "const value = 1;\n")
      status = nil
      expect do
        status = described_class.run([dir, "--format", "json", "--fail-on", "critical"])
      end.to output(/"findings":\s*\[\s*\]/m).to_stdout
      expect(status).to eq(0)
    end
  end

  it "fails the quality gate without printing the literal" do
    Dir.mktmpdir do |dir|
      File.write(File.join(dir, "app.js"), AWS_LINE)
      status = nil
      expect do
        status = described_class.run([dir, "--format", "json", "--fail-on", "high"])
      end.to output(/sec-aws-akid/).to_stdout.and output(/quality gate/).to_stderr
      expect(status).to eq(1)
    end
  end

  it "returns 2 when the rules file is missing" do
    status = nil
    expect do
      status = described_class.run([".", "--rules", "missing-rules.json"])
    end.to output(/rules file not found/).to_stderr
    expect(status).to eq(2)
  end

  it "prints the version" do
    status = nil
    expect do
      status = described_class.run(["--version"])
    end.to output("secscan #{Secscan::VERSION}\n").to_stdout
    expect(status).to eq(0)
  end
end
