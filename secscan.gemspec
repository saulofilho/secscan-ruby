# frozen_string_literal: true

require_relative "lib/secscan/version"

Gem::Specification.new do |spec|
  spec.name          = "secscan"
  spec.version       = Secscan::VERSION
  spec.authors       = ["Saulo Filho"]
  spec.email         = ["saulofilho@users.noreply.github.com"]

  spec.summary       = "SAST engine for secrets, Shannon entropy, API paths, and CI quality gates"
  spec.description   = <<~DESC
    Ruby gem that scans JavaScript and TypeScript trees for hardcoded secrets,
    high-entropy tokens, and sensitive API paths. Emits JSON, CSV, SARIF, and
    Markdown, and fails CI when a severity or cumulative impact score is exceeded.
  DESC
  spec.homepage      = "https://saulofilho.github.io/secscan/"
  spec.license       = "MIT"
  spec.required_ruby_version = ">= 3.1.0"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/saulofilho/secscan-ruby"
  spec.metadata["rubygems_mfa_required"] = "true"

  spec.files = Dir.chdir(__dir__) do
    Dir.glob("{lib,exe}/**/*", File::FNM_DOTMATCH) + %w[README.md LICENSE.txt CHANGELOG.md]
  end

  spec.bindir        = "exe"
  spec.executables   = ["secscan"]
  spec.require_paths = ["lib"]

  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.12"
end
