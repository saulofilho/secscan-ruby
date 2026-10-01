# frozen_string_literal: true

require_relative "secscan/version"
require_relative "secscan/errors"
require_relative "secscan/rules"
require_relative "secscan/scanner"
require_relative "secscan/report"
require_relative "secscan/cli"

module Secscan
  def self.scan(path, **options)
    Scanner.scan_path(path, **options)
  end

  def self.scan_text(content, **options)
    Scanner.scan_text(content, **options)
  end

  def self.load_rules(path = nil, **options)
    Scanner.load_rules(path, **options)
  end

  def self.calculate_entropy(value)
    Scanner.calculate_entropy(value)
  end

  def self.mask_secret(secret)
    Scanner.mask_secret(secret)
  end
end
