require 'spec_helper'
require 'time'
require 'pp'

describe "Investigate" do
  before(:all) do
    @sg = Investigate.new(ENV['INVESTIGATE_KEY'])
  end

  def has_keys?(data={}, keys=[])
    keys.each do |key|
      expect(data.has_key?(key)).to eq true
    end
  end

  it "does get_ip() correctly" do
    data = @sg.get_ip('208.64.121.161')
    has_keys?(data, ['features', 'rrs'])
  end

  it "does get_domain() correctly" do
    data = @sg.get_domain('www.test.com')
    has_keys?(data, ['features', 'rrs_tf'])
  end

  it "does get_related_domains() correctly" do
    data = @sg.get_related_domains('www.test.com')
    has_keys?(data, ['found', 'tb1'])
  end

  it "does get_cooccurrences() correctly" do
    data = @sg.get_cooccurrences('www.test.com')
    has_keys?(data, ['found', 'pfs2'])
  end

  it "does get_security() correctly" do
    data = @sg.get_security('www.test.com')
    keys = [
      "dga_score",
      "perplexity",
      "entropy",
      "securerank2",
      "pagerank",
      "asn_score",
      "prefix_score",
      "rip_score",
      "fastflux",
      "popularity",
      "geodiversity",
      "geodiversity_normalized",
      "tld_geodiversity",
      "geoscore",
      "ks_test",
      "handlings",
      "attack",
      "threat_type",
      "found"
    ]
    has_keys?(data, keys)
  end
end
