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

  it "does get_categorization() correctly" do
    # test a single domain
    cat_keys = ["status", "security_categories", "content_categories"]
    resp_json = @sg.categorization('www.amazon.com')
    expect(resp_json.has_key?('www.amazon.com')).to eq true
    has_keys?(resp_json['www.amazon.com'], cat_keys)

    # test a domain with labels
    resp_json = @sg.categorization('www.amazon.com', true)
    expect(resp_json.has_key?('www.amazon.com')).to eq true
    has_keys?(resp_json['www.amazon.com'], cat_keys)

    # test a list of domains with labels
    domains = ['www.amazon.com', 'www.opendns.com', 'bibikun.ru']
    resp_json = @sg.categorization(domains, true)
    has_keys?(resp_json, domains)
    domains.each do |d|
      has_keys?(resp_json[d], cat_keys)
    end

    # calling with the wrong kind of object should raise an error
    lambda { @sg.categorization({"blah" => "hello"}) }.should raise_error
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
