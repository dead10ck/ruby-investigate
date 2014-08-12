require 'spec_helper'
require 'time'

describe "Investigate" do
  before(:all) do
    @sg = Investigate.new(ENV['INVESTIGATE_KEY'])
  end

  def has_keys?(data={}, keys=[])
    keys.each do |key|
      expect(data.has_key?(key)).to eq true
    end
  end

  it "does categorization() correctly" do
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

  it "does rr_history() correctly" do
    # query an IP
    data = @sg.rr_history('208.64.121.161')
    has_keys?(data, ['features', 'rrs'])

    # query a domain
    data = @sg.rr_history('www.test.com')
    has_keys?(data, ['features', 'rrs_tf'])

    # query a domain with a different query_type
    data = @sg.rr_history('www.test.com', 'NS')
    has_keys?(data, ['rrs_tf'])

    # trying an unsupported query type should raise an error
    lambda { @sg.rr_history('www.test.com', 'AFSDB') }.should raise_error
  end

  it "does related_domains() correctly" do
    data = @sg.related_domains('www.test.com')
    has_keys?(data, ['found', 'tb1'])
  end

  it "does cooccurrences() correctly" do
    data = @sg.cooccurrences('www.test.com')
    has_keys?(data, ['found', 'pfs2'])
  end

  it "does security() correctly" do
    data = @sg.security('www.test.com')
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

  it "does domain_tags() correctly" do
    resp_json = @sg.domain_tags('bibikun.ru')
    resp_json.each do |tag_entry|
      has_keys?(tag_entry, ['category', 'period', 'url'])
      has_keys?(tag_entry['period'], ['begin', 'end'])
    end
  end
end
