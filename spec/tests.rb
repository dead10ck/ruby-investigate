require 'spec_helper'
require 'time'

describe "SGraph" do
  before(:all) do
    @sg = SGraph.new(CERT_FILE, KEY_FILE)
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
    has_keys?(data, ["asn_score", "crank", "dga_score", "entropy",
      "fastflux", "found", "frequencyrank", "geodiversity", "geodiversity_normalized",
      "geoscore", "handlings", "ks_test", "pagerank", "perplexity", "popularity",
      "prefix_score", "rip_score", "securerank", "securerank2", "tags", "tld_geodiversity"])
  end

  it "does get_whois() correctly" do
    data = @sg.get_whois('www.test.com')
    has_keys?(data, ['found'])
  end

  it "does get_infected() correctly" do
    data = @sg.get_infected(['www.test.com', 'bibikun.ru'])
    has_keys?(data, ['scores'])
    has_keys?(data['scores'], ['www.test.com', 'bibikun.ru'])
  end

  it "does get_traffic() correctly" do
    start = Time.local(2013, "Dec", 13)
    stop = Time.now
    data = @sg.get_traffic('wikileaks.org', start, stop)
    has_keys?(data, ["elapsed", "function", "query", "response"])
  end

end