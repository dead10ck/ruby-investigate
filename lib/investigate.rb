require 'json'
require 'rest-client'

# Ruby API for the OpenDNS Security Graph
class Investigate
  VERSION = '1.0.0'
  SGRAPH_URL = 'https://investigate.api.opendns.com'
  SIPHASH_KEY = 'Umbrella/OpenDNS'
  SUPPORTED_DNS_TYPES = [
      "A",
      "NS",
      "MX",
      "TXT",
      "CNAME"
  ]

  # Builds a new Investigate object.
  def initialize(key)
      @res = RestClient::Resource.new(SGRAPH_URL,
              :headers => { "Authorization" => "Bearer #{key}" })
  end

  # Generic GET call to the API with the given URI
  # Parses the response into a JSON object
  def get(uri, params={})
    resp = @res[uri].get(:params => params)
    JSON.parse(resp)
  end

  # Generic POST call to the API with the given URI and body
  # Parses the response into a JSON object
  def post(uri, body, params)
    resp = @res[uri].post(body, :params => params)
    JSON.parse(resp)
  end

  # Get the domain status and categorization of a domain or list of domains.
  # 'domains' can be either a single domain, or a list of domains.
  # Setting 'labels' to True will give back categorizations in human-readable
  # form.
  #
  # For more detail, see https://sgraph.opendns.com/docs/api#categorization
  def categorization(domains, labels=false)
    if domains.kind_of?(Array)
      post_categorization(domains, labels)
    elsif domains.kind_of?(String)
      get_categorization(domains, labels)
    else
      raise "domains must be a string or a list of strings"
    end
  end

  # Get the cooccurrences of the given domain.
  #
  # For details, see https://sgraph.opendns.com/docs/api#co-occurrences
  def cooccurrences(domain)
    get("/recommendations/name/#{domain}.json")
  end

  # Get the related domains of the given domain.
  #
  # For details, see https://sgraph.opendns.com/docs/api#relatedDomains
  def related_domains(domain)
    get("/links/name/#{domain}.json")
  end

  # Get the Security Information for the given domain.
  #
  # For details, see https://sgraph.opendns.com/docs/api#securityInfo
  def security(domain)
    get("/security/name/#{domain}.json")
  end

  # Get the domain tagging dates for the given domain.
  #
  # For details, see https://sgraph.opendns.com/docs/api#latest_tags
  def domain_tags(domain)
    get("/domains/#{domain}/latest_tags")
  end

  # Get the RR (Resource Record) History of the given domain or IP.
  # The default query type is for 'A' records, but the following query types
  # are supported:
  #
  # A, NS, MX, TXT, CNAME
  #
  # For details, see https://sgraph.opendns.com/docs/api#dnsrr_domain
  def rr_history(query, query_type="A")
    raise "unsupported query type" unless SUPPORTED_DNS_TYPES.include?(query_type)
    if query =~ /(\d{1,3}\.){3}\d{1,3}/
      get_ip(query, query_type)
    else
      get_domain(query, query_type)
    end
  end

  # Gets the latest known malicious domains associated with the given
  # IP address, if any. Returns the list of malicious domains.
  def latest_domains(ip)
    resp = get("/ips/#{ip}/latest_domains")
    resp.map { |h| h['name'] }
  end

  private

  # Make a GET call to '/dnsdb/ip/a/{ip}.json'.
  # Return the JSON object in the response
  def get_ip(ip, query_type)
    get("/dnsdb/ip/#{query_type}/#{ip}.json")
  end

  # Make a GET call to '/dnsdb/name/a/{domain}.json'.
  # Return the JSON object in the response
  def get_domain(domain, query_type)
    get("/dnsdb/name/#{query_type}/#{domain}.json")
  end

  def get_categorization(domain, labels)
    params = labels ? { "showLabels" => true } : {}
    get("/domains/categorization/#{domain}", params)
  end

  def post_categorization(domains, labels)
    params = labels ? { "showLabels" => true } : {}
    data = JSON.generate(domains)
    post("/domains/categorization/", data, params)
  end
end
