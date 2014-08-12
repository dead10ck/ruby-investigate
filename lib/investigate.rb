require 'json'
require 'openssl'
require 'rest-client'
require 'uri'
require 'siphash'

# Ruby API for the OpenDNS Security Graph
class Investigate
  VERSION = '0.0.1'
  SGRAPH_URL = 'https://investigate.api.opendns.com'
  SIPHASH_KEY = 'Umbrella/OpenDNS'

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

  # Make a GET call to '/dnsdb/ip/a/{ip}.json'.
  # Return the JSON object in the response
  def get_ip(ip)
    get("/dnsdb/ip/a/" + ip + ".json")
  end

  # Make a GET call to '/dnsdb/name/a/{domain}.json'.
  # Return the JSON object in the response
  def get_domain(domain)
    get("/dnsdb/name/a/" + domain + ".json")
  end

  private

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
