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
  def get(uri)
    resp = @res[uri].get()
    JSON.parse(resp)
  end

  # Generic POST call to the API with the given URI and body
  # Parses the response into a JSON object
  def post(uri, body)
    resp = @res[uri].post(body)
    JSON.parse(resp)
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

  # Make a GET call to '/links/name/{domain}.json'.
  # Return the JSON object in the response
  def get_related_domains(domain)
    get("/links/name/" + domain + ".json")
  end

  # Make a GET call to '/label/rface-gbt/name/{domain}.json'.
  # Return the JSON object in the response
  def get_score(domain)
    get("/label/rface-gbt/name/" + domain + ".json")
  end

  # Make a GET call to '/recommendations/name/{domain}.json'.
  # Return the JSON obje
  def get_cooccurrences(domain)
    get("/recommendations/name/" + domain + ".json")
  end

  # Make a GET call to '/security/name/{domain}.json'.
  # Return the JSON object
  def get_security(domain)
    get("/security/name/" + domain + ".json")
  end
end
