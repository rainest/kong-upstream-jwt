-- © Optum 2018
local resty_sha256 = require "resty.sha256"
local str = require "resty.string"
local singletons = require "kong.singletons"
-- These will now be retrieved later from a location with access to config
--local public_key_der_location =  os.getenv("KONG_SSL_CERT_DER")
--local private_key_location =  os.getenv("KONG_SSL_CERT_KEY")
local pl_file = require "pl.file"
local json = require "cjson"
local utils = require "kong.tools.utils"
local openssl_digest = require "openssl.digest"
local openssl_pkey = require "openssl.pkey"
local table_concat = table.concat
local encode_base64 = ngx.encode_base64
local jwt = require "resty.jwt"
local _M = {}

local id_lookup = {
  ip = function()
    return ngx.var.remote_addr
  end,
  credential = function()
    return ngx.ctx.authenticated_credential and
           ngx.ctx.authenticated_credential.id
  end,
  consumer = function()
    -- try the consumer, fall back to credential
    return ngx.ctx.authenticated_consumer and
           ngx.ctx.authenticated_consumer.id or
           ngx.ctx.authenticated_credential and
           ngx.ctx.authenticated_credential.id
  end
}

--- base 64 encoding
-- @param input String to base64 encode
-- @return Base64 encoded string
local function b64_encode(input)
  local result = encode_base64(input)
  result = result:gsub("+", "-"):gsub("/", "_"):gsub("=", "")
  return result
end

local function readFromFile(file_location)
  local content, err = pl_file.read(file_location)
  if not content then
    ngx.log(ngx.ERR, "Could not read file contents", err)
    return nil, err
  end

  return content
end

local function getKongKey(key, location)
  -- This will add a non expiring TTL on this cached value
  -- https://github.com/thibaultcha/lua-resty-mlcache/blob/master/README.md
  local pkey, err = singletons.cache:get(key, { ttl = 0 }, readFromFile, location)
	
  if err then
    ngx.log(ngx.ERR, "Could not retrieve pkey: ", err)
    return
  end
	
  return pkey
end

local function encode_token(data, key)
--  -- local header = {typ = "JWT", alg = "RS256", x5c = {b64_encode(getKongKey("pubder",public_key_der_location))} }
  local header = {typ = "JWT", alg = "RS256"}
  --header = {typ = "JWT", alg = "HS256"}
  matter = {}
  matter["header"] = header
  matter["payload"] = data
--  local segments = {
--    b64_encode(json.encode(header)),
--    b64_encode(json.encode(data))
--  }
  local token = jwt:sign(key, matter)
--  local signing_input = table_concat(segments, ".")
--  local signature = openssl_pkey.new(key):sign(openssl_digest.new("sha256"):update(signing_input))
--  segments[#segments+1] = b64_encode(signature)
----  return table_concat(segments, ".")
  return token
end

local function add_jwt_header(conf)
  local key = id_lookup[conf.identifier]()

  -- legacy logic, if authenticated consumer or credential is not found
  -- use the IP
  if not key then
    key = id_lookup["ip"]()
  end

  -- -- this is the original body generation code, which uses a digest of the request itself
  -- -- will need to add a switch case if maintaining original plugin functionality
  local kong_pkey = getKongKey("pkey", conf.private_key_location)
  -- ngx.req.read_body()
  -- local req_body  = ngx.req.get_body_data()
  -- local digest_created = ""
  -- if req_body ~= nil then
  --   local sha256 = resty_sha256:new()
  --   sha256:update(req_body)
  --   digest_created = sha256:final()
  -- end

  -- local payload = {
  --       payloadhash = str.to_hex(digest_created),
  --       exp = ngx.time() + 60 --much better performance improvement over os.time()
  -- }

  local payload = {
      exp = ngx.time() + conf.expiry,
      iss = conf.issuer,
      aud = conf.audience,
      nbf = ngx.time() + conf.not_before,
      jti = "not a uuid"
  }
		
  local jwt = encode_token(payload, kong_pkey)
  ngx.req.set_header("JWT", jwt)
end

function _M.execute(conf)
  add_jwt_header(conf)
end

return _M
