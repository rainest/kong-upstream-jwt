-- © Optum 2018
local singletons = require "kong.singletons"
local pl_file = require "pl.file"
local utils = require "kong.tools.utils"
local jwt = require "resty.jwt"
local _M = {}

-- Arbitrary constant subtracted from JWTs' cache TTLs (in seconds). Because
-- JWT generation and caching is not atomic, JWTs' exp claim will be a
-- timestamp slightly before the time JWTs will expire from cache, so it's
-- necessary cache JWTs for a shorter time than their expiry configuration
-- would suggest.
local JWT_TTL_GRACE_PERIOD = 30

local function readFromFile(file_location)
  local content, err = pl_file.read(file_location)
  if not content then
    ngx.log(ngx.ERR, "Could not read file contents", err)
    return nil, err
  end

  return content
end

local function encode_token(data, key)
  local header = {typ = "JWT", alg = "RS256"}
  local matter = {}
  matter["header"] = header
  matter["payload"] = data
  local token = jwt:sign(key, matter)
  return token
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

local function generateToken(keypath, conf)
  local kong_pkey, err = getKongKey(keypath, keypath)
  if not kong_pkey then
    return nil, err
  end

  local payload = {
      exp = ngx.time() + conf.expiry,
      iss = conf.issuer,
      aud = conf.audience,
      sub = conf.subject,
      nbf = ngx.time() + conf.not_before,
      jti = utils.uuid()
  }

  return encode_token(payload, kong_pkey)
end

local function getToken(keypath, conf)
  local identifier = conf.expiry .. conf.not_before .. conf.issuer ..
      conf.audience .. conf.subject .. conf.private_key_location
  local token, err = singletons.cache:get(identifier,
      { ttl = conf.expiry - JWT_TTL_GRACE_PERIOD}, generateToken, keypath, conf)

  if err then
    ngx.log(ngx.ERR, "Failed to retrieve or generate token: ", err)
    return nil, err
  end

  return token
end

local function add_jwt_header(conf)
  local token = getToken(conf.private_key_location, conf)

  if conf.upstream_jwt_header == "Authorization" then
    token = "Bearer " .. token
  end

  ngx.req.set_header(conf.upstream_jwt_header, token)
end

function _M.execute(conf)
  add_jwt_header(conf)
end

return _M
