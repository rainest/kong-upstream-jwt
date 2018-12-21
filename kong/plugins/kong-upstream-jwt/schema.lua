-- © Optum 2018
local find = string.find

return {
  fields = {
    expiry = { type = "number", required = true, default = 900},
    not_before = { type = "number", required = true, default = 0},
    issuer = { type = "string", required = true},
    audience = { type = "string", required = true},
    subject = { type = "string", required = true},
    upstream_jwt_header = { type = "string", required = true, default = "Authorization"},
    private_key_location = { type = "string", required = true}
  }
}
