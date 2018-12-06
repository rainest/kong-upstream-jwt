-- © Optum 2018
local find = string.find

return {
  fields = {
    expiry = { type = "number"},
    not_before = { type = "number"},
    issuer = { type = "string"},
    audience = { type = "string"}
  }
}
