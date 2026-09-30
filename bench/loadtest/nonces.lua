-- wrk script: harvest server-issued DPoP nonces. Each request presents the
-- DPoP-bound token with a nonce-less proof (line 1 and 2 of the first script
-- argument), which the server answers with a use_dpop_nonce challenge carrying
-- a fresh DPoP-Nonce; every nonce is appended to <second argument>.<thread>.
local nextId = 0

setup = function(thread)
  thread:set("id", nextId)
  nextId = nextId + 1
end

init = function(args)
  local lines = {}
  for line in io.lines(args[1]) do lines[#lines + 1] = line end
  token, probe = lines[1], lines[2]
  out = io.open(args[2] .. "." .. id, "w")
  out:setvbuf("line")
end

request = function()
  return wrk.format("GET", "/me", {
    ["Authorization"] = "DPoP " .. token,
    ["DPoP"] = probe,
  })
end

response = function(status, headers, body)
  local nonce = headers["DPoP-Nonce"]
  if nonce then out:write(nonce, "\n") end
end
