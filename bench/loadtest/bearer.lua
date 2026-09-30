-- wrk script: each request presents a random token from the population file
-- (first script argument), so caches see a realistic mix rather than one token.
local tokens = {}

setup = function(thread)
  thread:set("seed", math.random(1, 1e9))
end

init = function(args)
  math.randomseed(seed or os.time())
  for line in io.lines(args[1]) do
    if #line > 0 then tokens[#tokens + 1] = line end
  end
end

request = function()
  local token = tokens[math.random(#tokens)]
  return wrk.format("GET", "/me", { ["Authorization"] = "Bearer " .. token })
end
