-- wrk script: DPoP requests, each with a never-reused proof. The proof file
-- (first argument) holds the DPoP-bound token on line 1, then one proof per
-- line; thread i of n (second argument) takes every n-th proof, so no proof is
-- sent twice. A thread that runs out repeats its last proof, which the server
-- rejects as a replay: size the pool so that shows up as 0 non-2xx responses.
local nextId = 0

setup = function(thread)
  thread:set("id", nextId)
  nextId = nextId + 1
end

init = function(args)
  local threads = tonumber(args[2])
  proofs, index = {}, 0
  local n = 0
  for line in io.lines(args[1]) do
    n = n + 1
    if n == 1 then
      token = line
    elseif #line > 0 and (n % threads) == id then
      proofs[#proofs + 1] = line
    end
  end
end

request = function()
  index = index + 1
  local proof = proofs[index] or proofs[#proofs]
  return wrk.format("GET", "/me", {
    ["Authorization"] = "DPoP " .. token,
    ["DPoP"] = proof,
  })
end
