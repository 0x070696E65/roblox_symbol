local sha2 = require(game.ServerScriptService.sha2for51)
local nacl = require(game.ServerScriptService.lua_tweetnacl)
local symbol = require(game.ServerScriptService.symbol_utils)
local HttpService = game:GetService("HttpService")

local function serializeTransaction(tx)
	local jsonData = HttpService:JSONEncode(tx)

	-- 今のところのエンドポイントでtxをシリアライズします
	local url = "https://vmi1560137.contaboserver.net:3030/serialize"
	local success, response = pcall(function()
		return HttpService:PostAsync(url, jsonData, Enum.HttpContentType.ApplicationJson, false)
	end)

	if success then
		return response
	else
		warn("Failed to send POST request: " .. response)
	end
end

local function generatePayload(payload, generationhash_seed, signature)
	local json = {payload = payload, generationHashSeed = generationhash_seed, signature = signature}
	local jsonData = HttpService:JSONEncode(json)

	-- 今のところのエンドポイントでtxをシリアライズします
	local url = "https://vmi1560137.contaboserver.net:3030/generatePayload"
	local success, response = pcall(function()
		return HttpService:PostAsync(url, jsonData, Enum.HttpContentType.ApplicationJson, false)
	end)

	if success then
		return response
	else
		warn("Failed to send POST request: " .. response)
	end
end

local function anounceTransaction(payload)
	local payload = {payload = payload}
	local jsonData = HttpService:JSONEncode(payload)

	-- NODE
	local url = "https://sym-test-01.opening-line.jp:3001/transactions"
	local headers = {["Content-Type"] = "application/json"}
	local success, response = pcall(function()
		return HttpService:RequestAsync({Url = url, Method = "PUT", Headers = headers, Body = jsonData})
	end)

	if success then
		return response
	else
		warn("Failed to send POST request: " .. response)
	end
end

local generationhash_seed = "49D6E1CE276A85B70EAFE52349AACCA389302E7A9754BCF1221E79494FC665A4"
local part = script.Parent
local hasTouched = false
part.Touched:Connect(function(hit)
	if not hasTouched and hit and hit.Parent:FindFirstChild("Humanoid") then
		hasTouched = true

		local pkey = symbol.utils.hex_to_table("PRIVATE_KEY");
		local key_pair = nacl.key_pair.fromSeed(pkey, sha2.sha512bin)
		local deadline = symbol.create_deadline(7200)

		local tx = {
			network = "testnet",
			transaction = {
				type = "transfer_transaction_v1",
				signerPublicKey = symbol.utils.table_to_hex_string(key_pair.publicKey),
				fee = "1000000",
				deadline = deadline,
				recipientAddress = "TCHBDENCLKEBILBPWP3JPB2XNY64OE7PYHHE32I",
				mosaics = {{mosaicId = "8268645399043017678", amount = "1000000"}}
			}
		}

		local serializeTransaction = serializeTransaction(tx)
		local jsonSerializeTransaction = HttpService:JSONDecode(serializeTransaction)
		local formatTransaction = symbol.format_transaction(jsonSerializeTransaction.payload, generationhash_seed)
		local signature = nacl.sign_detached(formatTransaction, key_pair["secretKey"], sha2.sha512bin)
		local payload = generatePayload(jsonSerializeTransaction.payload, generationhash_seed,
						symbol.utils.table_to_hex_string(signature))
		local jsonPayload = HttpService:JSONDecode(payload)
		local result = anounceTransaction(jsonPayload["payload"])
		print(jsonPayload["hash"])
		print(result)
	end
end)

