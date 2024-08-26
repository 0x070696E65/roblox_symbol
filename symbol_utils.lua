-- 10進数を16進数に変換し、文字列として返す関数
local function to_hex(n)
	return string.format("%02x", n)
end

-- テーブル内の各要素を16進数に変換し、それらを連結した文字列を返す関数
local function table_to_hex_string(tbl)
	local hex_string = ""
	for _, v in ipairs(tbl) do
		hex_string = hex_string .. to_hex(v)
	end
	return hex_string
end

-- 16進数文字列からバイト配列へ変換する関数
local function hex_to_table(hex_string)
	local byte_array = {}
	for i = 1, #hex_string, 2 do
		local hex_byte = hex_string:sub(i, i + 1)
		local byte = tonumber(hex_byte, 16)
		table.insert(byte_array, byte)
	end
	return byte_array
end

local function subarray(array, start_idx)
	local result = {}
	for i = start_idx + 1, #array do
		table.insert(result, array[i])
	end
	return result
end

local function table_concat(t1, t2)
	local result = {}
	for i = 1, #t1 do
		result[#result + 1] = t1[i]
	end
	for i = 1, #t2 do
		result[#result + 1] = t2[i]
	end
	return result
end

local TRANSACTION_HEADER_SIZE = (function()
	local sizes = {4, 4, 64, 32, 4}
	local sum = 0
	for _, size in ipairs(sizes) do
		sum = sum + size
	end
	return sum
end)()

local AGGREGATE_HASHED_SIZE = (function()
	local sizes = {4, 8, 8, 32}
	local sum = 0
	for _, size in ipairs(sizes) do
		sum = sum + size
	end
	return sum
end)()

local function is_aggregateTransaction(transactionBuffer)
	local transactionTypeOffset = TRANSACTION_HEADER_SIZE + 2 -- skip version and network byte
	local transactionType = math.floor(transactionBuffer[transactionTypeOffset + 1] / 2 ^ 8) +
					                        transactionBuffer[transactionTypeOffset]
	local aggregateTypes = {16961, 16705}

	for _, aggregateType in ipairs(aggregateTypes) do
		if aggregateType == transactionType then
			return true
		end
	end
	return false
end

local function transaction_data_buffer(transactionBuffer)
	local dataBufferStart = TRANSACTION_HEADER_SIZE + 1
	local dataBufferEnd = 1

	if is_aggregateTransaction(transactionBuffer) then
		dataBufferEnd = TRANSACTION_HEADER_SIZE + AGGREGATE_HASHED_SIZE
	else
		dataBufferEnd = #transactionBuffer
	end

	local dataBuffer = {}
	for i = dataBufferStart, dataBufferEnd do
		table.insert(dataBuffer, transactionBuffer[i])
	end

	return dataBuffer
end

local function format_transaction(transaction, generation_hash)
	local generationHashSeedBytes = hex_to_table(generation_hash)
	local transactionData = transaction_data_buffer(hex_to_table(transaction))

	local combined = {}
	for i = 1, #generationHashSeedBytes do
		table.insert(combined, generationHashSeedBytes[i])
	end
	for i = 1, #transactionData do
		table.insert(combined, transactionData[i])
	end

	return combined
end

local function hexToDec(hex)
	local dec = "0"
	local base = 1

	for i = #hex, 1, -1 do
		local digit = tonumber(hex:sub(i, i), 16)
		if digit then
			dec = tostring(tonumber(dec) + digit * base)
			base = base * 16
		else
			return nil, "Invalid hex digit"
		end
	end

	return dec
end

local function create_deadline(add_seconds)
	local timestamp = os.time()
	local epoctime = 1667250467
	return (timestamp - epoctime + add_seconds) * 1000
end

local utils = {
	table_to_hex_string = table_to_hex_string,
	hex_to_table = hex_to_table,
	subarray = subarray,
	table_concat = table_concat,
	hexToDec = hexToDec
}

local symbol = {utils = utils, format_transaction = format_transaction, create_deadline = create_deadline}
return symbol
