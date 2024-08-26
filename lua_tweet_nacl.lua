-- This file is based on tweetnacl/nacl-fast with the following changes:
-- - Allows custom hash functions
-- - Pruned to include minimal dependencies
-- Function to create a subarray
local function subarray(array, start_idx)
	local result = {}
	for i = start_idx + 1, #array do
		table.insert(result, array[i])
	end
	return result
end

local gf = function(init)
	local r = {}
	for i = 1, 16 do
		r[i] = 0
	end
	if init then
		for i = 1, #init do
			r[i] = init[i]
		end
	end
	return r
end

local _9 = {9}
for i = 2, 32 do
	_9[i] = 0
end

local gf0 = gf()
local gf1 = gf({1})
local D = gf({
	0x78a3, 0x1359, 0x4dca, 0x75eb, 0xd8ab, 0x4141, 0x0a4d, 0x0070, 0xe898, 0x7779, 0x4079, 0x8cc7, 0xfe73, 0x2b6f, 0x6cee,
 0x5203
})
local D2 = gf({
	0xf159, 0x26b2, 0x9b94, 0xebd6, 0xb156, 0x8283, 0x149a, 0x00e0, 0xd130, 0xeef3, 0x80f2, 0x198e, 0xfce7, 0x56df, 0xd9dc,
 0x2406
})
local X = gf({
	0xd51a, 0x8f25, 0x2d60, 0xc956, 0xa7b2, 0x9525, 0xc760, 0x692c, 0xdc5c, 0xfdd6, 0xe231, 0xc0a4, 0x53fe, 0xcd6e, 0x36d3,
 0x2169
})
local Y = gf({
	0x6658, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666, 0x6666,
 0x6666
})
local I = gf({
	0xa0b0, 0x4a0e, 0x1b27, 0xc4ee, 0xe478, 0xad2f, 0x1806, 0x2f43, 0xd7a7, 0x3dfb, 0x0099, 0x2b4d, 0xdf0b, 0x4fc1, 0x2480,
 0x2b83
})

-- 数値の配列を文字列に戻す関数
local function bytes_to_string(bytes)
	local chars = {}
	for i = 1, #bytes do
		table.insert(chars, string.char(bytes[i]))
	end
	return table.concat(chars)
end

-- ビット右シフト関数
local function bit_rshift(value, shift)
	return math.floor(value / 2 ^ shift)
end

-- ビット左シフト関数
local function bit_lshift(value, shift)
	return value * 2 ^ shift
end

-- ビットOR関数
local function bit_bor(a, b)
	local result = 0
	local bitval = 1
	while a > 0 or b > 0 do
		if (a % 2 == 1) or (b % 2 == 1) then
			result = result + bitval
		end
		bitval = bitval * 2
		a = math.floor(a / 2)
		b = math.floor(b / 2)
	end
	return result
end

-- ビットXOR関数
local function bit_bxor(a, b)
	local result = 0
	local bitval = 1
	while a > 0 or b > 0 do
		if ((a % 2 == 1) and (b % 2 == 0)) or ((a % 2 == 0) and (b % 2 == 1)) then
			result = result + bitval
		end
		bitval = bitval * 2
		a = math.floor(a / 2)
		b = math.floor(b / 2)
	end
	return result
end

-- ビットAND関数
local function bit_band(a, b)
	local result = 0
	local bitval = 1
	for i = 0, 31 do
		if (a % 2 == 1) and (b % 2 == 1) then
			result = result + bitval
		end
		a = math.floor(a / 2)
		b = math.floor(b / 2)
		bitval = bitval * 2
	end
	return result
end

-- ビット反転関数（32ビット）
local function bitwise_not(x)
	-- 32ビットの場合、全てのビットを反転させます
	local result = 0xFFFFFFFF
	return bit_bxor(result, x)
end

local function vn(x, xi, y, yi, n)
	local d = 0
	for i = 0, n - 1 do
		d = bit_bor(d, bit_bxor(x[xi + i], y[yi + i]))
	end
	return (bit_band(1, bit_rshift((d - 1), 8))) - 1
end

local function crypto_verify_32(x, xi, y, yi)
	return vn(x, xi, y, yi, 32)
end

local function set25519(r, a)
	for i = 1, 16 do
		r[i] = a[i] or 0
	end
end

local function car25519(o)
	local c = 1
	for i = 1, 16 do
		local v = o[i] + c + 65535
		c = math.floor(v / 65536)
		o[i] = v - c * 65536
	end
	o[1] = o[1] + c - 1 + 37 * (c - 1)
end

local function sel25519(p, q, b)
	local t
	local c = bitwise_not(b - 1)
	for i = 1, 16 do
		t = bit_band(c, bit_bxor(p[i], q[i]))
		p[i] = bit_bxor(p[i], t)
		q[i] = bit_bxor(q[i], t)
	end
end

-- 255ビットの値をパックする関数
local function pack25519(o, n)
	local b
	local m = gf()
	local t = gf()

	for i = 1, 16 do
		t[i] = n[i]
	end

	car25519(t)
	car25519(t)
	car25519(t)

	for j = 1, 2 do
		m[1] = t[1] - 0xffed
		for i = 2, 15 do
			m[i] = t[i] - 0xffff - bit_band(bit_rshift(m[i - 1], 16), 1)
			m[i - 1] = bit_band(m[i - 1], 0xffff)
		end
		m[16] = t[16] - 0x7fff - bit_band(bit_rshift(m[15], 16), 1)
		b = bit_band(bit_rshift(m[16], 16), 1)
		m[15] = bit_band(m[15], 0xffff)
		sel25519(t, m, 1 - b)
	end

	for i = 1, 16 do
		o[2 * i - 1] = bit_band(t[i], 0xff)
		o[2 * i] = bit_rshift(t[i], 8)
	end
end

local function neq25519(a, b)
	local c = {}
	local d = {}
	pack25519(c, a)
	pack25519(d, b)
	return crypto_verify_32(c, 1, d, 1)
end

local function par25519(a)
	local d = {}
	pack25519(d, a)
	return bit_band(d[1], 1)
end

local function unpack25519(o, n)
	for i = 1, 16 do
		o[i] = n[2 * i - 1] + bit_lshift(n[2 * i], 8)
	end
	o[16] = bit_band(o[16], 0x7fff)
end

local function A(o, a, b)
	for i = 1, 16 do
		o[i] = a[i] + b[i]
	end
end

local function Z(o, a, b)
	for i = 1, 16 do
		o[i] = a[i] - b[i]
	end
end

local function M(o, a, b)
	local v, c
	local t0, t1, t2, t3, t4, t5, t6, t7, t8, t9, t10, t11, t12, t13, t14, t15, t16, t17, t18, t19, t20, t21, t22, t23,
					t24, t25, t26, t27, t28, t29, t30 = 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
					0, 0, 0, 0, 0
	local b0, b1, b2, b3, b4, b5, b6, b7, b8, b9, b10, b11, b12, b13, b14, b15 = b[1], b[2], b[3], b[4], b[5], b[6], b[7],
					b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15], b[16]

	v = a[1]
	t0 = t0 + v * b0
	t1 = t1 + v * b1
	t2 = t2 + v * b2
	t3 = t3 + v * b3
	t4 = t4 + v * b4
	t5 = t5 + v * b5
	t6 = t6 + v * b6
	t7 = t7 + v * b7
	t8 = t8 + v * b8
	t9 = t9 + v * b9
	t10 = t10 + v * b10
	t11 = t11 + v * b11
	t12 = t12 + v * b12
	t13 = t13 + v * b13
	t14 = t14 + v * b14
	t15 = t15 + v * b15

	v = a[2]
	t1 = t1 + v * b0
	t2 = t2 + v * b1
	t3 = t3 + v * b2
	t4 = t4 + v * b3
	t5 = t5 + v * b4
	t6 = t6 + v * b5
	t7 = t7 + v * b6
	t8 = t8 + v * b7
	t9 = t9 + v * b8
	t10 = t10 + v * b9
	t11 = t11 + v * b10
	t12 = t12 + v * b11
	t13 = t13 + v * b12
	t14 = t14 + v * b13
	t15 = t15 + v * b14
	t16 = t16 + v * b15

	v = a[3]
	t2 = t2 + v * b0
	t3 = t3 + v * b1
	t4 = t4 + v * b2
	t5 = t5 + v * b3
	t6 = t6 + v * b4
	t7 = t7 + v * b5
	t8 = t8 + v * b6
	t9 = t9 + v * b7
	t10 = t10 + v * b8
	t11 = t11 + v * b9
	t12 = t12 + v * b10
	t13 = t13 + v * b11
	t14 = t14 + v * b12
	t15 = t15 + v * b13
	t16 = t16 + v * b14
	t17 = t17 + v * b15

	v = a[4]
	t3 = t3 + v * b0
	t4 = t4 + v * b1
	t5 = t5 + v * b2
	t6 = t6 + v * b3
	t7 = t7 + v * b4
	t8 = t8 + v * b5
	t9 = t9 + v * b6
	t10 = t10 + v * b7
	t11 = t11 + v * b8
	t12 = t12 + v * b9
	t13 = t13 + v * b10
	t14 = t14 + v * b11
	t15 = t15 + v * b12
	t16 = t16 + v * b13
	t17 = t17 + v * b14
	t18 = t18 + v * b15

	v = a[5]
	t4 = t4 + v * b0
	t5 = t5 + v * b1
	t6 = t6 + v * b2
	t7 = t7 + v * b3
	t8 = t8 + v * b4
	t9 = t9 + v * b5
	t10 = t10 + v * b6
	t11 = t11 + v * b7
	t12 = t12 + v * b8
	t13 = t13 + v * b9
	t14 = t14 + v * b10
	t15 = t15 + v * b11
	t16 = t16 + v * b12
	t17 = t17 + v * b13
	t18 = t18 + v * b14
	t19 = t19 + v * b15

	v = a[6]
	t5 = t5 + v * b0
	t6 = t6 + v * b1
	t7 = t7 + v * b2
	t8 = t8 + v * b3
	t9 = t9 + v * b4
	t10 = t10 + v * b5
	t11 = t11 + v * b6
	t12 = t12 + v * b7
	t13 = t13 + v * b8
	t14 = t14 + v * b9
	t15 = t15 + v * b10
	t16 = t16 + v * b11
	t17 = t17 + v * b12
	t18 = t18 + v * b13
	t19 = t19 + v * b14
	t20 = t20 + v * b15

	v = a[7]
	t6 = t6 + v * b0
	t7 = t7 + v * b1
	t8 = t8 + v * b2
	t9 = t9 + v * b3
	t10 = t10 + v * b4
	t11 = t11 + v * b5
	t12 = t12 + v * b6
	t13 = t13 + v * b7
	t14 = t14 + v * b8
	t15 = t15 + v * b9
	t16 = t16 + v * b10
	t17 = t17 + v * b11
	t18 = t18 + v * b12
	t19 = t19 + v * b13
	t20 = t20 + v * b14
	t21 = t21 + v * b15

	v = a[8]
	t7 = t7 + v * b0
	t8 = t8 + v * b1
	t9 = t9 + v * b2
	t10 = t10 + v * b3
	t11 = t11 + v * b4
	t12 = t12 + v * b5
	t13 = t13 + v * b6
	t14 = t14 + v * b7
	t15 = t15 + v * b8
	t16 = t16 + v * b9
	t17 = t17 + v * b10
	t18 = t18 + v * b11
	t19 = t19 + v * b12
	t20 = t20 + v * b13
	t21 = t21 + v * b14
	t22 = t22 + v * b15

	v = a[9]
	t8 = t8 + v * b0
	t9 = t9 + v * b1
	t10 = t10 + v * b2
	t11 = t11 + v * b3
	t12 = t12 + v * b4
	t13 = t13 + v * b5
	t14 = t14 + v * b6
	t15 = t15 + v * b7
	t16 = t16 + v * b8
	t17 = t17 + v * b9
	t18 = t18 + v * b10
	t19 = t19 + v * b11
	t20 = t20 + v * b12
	t21 = t21 + v * b13
	t22 = t22 + v * b14
	t23 = t23 + v * b15

	v = a[10]
	t9 = t9 + v * b0
	t10 = t10 + v * b1
	t11 = t11 + v * b2
	t12 = t12 + v * b3
	t13 = t13 + v * b4
	t14 = t14 + v * b5
	t15 = t15 + v * b6
	t16 = t16 + v * b7
	t17 = t17 + v * b8
	t18 = t18 + v * b9
	t19 = t19 + v * b10
	t20 = t20 + v * b11
	t21 = t21 + v * b12
	t22 = t22 + v * b13
	t23 = t23 + v * b14
	t24 = t24 + v * b15

	v = a[11]
	t10 = t10 + v * b0
	t11 = t11 + v * b1
	t12 = t12 + v * b2
	t13 = t13 + v * b3
	t14 = t14 + v * b4
	t15 = t15 + v * b5
	t16 = t16 + v * b6
	t17 = t17 + v * b7
	t18 = t18 + v * b8
	t19 = t19 + v * b9
	t20 = t20 + v * b10
	t21 = t21 + v * b11
	t22 = t22 + v * b12
	t23 = t23 + v * b13
	t24 = t24 + v * b14
	t25 = t25 + v * b15

	v = a[12]
	t11 = t11 + v * b0
	t12 = t12 + v * b1
	t13 = t13 + v * b2
	t14 = t14 + v * b3
	t15 = t15 + v * b4
	t16 = t16 + v * b5
	t17 = t17 + v * b6
	t18 = t18 + v * b7
	t19 = t19 + v * b8
	t20 = t20 + v * b9
	t21 = t21 + v * b10
	t22 = t22 + v * b11
	t23 = t23 + v * b12
	t24 = t24 + v * b13
	t25 = t25 + v * b14
	t26 = t26 + v * b15

	v = a[13]
	t12 = t12 + v * b0
	t13 = t13 + v * b1
	t14 = t14 + v * b2
	t15 = t15 + v * b3
	t16 = t16 + v * b4
	t17 = t17 + v * b5
	t18 = t18 + v * b6
	t19 = t19 + v * b7
	t20 = t20 + v * b8
	t21 = t21 + v * b9
	t22 = t22 + v * b10
	t23 = t23 + v * b11
	t24 = t24 + v * b12
	t25 = t25 + v * b13
	t26 = t26 + v * b14
	t27 = t27 + v * b15

	v = a[14]
	t13 = t13 + v * b0
	t14 = t14 + v * b1
	t15 = t15 + v * b2
	t16 = t16 + v * b3
	t17 = t17 + v * b4
	t18 = t18 + v * b5
	t19 = t19 + v * b6
	t20 = t20 + v * b7
	t21 = t21 + v * b8
	t22 = t22 + v * b9
	t23 = t23 + v * b10
	t24 = t24 + v * b11
	t25 = t25 + v * b12
	t26 = t26 + v * b13
	t27 = t27 + v * b14
	t28 = t28 + v * b15

	v = a[15]
	t14 = t14 + v * b0
	t15 = t15 + v * b1
	t16 = t16 + v * b2
	t17 = t17 + v * b3
	t18 = t18 + v * b4
	t19 = t19 + v * b5
	t20 = t20 + v * b6
	t21 = t21 + v * b7
	t22 = t22 + v * b8
	t23 = t23 + v * b9
	t24 = t24 + v * b10
	t25 = t25 + v * b11
	t26 = t26 + v * b12
	t27 = t27 + v * b13
	t28 = t28 + v * b14
	t29 = t29 + v * b15

	v = a[16]
	t15 = t15 + v * b0
	t16 = t16 + v * b1
	t17 = t17 + v * b2
	t18 = t18 + v * b3
	t19 = t19 + v * b4
	t20 = t20 + v * b5
	t21 = t21 + v * b6
	t22 = t22 + v * b7
	t23 = t23 + v * b8
	t24 = t24 + v * b9
	t25 = t25 + v * b10
	t26 = t26 + v * b11
	t27 = t27 + v * b12
	t28 = t28 + v * b13
	t29 = t29 + v * b14
	t30 = t30 + v * b15

	t0 = t0 + 38 * t16
	t1 = t1 + 38 * t17
	t2 = t2 + 38 * t18
	t3 = t3 + 38 * t19
	t4 = t4 + 38 * t20
	t5 = t5 + 38 * t21
	t6 = t6 + 38 * t22
	t7 = t7 + 38 * t23
	t8 = t8 + 38 * t24
	t9 = t9 + 38 * t25
	t10 = t10 + 38 * t26
	t11 = t11 + 38 * t27
	t12 = t12 + 38 * t28
	t13 = t13 + 38 * t29
	t14 = t14 + 38 * t30

	-- fitst car
	c = 1
	v = t0 + c + 65535
	c = math.floor(v / 65536)
	t0 = v - c * 65536
	v = t1 + c + 65535
	c = math.floor(v / 65536)
	t1 = v - c * 65536
	v = t2 + c + 65535
	c = math.floor(v / 65536)
	t2 = v - c * 65536
	v = t3 + c + 65535
	c = math.floor(v / 65536)
	t3 = v - c * 65536
	v = t4 + c + 65535
	c = math.floor(v / 65536)
	t4 = v - c * 65536
	v = t5 + c + 65535
	c = math.floor(v / 65536)
	t5 = v - c * 65536
	v = t6 + c + 65535
	c = math.floor(v / 65536)
	t6 = v - c * 65536
	v = t7 + c + 65535
	c = math.floor(v / 65536)
	t7 = v - c * 65536
	v = t8 + c + 65535
	c = math.floor(v / 65536)
	t8 = v - c * 65536
	v = t9 + c + 65535
	c = math.floor(v / 65536)
	t9 = v - c * 65536
	v = t10 + c + 65535
	c = math.floor(v / 65536)
	t10 = v - c * 65536
	v = t11 + c + 65535
	c = math.floor(v / 65536)
	t11 = v - c * 65536
	v = t12 + c + 65535
	c = math.floor(v / 65536)
	t12 = v - c * 65536
	v = t13 + c + 65535
	c = math.floor(v / 65536)
	t13 = v - c * 65536
	v = t14 + c + 65535
	c = math.floor(v / 65536)
	t14 = v - c * 65536
	v = t15 + c + 65535
	c = math.floor(v / 65536)
	t15 = v - c * 65536
	t0 = t0 + c - 1 + 37 * (c - 1)

	-- second car
	c = 1
	v = t0 + c + 65535
	c = math.floor(v / 65536)
	t0 = v - c * 65536
	v = t1 + c + 65535
	c = math.floor(v / 65536)
	t1 = v - c * 65536
	v = t2 + c + 65535
	c = math.floor(v / 65536)
	t2 = v - c * 65536
	v = t3 + c + 65535
	c = math.floor(v / 65536)
	t3 = v - c * 65536
	v = t4 + c + 65535
	c = math.floor(v / 65536)
	t4 = v - c * 65536
	v = t5 + c + 65535
	c = math.floor(v / 65536)
	t5 = v - c * 65536
	v = t6 + c + 65535
	c = math.floor(v / 65536)
	t6 = v - c * 65536
	v = t7 + c + 65535
	c = math.floor(v / 65536)
	t7 = v - c * 65536
	v = t8 + c + 65535
	c = math.floor(v / 65536)
	t8 = v - c * 65536
	v = t9 + c + 65535
	c = math.floor(v / 65536)
	t9 = v - c * 65536
	v = t10 + c + 65535
	c = math.floor(v / 65536)
	t10 = v - c * 65536
	v = t11 + c + 65535
	c = math.floor(v / 65536)
	t11 = v - c * 65536
	v = t12 + c + 65535
	c = math.floor(v / 65536)
	t12 = v - c * 65536
	v = t13 + c + 65535
	c = math.floor(v / 65536)
	t13 = v - c * 65536
	v = t14 + c + 65535
	c = math.floor(v / 65536)
	t14 = v - c * 65536
	v = t15 + c + 65535
	c = math.floor(v / 65536)
	t15 = v - c * 65536
	t0 = t0 + c - 1 + 37 * (c - 1)

	o[1] = t0;
	o[2] = t1;
	o[3] = t2;
	o[4] = t3
	o[5] = t4;
	o[6] = t5;
	o[7] = t6;
	o[8] = t7
	o[9] = t8;
	o[10] = t9;
	o[11] = t10;
	o[12] = t11
	o[13] = t12;
	o[14] = t13;
	o[15] = t14;
	o[16] = t15
end

local function S(o, a)
	M(o, a, a)
end

local function inv25519(o, i)
	local c = gf()
	for a = 1, 16 do
		c[a] = i[a]
	end
	for a = 253, 0, -1 do
		S(c, c)
		if a ~= 2 and a ~= 4 then
			M(c, c, i)
		end
	end
	for a = 1, 16 do
		o[a] = c[a]
	end
end

local function pow2523(o, i)
	local c = gf()
	for a = 1, 16 do
		c[a] = i[a]
	end
	for a = 250, 0, -1 do
		S(c, c)
		if a ~= 1 then
			M(c, c, i)
		end
	end
	for a = 1, 16 do
		o[a] = c[a]
	end
end

local function crypto_hash(out, m, n, hasher)
	local hash = hasher(string.sub(bytes_to_string(m), 1, n))

	for i = 1, #hash do
		out[i] = string.byte(hash, i)
	end

	return 0
end

local function add(p, q)
	local a, b, c, d, e, f, g, h, t = gf(), gf(), gf(), gf(), gf(), gf(), gf(), gf(), gf()

	Z(a, p[2], p[1])
	Z(t, q[2], q[1])
	M(a, a, t)
	A(b, p[1], p[2])
	A(t, q[1], q[2])
	M(b, b, t)
	M(c, p[4], q[4])
	M(c, c, D2)
	M(d, p[3], q[3])
	A(d, d, d)
	Z(e, b, a)
	Z(f, d, c)
	A(g, d, c)
	A(h, b, a)

	M(p[1], e, f)
	M(p[2], h, g)
	M(p[3], g, f)
	M(p[4], e, h)
end

local function cswap(p, q, b)
	for i = 1, 4 do
		sel25519(p[i], q[i], b)
	end
end

local function pack(r, p)
	local tx, ty, zi = gf(), gf(), gf()
	inv25519(zi, p[3])
	M(tx, p[1], zi)
	M(ty, p[2], zi)
	pack25519(r, ty)
	r[32] = bit_bor(r[32], bit_lshift(par25519(tx), 7))
end

local function scalarmult(p, q, s)
	local b
	set25519(p[1], gf0)
	set25519(p[2], gf1)
	set25519(p[3], gf1)
	set25519(p[4], gf0)
	for i = 255, 0, -1 do
		b = bit_band(bit_rshift(s[math.floor(i / 8) + 1], bit_band(i, 7)), 1)
		cswap(p, q, b)
		add(q, p)
		add(p, p)
		cswap(p, q, b)
	end
end

local function scalarbase(p, s)
	local q = {gf(), gf(), gf(), gf()}
	set25519(q[1], X)
	set25519(q[2], Y)
	set25519(q[3], gf1)
	M(q[4], X, Y)
	scalarmult(p, q, s)
end

local function crypto_sign_keypair(pk, sk, hasher)
	local d = {}
	for i = 1, 64 do
		d[i] = 0
	end
	local p = {gf(), gf(), gf(), gf()}

	crypto_hash(d, sk, 32, hasher)

	d[1] = bit_band(d[1], 248)
	d[32] = bit_band(d[32], 127)
	d[32] = bit_bor(d[32], 64)
	scalarbase(p, d)

	pack(pk, p)
	for i = 1, 32 do
		sk[i + 32] = pk[i]
	end
	return 0
end

local L = {
	237, 211, 245, 92, 26, 99, 18, 88, 214, 156, 247, 162, 222, 249, 222, 20, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
 16
}

local function modL(r, x)
	local carry

	for i = 64, 33, -1 do
		carry = 0
		for j = i - 32, i - 13 do
			x[j] = x[j] + carry - 16 * x[i] * L[j - (i - 32) + 1]
			carry = math.floor((x[j] + 128) / 256)
			x[j] = x[j] - carry * 256
		end

		x[i - 12] = x[i - 12] + carry
		x[i] = 0
	end

	carry = 0
	for j = 1, 32 do
		x[j] = x[j] + carry - bit_rshift(x[32], 4) * L[j]
		carry = bit_rshift(x[j], 8)
		x[j] = bit_band(x[j], 255)
	end

	for j = 1, 32 do
		x[j] = x[j] - carry * L[j]
	end

	for i = 1, 32 do
		x[i + 1] = x[i + 1] + bit_rshift(x[i], 8)
		r[i] = bit_band(x[i], 255)
	end
end

local function reduce(r)
	local x = {}
	for i = 1, 64 do
		x[i] = r[i]
	end
	for i = 1, 64 do
		r[i] = 0
	end
	modL(r, x)

end

local function crypto_sign(sm, m, n, sk, hasher)
	local d, h, r = {}, {}, {}
	for i = 1, 64 do
		d[i] = 0
		h[i] = 0
		r[i] = 0
	end
	local p = {gf(), gf(), gf(), gf()}
	crypto_hash(d, sk, 32, hasher)

	d[1] = bit_band(d[1], 248)
	d[32] = bit_band(d[32], 127)
	d[32] = bit_bor(d[32], 64)
	local smlen = n + 64
	for i = 1, n do
		sm[i + 64] = m[i]
	end
	for i = 1, 32 do
		sm[i + 32] = d[i + 32]
	end
	crypto_hash(r, subarray(sm, 32), n + 32, hasher)
	reduce(r)
	scalarbase(p, r)
	pack(sm, p)

	for i = 1, 32 do
		sm[i + 32] = sk[i + 32]
	end

	crypto_hash(h, sm, n + 64, hasher)
	reduce(h)

	local x = {}
	for i = 1, 64 do
		x[i] = 0
	end
	for i = 1, 32 do
		x[i] = r[i]
	end
	for i = 1, 32 do
		for j = 1, 32 do
			x[i + j - 1] = x[i + j - 1] + h[i] * d[j]
		end
	end

	local rr = subarray(sm, 32)
	modL(rr, x)
	for i = 1, #rr do
		sm[i + 32] = rr[i]
	end

	return smlen
end

local function unpackneg(r, p)
	local t, chk, num, den, den2, den4, den6 = gf(), gf(), gf(), gf(), gf(), gf(), gf()

	set25519(r[3], gf1)
	unpack25519(r[2], p)
	S(num, r[2])
	M(den, num, D)
	Z(num, num, r[3])
	A(den, r[3], den)

	S(den2, den)
	S(den4, den2)
	M(den6, den4, den2)
	M(t, den6, num)
	M(t, t, den)

	pow2523(t, t)
	M(t, t, num)
	M(t, t, den)
	M(t, t, den)
	M(r[1], t, den)

	S(chk, r[1])
	M(chk, chk, den)
	if neq25519(chk, num) ~= 0 then
		M(r[1], r[1], I)
	end
	S(chk, r[1])
	M(chk, chk, den)
	if neq25519(chk, num) ~= 0 then
		M(r[1], r[1], I)
	end

	if par25519(r[1]) == bit_band(p[32], 128) then
		Z(r[1], gf0, r[1])
	end

	M(r[4], r[1], r[2])
	return 0
end

local function crypto_sign_open(m, sm, n, pk, hasher)
	local t = {}
	for i = 1, 64 do
		t[i] = 0
	end
	local h = {}
	for i = 1, 64 do
		h[i] = 0
	end
	local p = {gf(), gf(), gf(), gf()}
	local q = {gf(), gf(), gf(), gf()}

	if n < 64 or unpackneg(q, pk) ~= 0 then
		return -1
	end

	for i = 1, n do
		m[i] = sm[i]
	end
	for i = 1, 32 do
		m[i + 32] = pk[i]
	end

	crypto_hash(h, table.concat(sm, "", 1, n), n, hasher)
	reduce(h)

	scalarmult(p, q, h)
	scalarbase(q, sm)
	add(p, q)

	pack(t, p)

	for i = 1, 32 do
		if t[i] ~= sm[i] then
			return -1
		end
	end

	for i = 1, n - 64 do
		m[i] = sm[i + 64]
	end

	return n - 64
end

-- テーブル内のすべての値が255以下のbyteかどうかをチェックする関数
function is_valid_byte_table(var)
	-- まず変数がテーブルかどうかを確認
	if type(var) ~= "table" then
		return false
	end

	-- テーブル内の各値をチェック
	for _, value in pairs(var) do
		if type(value) ~= "number" or value < 0 or value > 255 or value % 1 ~= 0 then
			return false
		end
	end

	return true
end

-- 配列内の全ての文字列をチェックする関数
local function checkByteArray(array)
	for i, bytes in ipairs(array) do
		if not is_valid_byte_table(bytes) then
			error('unexpected type, use ByteArray')
		end
	end
end

local crypto_sign_BYTES = 64
local crypto_sign_PUBLICKEYBYTES = 32
local crypto_sign_SECRETKEYBYTES = 64
local crypto_sign_SEEDBYTES = 32

local nacl = {}

local nacl_sign = function(msg, secretKey, hasher)
	checkByteArray({msg, secretKey})
	if #secretKey ~= crypto_sign_SECRETKEYBYTES then
		error("bad secret key size")
	end
	local signedMsg = {}
	for i = 1, crypto_sign_BYTES + #msg do
		signedMsg[i] = 0
	end
	crypto_sign(signedMsg, msg, #msg, secretKey, hasher)
	return signedMsg
end

local nacl_sign_detached = function(msg, secretKey, hasher)
	local signedMsg = nacl_sign(msg, secretKey, hasher)
	local sig = {}
	for i = 1, crypto_sign_BYTES do
		sig[i] = signedMsg[i]
	end
	return sig
end

local fromSeed = function(seed, hasher)
	checkByteArray({seed})
	if #seed ~= crypto_sign_SEEDBYTES then
		error('bad seed size');
	end
	local pk = {};
	local sk = {};
	for i = 1, 32 do
		sk[i] = seed[i];
	end
	for i = 33, 64 do
		sk[i] = 0;
	end

	crypto_sign_keypair(pk, sk, hasher);
	return {["publicKey"] = pk, ["secretKey"] = sk}
end

local lowlevel = {
	crypto_hash = crypto_hash,
	gf = gf,
	L = L,
	Z = Z,
	modL = modL,
	scalarmult = scalarmult,
	neq25519 = neq25519,
	par25519 = par25519,
	inv25519 = inv25519,
	pack = pack,
	unpackneg = unpackneg
}

local key_pair = {fromSeed = fromSeed}

nacl = {sign = nacl_sign, sign_detached = nacl_sign_detached, key_pair = key_pair, lowlevel = lowlevel, modL = modL}

return nacl
