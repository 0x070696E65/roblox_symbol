# usage

- lua_tweet_nacl
- sha2for51
- symbol_utils

この 3 つのファイルを ServerScriptService 直下に ModuleScript でファイル名このままでコピペしてください

main.lua は sample です
object を配置し、Script を追加しそのまま貼り付けてください
上の３つのファイルは主に署名ライブラリなので他のトランザクション構築などは API で行います。

## アカウント

```lua
local pkey = symbol.utils.hex_to_table("PRIVATE_KEY");
local key_pair = nacl.key_pair.fromSeed(pkey, sha2.sha512bin)
```

新たなアカウント作成は seed にランダムな 64byte の byte 配列を渡せば良いですが暗号学的に安全なランダム値を roblox では作成できそうにないのであまりおすすめではない。
テストネットであれば以下で可能

```lua
math.randomseed(os.time())
local byteArray = {}
for i = 1, 32 do
	local byte = math.random(0, 255)
	table.insert(byteArray, byte)
end
```

## serializeTransaction()

json で transaction を渡すとペイロードの形で返却します

```lua
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
```

deadline は現在時刻に秒を足します。関数内で epoc をハードコーディングしてるので基本はテストネット用、万が一メインネットで試したい場合は書き換えてください。（非推奨）

基本的には v3 の sdk の形に沿っています、数値型はありません、全て文字列です。BigInt も文字列で渡します。
`例）mosaicId = "8268645399043017678"`
これは 0x72C0212E67A08BCE の数値型です

https://www.simonv.fr/TypesConvert/?integers

ここの hex で貼り付けると 64bit 整数がわかるのでそれを使ってください(Roblox 上だと BigInt 用のライブラリが必要で面倒だった)

## sign

```lua
local jsonSerializeTransaction = HttpService:JSONDecode(serializeTransaction)
local formatTransaction = symbol.format_transaction(jsonSerializeTransaction.payload, generationhash_seed)
local signature = nacl.sign_detached(formatTransaction, key_pair["secretKey"], sha2.sha512bin)
```

シリアライズされた tx を json にして generationhash を含む署名可能な形にし、署名します。

## payload 完成

```lua
local payload = generatePayload(jsonSerializeTransaction.payload, generationhash_seed, symbol.utils.table_to_hex_string(signature))
```

署名前ペイロード、generation hash、署名を api に投げて、署名をアタッチするのと、status 確認用の hash を返します
sha3-256 でハッシュ作成で面倒だったのでこれも API に任せた

## anounceTransaction

```lua
local jsonPayload = HttpService:JSONDecode(payload)
local result = anounceTransaction(jsonPayload["payload"])
print(jsonPayload["hash"])
print(result)
```

あとはアナウンスです

# 注意点

一番重要な署名は API じゃなくて Roblox で行う（オンライン上に秘密鍵が滞在しない）
それ以外は基本的に API に任せます。
シリアライズは僕の管理するサーバーで、ぶっちゃけいくらでも改変できます。（もちろんそんなことはしていない）
それも踏まえて、基本的にはテストネットで遊ぶ用です。

信頼のおけるサーバーでシリアライズするなら良いかなとは思います。
署名ライブラリがほぼ自作なので、そこも信用問題というか、あくまでも遊び用です。
