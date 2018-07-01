import sodium/c25519, sodium/secretbox, sodium/hmac, sodium/sha2, collections, reactor, collections/binary_pack

type
  Handshake* = object
    kind*: uint8
    ephemeral*: C25519Public
    token1*: array[32, byte]
    token2*: array[32, byte]

  Tunnel* = ref object of Pipe[Buffer]
    raw: Pipe[Buffer]
    myInput: Output[Buffer]
    myOutput: Input[Buffer]

    peerPublic: Ed25519Public
    myKey: Ed25519Private
    psk: Sha256Hash

    staticRxKey: array[32, byte]
    staticTxKey: array[32, byte]

    ready: Completer[void]

    myEphemeral: C25519Private
    peerEphemeral: C25519Public

    rxKey: SecretboxKey
    txKey: SecretboxKey

    token: array[32, byte]

proc isReady(self: Tunnel): bool =
  return self.ready.getFuture.isCompleted

proc sendHandshake(self: Tunnel, h: Handshake) {.async.} =
  let data = ed25519Sign(data=binaryPack(h), key=self.myKey, purpose="cg-handshake")
  let encrypted = newBuffer(1 + secretboxLength + data.len)
  encrypted[0] = 0
  secretboxMake(key=self.staticTxKey, plaintext=data, target=encrypted.slice(1))
  await self.raw.output.send(encrypted)

proc sendHandshake(self: Tunnel) {.async.} =
  await self.sendHandshake(Handshake(
    kind: 0,
    token1: self.token,
    ephemeral: self.myEphemeral.getPublic
  ))

proc sendDataPacket(self: Tunnel, data: Buffer) {.async.} =
  let encrypted = newBuffer(1 + secretboxLength + data.len)
  encrypted[0] = byte(1)
  secretboxMake(key=self.txKey, plaintext=data, target=encrypted.slice(1))
  await self.raw.output.send(encrypted)

proc receivedDataPacket(self: Tunnel, data: Buffer) {.async.} =
  if not self.isReady:
    return

  let d = secretboxOpen(key=self.rxKey, ciphertext=data)
  if d.isSome:
    await self.myInput.send(d.get)

proc finishExchange(self: Tunnel, peerEphemeral: C25519Public) =
  self.peerEphemeral = peerEphemeral
  let (rxKeyPre, txKeyPre) = dhKeyExchange(self.myEphemeral, peerEphemeral)
  self.rxKey = sha256(rxKeyPre.toBinaryString & self.staticRxKey.toBinaryString & self.psk.toBinaryString)
  self.txKey = sha256(txKeyPre.toBinaryString & self.staticTxKey.toBinaryString & self.psk.toBinaryString)
  self.token = urandom(32).byteArray(32) # change token to prevent replays

  self.ready.complete

proc receivedHandshake(self: Tunnel, data: Buffer) {.async.} =
  let signedPlaintext = secretboxOpen(key=self.staticRxKey, ciphertext=data)
  if signedPlaintext.isNone:
    return

  let plaintext = ed25519Unsign(data=signedPlaintext.get, purpose="cg-handshake", key=self.peerPublic)
  if plaintext.isNone: return

  var handshake: Handshake
  try:
    handshake = binaryUnpack(plaintext.get, Handshake)
  except EOFError:
    return

  if handshake.kind == 1 or handshake.kind == 2:
    if handshake.token2 != self.token: return
    self.finishExchange(handshake.ephemeral)

  if handshake.kind == 0 or handshake.kind == 1:
    let handshakeResponse = Handshake(kind: handshake.kind + 1,
                                      ephemeral: self.myEphemeral.getPublic,
                                      token1: self.token,
                                      token2: handshake.token1)
    await self.sendHandshake(handshakeResponse)

proc outputHandler(self: Tunnel) {.async.} =
  var delay = 200
  while not self.isReady:
    await self.sendHandshake()
    await asyncSleep(delay) or self.ready.getFuture
    delay = min(delay * 2, 3000)

  asyncFor data in self.myOutput:
    await self.sendDataPacket(data)

proc inputHandler(self: Tunnel) {.async.} =
  asyncFor data in self.raw.input:
    if data.len <= 2: continue

    let kind = data[0]
    if kind == 0: # handshake
      await self.receivedHandshake(data.slice(1))
    elif kind == 1: # data
      await self.receivedDataPacket(data.slice(1))

proc createTunnel*(raw: Pipe[Buffer], myKey: Ed25519Private, peerKey: Ed25519Public, psk: string=""): Tunnel =
  ## Creates a secure tunnel on ``raw`` pipe.
  ##
  ## It does not check for replay of individual packets - this should be a job of the upper layer.
  let self = Tunnel()
  self.raw = raw
  self.myKey = myKey
  self.peerPublic = peerKey
  self.ready = newCompleter[void]()
  self.psk = sha256("channelguard|" & psk)
  self.myEphemeral = c25519Generate()
  self.token = urandom(32).byteArray(32)

  (self.input, self.myInput) = newInputOutputPair[Buffer]()
  (self.myOutput, self.output) = newInputOutputPair[Buffer]()

  (self.staticRxKey, self.staticTxKey) = dhKeyExchange(myKey.edToC25519, peerKey.edToC25519)
  self.outputHandler().ignore
  self.inputHandler().ignore

  return self
