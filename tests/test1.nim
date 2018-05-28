import channelguard, sodium/c25519, reactor, reactor/testpipe

proc main() {.async.} =
  let (pipe1, pipe2, rawA, rawB) = newTwoWayTestPipe(mtu=1300, logPackets=false)
  let keyA = c25519Generate()
  let keyB = c25519Generate()
  pipe1.packetLoss = 1.0 # lose first handshake (to test resend)
  let a = createTunnel(rawA, keyA, keyB.getPublic)
  let b = createTunnel(rawB, keyB, keyA.getPublic)

  await a.output.send(newView("foo"))

  await asyncSleep(100)
  pipe1.packetLoss = 0.0

  var p = await b.input.receive()
  doAssert p.copyAsString == "foo"

  await a.output.send(newView("bar"))

  p = await b.input.receive()
  doAssert p.copyAsString == "bar"

  await b.output.send(newView("bar1"))

  p = await a.input.receive()
  doAssert p.copyAsString == "bar1"

  echo "ok"

when isMainModule:
  main().runMain
