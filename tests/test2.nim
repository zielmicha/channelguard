import channelguard, sodium/c25519, reactor, reactor/testpipe

proc main() {.async.} =
  let (pipe1, pipe2, rawA, rawB) = newTwoWayTestPipe(mtu=1300, logPackets=false)
  let keyA = ed25519Generate()
  let keyB = ed25519Generate()
  let keyC = ed25519Generate()
  let a = createTunnel(rawA, keyA, pubkeyHash(keyB.getPublic))
  let b = createTunnel(rawB, keyC, pubkeyHash(keyA.getPublic))

  await a.output.send(newView("foo"))
  b.input.receive().then(proc(b: Buffer) =
                           echo "fail"
                           quit(1)).ignore

  await (asyncSleep 500)
  echo "ok"

when isMainModule:
  main().runMain
