# ChannelGuard

ChannelGuard is a simple encrypted tunnel for unreliable packet based traffic, with forward secrecy. We assume that both sides already know each other public key.

The protocol is loosely based on Noise_IK handshake (the same as one used by WireGuard) implemented with libsodium.

ChannelGuard implementation has <200 lines of code making it easy to audit (in contrast to DTLS).
