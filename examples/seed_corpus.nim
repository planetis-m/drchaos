import drchaos

type
  CorpusMessage = object
    route: string
    payload: seq[byte]
    priority: Option[uint8]

let seed = CorpusMessage(
  route: "/health",
  payload: @[1'u8, 2'u8, 3'u8],
  priority: some(1'u8)
)

let bytes = encodeInput(seed)
var decoded: CorpusMessage
discard tryDecodeInput(bytes, decoded)
