local key = ""
local wirelessChannel = 44385

local wirelessModem = assert(peripheral.wrap("top"))

wirelessModem.open(wirelessChannel)

local random = require("ccryptolib.random")
local aead = require("ccryptolib.aead")

local seed = ""
-- this isnt exactly secure, but its fine, probably..
for i=1,64 do
  seed = seed .. string.char(math.random(0, 255))
end

random.init(seed)

local function encrypt(message)
  local nonce = random.random(12)
  local ciphertext, tag = aead.encrypt(key, nonce, message, "")

  return nonce..tag..ciphertext
end

local function decrypt(message)
  local ciphertextLength = #message-12-16

  if ciphertextLength < 0 then
    printError("message too short, this may be caused by other traffic on the same port")
    return
  end

  if ciphertextLength >= 32768 then
    printError("message too large, this may be caused by other traffic on the same port")
    return
  end

  local nonce, tag, endPos = string.unpack("c12c16", message)
  local ciphertext = message:sub(endPos)

  local decryptedMessage = aead.decrypt(key, nonce, tag, ciphertext, "") -- this is nil if auth failed

  if not decryptedMessage then
    printError("message auth invalid")
    return
  end

  return decryptedMessage
end

local function sendWireless(tbl)
  local str = textutils.serialize(tbl)

  if not str then
    printError("failed to serialize message")
    return
  end

  local enc = encrypt(str)

  if not enc then
    printError("failed to encrypt serialized message")
    return
  end

  wirelessModem.transmit(wirelessChannel, wirelessChannel, enc)
end

local function recvWireless()
  while true do
    local event, side, channel, replyChannel, message, distance = os.pullEvent("modem_message")
    if side == peripheral.getName(wirelessModem) and channel == wirelessChannel then
      local dec = decrypt(message)
      if dec then
        local unser = textutils.unserialize(dec)
        if unser then
          return unser
        else
          printError("failed to unserialize")
        end
      end
    end
  end
end

return {
  broadcast = function(data, protocol)
    local message_wrapper = {
      nMessageID = math.random(1, 2147483647), -- we dont store messageid here because we shouldnt get our messages back
      nRecipient = rednet.CHANNEL_BROADCAST,
      nSender = os.getComputerID(),
      message = data,
      sProtocol = protocol,
    }

    sendWireless(message_wrapper)
  end,
  receive = function(protocol, timeout) -- computer ids not implemented
    local ret = {}
    parallel.waitForAny(function()
      while true do
        local msg = recvWireless()

        if type(msg) == "table" then
          ret = {msg.nMessageID, msg.message, msg.sProtocol}
          return
        end
      end
    end, function() -- this sucks as well
      while not timeout do sleep(1) end
      sleep(timeout)
      ret = {}
    end)

    return table.unpack(ret)
  end
}