from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING

class UnlockPacket(PacketType):
    DEFINITION_IDENTIFIER = "lab1b.tmeng4.UnlockPacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("password", STRING)
    ]

class ChangePasswordPacket(PacketType):
    DEFINITION_IDENTIFIER = "lab1b.tmeng4.ChangePasswordPacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("password", STRING)
    ]

class LockPacket(PacketType):
    DEFINITION_IDENTIFIER = "lab1b.tmeng4.LockPacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = []

class ResponsePacket(PacketType):
    DEFINITION_IDENTIFIER = "lab1b.tmeng4.ResponsePacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("code", UINT32),
        ("message", STRING)
    ]

def basicUnitTest():
    # Modified from lab1b PDF
    unlockPacket1 = UnlockPacket()
    unlockPacket1.password = 000
    unlockPacketBytes = unlockPacket1.__serialize__()
    unlockPacket2 = PacketType.Deserialize(unlockPacketBytes)
    if unlockPacket1 == unlockPacket2:
        print("These two unlock packets are the same!")

    changePasswordPacket1 = ChangePasswordPacket()
    changePasswordPacket1.password = 000
    changePasswordPacket2 = ChangePasswordPacket()
    changePasswordPacket2.password = 000
    if changePasswordPacket1 == changePasswordPacket2:
        print("These two change password packets are the same!")
    changePasswordPacket2.password = 111
    if changePasswordPacket1 != changePasswordPacket2:
        print("After editing, these two change password packets are not the same.")

    # Missed Google foo.bar by searching "python try except" and clicking on the first result immediately -_-
    lockPacket1 = LockPacket()
    lockPacket1.password = 222
    lockPacketBytes = lockPacket1.__serialize__()
    lockPacket2 = PacketType.Deserialize(lockPacketBytes)
    print("Lock packet 1 password is: " + str(lockPacket1.password))
    try:
        print("Lock packet 2 password is: " + str(lockPacket2.password))
    except AttributeError:
        print("Exception on accessing invalid password field of deserialized lock packet 2.")

    responsePacket1 = ResponsePacket()
    responsePacket1.code = 200
    responsePacket1.message = "Success"
    responsePacket2 = ResponsePacket()
    responsePacket2.code = 400
    responsePacket2.message = "Bad Request"
    responsePacket3 = ResponsePacket()
    responsePacket3.code = 403
    responsePacket3.message = "Forbidden"
    pktBytes = responsePacket1.__serialize__() + responsePacket2.__serialize__() + responsePacket3.__serialize__()
    deserializer = PacketType.Deserializer()
    print("Starting with {} bytes of data".format(len(pktBytes)))
    packetCount = 0;
    while len(pktBytes) > 0:
        # let’s take one byte
        chunk, pktBytes = pktBytes[:1], pktBytes[1:]
        deserializer.update(chunk)
        packetCount += 1
        for packet in deserializer.nextPackets():
            print("Got a packet end at byte " + str(packetCount) + "!")
            if packet == responsePacket1:
                print("It’s response packet 1!")
            elif packet == responsePacket2:
                print("It’s response packet 2!")
            elif packet == responsePacket3:
                print("It’s response packet 3!")

if __name__=="__main__":
    basicUnitTest()
