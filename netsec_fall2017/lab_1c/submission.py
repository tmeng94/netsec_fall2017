from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, ListFieldType
from playground.network.packet.fieldtypes.attributes import Optional
from playground.asyncio_lib.testing import TestLoopEx
from playground.network.testing import MockTransportToStorageStream, MockTransportToProtocol
import asyncio
import hashlib
import os

# Define lock transfer protocol codes
LtpCode = {
    200: "Success",
    400: "Bad Request",
    401: "Unauthorized",
    403: "Forbidden",
    405: "Method Unavailable",
    500: "Internal Server Error"
}


def serverPrint(txt):
    print("(Server) " + str(txt))


def clientPrint(txt):
    print("(Client) " + str(txt))


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


# For test purpose only; not included in protocol


class TestOptionalListPacket(PacketType):
    DEFINITION_IDENTIFIER = "lab1b.tmeng4.TestOptionalListPacket"
    DEFINITION_VERSION = "1.0"
    FIELDS = [
        ("testlist", ListFieldType(STRING, {Optional: True}))
    ]


class Lock():
    SUCCESS = 1000
    ERROR_UNSPECIFIC = 4000
    ERROR_LOCKED = 4001
    ERROR_ALREADY_UNLOCKED = 4002
    ERROR_WRONG_PASSWORD = 4003
    ERROR_WRONG_PASSWORD_FORMAT = 4004

    # Take a string password and return a salted hash
    @staticmethod
    def hash(password, salt):
        m = hashlib.sha256()
        m.update(password.encode() + salt)
        return m.digest()

    def __init__(self, password, locked):
        self.salt = os.urandom(8)
        self.password_hashed = Lock.hash(password, self.salt)
        self.locked = locked

    def unlock(self, password):
        if not password or not password.isdigit() or len(password) != 3:
            return Lock.ERROR_WRONG_PASSWORD_FORMAT
        elif self.locked == False:
            return Lock.ERROR_ALREADY_UNLOCKED
        elif self.password_hashed != Lock.hash(password, self.salt):
            return Lock.ERROR_WRONG_PASSWORD
        else:
            self.locked = False
            return Lock.SUCCESS

    def changePassword(self, newPassword):
        if not newPassword or not newPassword.isdigit() or len(newPassword) != 3:
            return Lock.ERROR_WRONG_PASSWORD_FORMAT
        elif self.locked == True:
            return Lock.ERROR_LOCKED
        else:
            self.salt = os.urandom(8)
            self.password_hashed = Lock.hash(newPassword, self.salt)
            return Lock.SUCCESS

    def lock(self):
        if self.locked == True:
            return Lock.ERROR_LOCKED
        else:
            self.locked = True
            return Lock.SUCCESS


class LockServerProtocol(asyncio.Protocol):
    def __init__(self, lock):
        self.transport = None
        self.lock = lock
        self.deserializer = PacketType.Deserializer()

    def connection_made(self, transport):
        serverPrint('New Connection')
        self.transport = transport

    def data_received(self, data):
        self.deserializer.update(data)
        for pkt in self.deserializer.nextPackets():
            response = ResponsePacket()
            if isinstance(pkt, UnlockPacket):
                result = self.lock.unlock(pkt.password)
                if result == Lock.SUCCESS:
                    response.code = 200
                    response.message = "Success"
                elif result == Lock.ERROR_WRONG_PASSWORD:
                    response.code = 401
                    response.message = "Wrong Password"
                elif result == Lock.ERROR_ALREADY_UNLOCKED:
                    response.code = 403
                    response.message = "Already Unlocked"
                elif result == Lock.ERROR_WRONG_PASSWORD_FORMAT:
                    response.code = 400
                    response.message = "Wrong Password Format"
                else:
                    response.code = 500
                    response.message = "Unknown Error"
                serverPrint("Unlocking with " + pkt.password +
                            " ... " + response.message)
            elif isinstance(pkt, ChangePasswordPacket):
                result = self.lock.changePassword(pkt.password)
                if result == Lock.SUCCESS:
                    response.code = 200
                    response.message = "Success"
                elif result == Lock.ERROR_LOCKED:
                    response.code = 403
                    response.message = "Locked"
                elif result == Lock.ERROR_WRONG_PASSWORD_FORMAT:
                    response.code = 400
                    response.message = "Wrong Password Format"
                else:
                    response.code = 500
                    response.message = "Unknown Error"
                serverPrint("Changing password to " +
                            pkt.password + " ... " + response.message)
            elif isinstance(pkt, LockPacket):
                result = self.lock.lock()
                if result == Lock.SUCCESS:
                    response.code = 200
                    response.message = "Success"
                elif result == Lock.ERROR_LOCKED:
                    response.code = 403
                    response.message = "Already Locked"
                else:
                    response.code = 500
                    response.message = "Unknown Error"
                serverPrint("Locking ... " + response.message)
            else:
                response.code = 405
                response.message = "Unknown Packet Type"
            self.transport.write(response.__serialize__())

    def connection_lost(self, exc):
        serverPrint('The client closed the connection')
        self.transport = None


class LockClientProtocol(asyncio.Protocol):
    def connection_made(self, transport):
        # newline
        print()
        clientPrint("Sending unlock packet #1 (1234, bad format)")
        unlockPacket1 = UnlockPacket()
        unlockPacket1.password = "1234"
        transport.write(unlockPacket1.__serialize__())

        print()
        clientPrint("Sending unlock packet #2 (001, wrong password)")
        unlockPacket2 = UnlockPacket()
        unlockPacket2.password = "001"
        transport.write(unlockPacket2.__serialize__())

        print()
        clientPrint("Sending unlock packet #3 (000)")
        unlockPacket3 = UnlockPacket()
        unlockPacket3.password = "000"
        transport.write(unlockPacket3.__serialize__())

        print()
        clientPrint("Sending unlock packet #4 (000, duplicate)")
        unlockPacket4 = unlockPacket3
        transport.write(unlockPacket4.__serialize__())

        print()
        clientPrint("Sending change password packet #1 (1234, bad format)")
        changePasswordPacket1 = ChangePasswordPacket()
        changePasswordPacket1.password = "1234"
        transport.write(changePasswordPacket1.__serialize__())

        print()
        clientPrint("Sending change password packet #2 (123)")
        changePasswordPacket2 = ChangePasswordPacket()
        changePasswordPacket2.password = "123"
        transport.write(changePasswordPacket2.__serialize__())

        print()
        clientPrint("Sending lock packet #1")
        lockPacket1 = LockPacket()
        transport.write(lockPacket1.__serialize__())

        print()
        clientPrint("Sending lock packet #2")
        lockPacket2 = LockPacket()
        transport.write(lockPacket1.__serialize__())

        print()
        clientPrint("Sending change password packet #3 (456, now locked)")
        changePasswordPacket3 = ChangePasswordPacket()
        changePasswordPacket3.password = "456"
        transport.write(changePasswordPacket3.__serialize__())

        print()
        clientPrint("Sending unlock packet #5 (000, wrong password)")
        unlockPacket5 = UnlockPacket()
        unlockPacket5.password = "000"
        transport.write(unlockPacket5.__serialize__())

        print()
        clientPrint("Sending unlock packet #6 (123)")
        unlockPacket6 = UnlockPacket()
        unlockPacket6.password = "123"
        transport.write(unlockPacket6.__serialize__())

        print()
        clientPrint("Sending unknown type packet")
        testOptionalListPacket = TestOptionalListPacket()
        testOptionalListPacket.testlist = ["Whatever"]
        transport.write(testOptionalListPacket.__serialize__())

        # transport.close is not implemented for MockTransportToProtocol
        # transport.close()

    def data_received(self, data):
        pkt = PacketType.Deserialize(data)
        if isinstance(pkt, ResponsePacket):
            clientPrint("LTP " + str(pkt.code) + " " +
                        LtpCode[pkt.code] + ", server message: " + pkt.message)

    def connection_lost(self, exc):
        clientPrint('The server closed the connection')


def basicUnitTest():
    lock = Lock("000", True)
    print("Unit test started; Lock initialized as locked, password = 000")
    # Modified from lab1c PDF
    asyncio.set_event_loop(TestLoopEx())
    client = LockClientProtocol()
    server = LockServerProtocol(lock)
    transportToServer = MockTransportToProtocol(server)
    transportToClient = MockTransportToProtocol(client)
    server.connection_made(transportToClient)
    client.connection_made(transportToServer)


if __name__ == "__main__":
    basicUnitTest()
