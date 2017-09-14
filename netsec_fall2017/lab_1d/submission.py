from playground.network.packet import PacketType
from playground.network.packet.fieldtypes import UINT32, STRING, ListFieldType
from playground.network.packet.fieldtypes.attributes import Optional
from playground.asyncio_lib.testing import TestLoopEx
from playground.network.testing import MockTransportToStorageStream, MockTransportToProtocol
import asyncio
import hashlib
import os
import argparse
import sys
import playground

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
    def __init__(self, future=None):
        self.transport = None
        self.responseCount = 0
        self.future = future
        self.pktCount = 0

    def connection_made(self, transport):
        self.transport = transport

    def sendPackets(self, pktInfoSequence):
        self.pktCount += len(pktInfoSequence)
        for pktInfo in pktInfoSequence:
            # newline
            print()
            # print text description
            clientPrint(pktInfo[0])
            # send packet
            self.transport.write(pktInfo[1].__serialize__())

    def data_received(self, data):
        pkt = PacketType.Deserialize(data)
        if isinstance(pkt, ResponsePacket):
            clientPrint("LTP " + str(pkt.code) + " " +
                        LtpCode[pkt.code] + ", server message: " + pkt.message)
        self.responseCount += 1
        if self.responseCount == self.pktCount:
            # All request completed
            self.transport.close()

    def connection_lost(self, exc):
        clientPrint('The server closed the connection')
        self.transport = None
        if self.future:
            self.future.set_result(0)


def basicUnitTest():
    # initialize packets
    pktInfoSequence = []

    unlockPacket1 = UnlockPacket()
    unlockPacket1.password = "1234"
    pktInfoSequence.append(
        ("Sending unlock packet #1 (1234, bad format)", unlockPacket1))

    unlockPacket2 = UnlockPacket()
    unlockPacket2.password = "001"
    pktInfoSequence.append(
        ("Sending unlock packet #2 (001, wrong password)", unlockPacket2))

    unlockPacket3 = UnlockPacket()
    unlockPacket3.password = "000"
    pktInfoSequence.append(("Sending unlock packet #3 (000)", unlockPacket3))

    unlockPacket4 = unlockPacket3
    pktInfoSequence.append(
        ("Sending unlock packet #4 (000, duplicate)", unlockPacket4))

    changePasswordPacket1 = ChangePasswordPacket()
    changePasswordPacket1.password = "1234"
    pktInfoSequence.append(
        ("Sending change password packet #1 (1234, bad format)", changePasswordPacket1))

    changePasswordPacket2 = ChangePasswordPacket()
    changePasswordPacket2.password = "123"
    pktInfoSequence.append(
        ("Sending change password packet #2 (123)", changePasswordPacket2))

    lockPacket1 = LockPacket()
    pktInfoSequence.append(("Sending lock packet #1", lockPacket1))

    lockPacket2 = LockPacket()
    pktInfoSequence.append(("Sending lock packet #2", lockPacket2))

    changePasswordPacket3 = ChangePasswordPacket()
    changePasswordPacket3.password = "456"
    pktInfoSequence.append(
        ("Sending change password packet #3 (456, now locked)", changePasswordPacket3))

    unlockPacket5 = UnlockPacket()
    unlockPacket5.password = "000"
    pktInfoSequence.append(
        ("Sending unlock packet #5 (000, wrong password)", unlockPacket5))

    unlockPacket6 = UnlockPacket()
    unlockPacket6.password = "123"
    pktInfoSequence.append(("Sending unlock packet #6 (123)", unlockPacket6))

    testOptionalListPacket = TestOptionalListPacket()
    testOptionalListPacket.testlist = ["Whatever"]
    pktInfoSequence.append(
        ("Sending unknown type packet", testOptionalListPacket))

    lock = Lock("000", True)
    print("Unit test started; Lock initialized as locked, password = 000")
    # Modified from lab1c PDF
    asyncio.set_event_loop(TestLoopEx())
    clientProtocol = LockClientProtocol()
    serverProtocol = LockServerProtocol(lock)
    cTransport, sTransport = MockTransportToProtocol.CreateTransportPair(
        clientProtocol, serverProtocol)
    # Initialize server first to obtain transport
    serverProtocol.connection_made(sTransport)
    clientProtocol.connection_made(cTransport)
    clientProtocol.sendPackets(pktInfoSequence)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description='Network Security Lab 1d Submission', formatter_class=argparse.RawTextHelpFormatter)
    parser.add_argument('--address', default='20174.8.16.32', help='''client only:
Playground address of lock server (default to 20174.8.16.32).''')
    parser.add_argument('option', metavar='option', choices=['server', 'client', 'unittest'],
                        help='application mode: {server, client, unittest}')
    parser.add_argument('request', nargs='*',
                        help='''client request:
unlock PASSWORD: unlock with the given password.
changePassword NEW_PASSWORD: reset the lock's password (only when unlocked)
lock: set the lock to be locked.''')
    if len(sys.argv) == 1:
        basicUnitTest()
        print()
        print("Note: run with --help for more options")
        sys.exit(1)
    args = parser.parse_args()
    if args.option == "unittest":
        basicUnitTest()
    elif args.option == "server":
        lock = Lock("000", True)
        print("Server mode; Lock initialized as locked, password = 000")
        loop = asyncio.get_event_loop()
        loop.set_debug(enabled=True)
        # Each client connection will create a new protocol instance
        coro = playground.getConnector().create_playground_server(
            lambda: LockServerProtocol(lock), 32768)
        server = loop.run_until_complete(coro)

        # Serve requests until Ctrl+C is pressed
        # print('Serving on {}'.format(server.sockets[0].getsockname()))
        print('Serving on Playground route ' + server.sockets[0].gethostname()[
              0] + ", port " + str(server.sockets[0].gethostname()[1]))
        try:
            loop.run_forever()
        except KeyboardInterrupt:
            pass

        # Close the server
        server.close()
        # loop.run_until_complete(server.wait_closed())
        loop.close()
    elif args.option == "client":
        if args.request and len(args.request):
            pktInfoSequence = []
            if args.request[0] == "unlock":
                if len(args.request) >= 2:
                    clientPrint("Client mode, request = unlock")
                    unlockPacket = UnlockPacket()
                    unlockPacket.password = args.request[1]
                    pktInfoSequence.append(
                        ("Sending unlock packet, password = " + args.request[1], unlockPacket))
            elif args.request[0] == "changePassword":
                if len(args.request) >= 2:
                    clientPrint("Client mode, request = change password")
                    changePasswordPacket = ChangePasswordPacket()
                    changePasswordPacket.password = args.request[1]
                    pktInfoSequence.append(
                        ("Sending change password packet, new password = " + args.request[1], changePasswordPacket))
            elif args.request[0] == "lock":
                clientPrint("Client mode, request = lock")
                lockPacket = LockPacket()
                pktInfoSequence.append(("Sending lock packet", lockPacket))
            if not len(pktInfoSequence):
                parser.print_help()
                sys.exit(1)
            loop = asyncio.get_event_loop()
            # loop.set_debug(enabled=True)
            future = asyncio.Future()
            coro = playground.getConnector().create_playground_connection(
                lambda: LockClientProtocol(future), args.address, 32768, "default", 0, 3)
            transport, protocol = loop.run_until_complete(coro)
            protocol.sendPackets(pktInfoSequence)
            # run until completion of request
            loop.run_until_complete(future)
            loop.close()
        else:
            parser.print_help()
            sys.exit(1)
