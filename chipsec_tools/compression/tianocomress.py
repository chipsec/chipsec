import struct


class TianoError(RuntimeError):
    pass


class Decompress:
    #Globals found within TianoCompress.h
    BITBUFSIZ = 32
    UINT8_MAX = 0xFF
    THRESHOLD = 3
    CODE_BIT = 16
    NT = CODE_BIT + 3
    TBIT = 5
    MAXPBIT = 5
    MAXNP = (1 << MAXPBIT) - 1
    if NT > MAXNP:
        NPT = NT
    else:
        NPT = MAXNP
    CBIT = 9
    MAXMATCH = 256
    NC = 0xff + MAXMATCH + 2 - THRESHOLD

    def __init__(self):
        self.BitCount = 0
        self.BitBuf = 0
        self.subBitBuf = 0
        self.srcbufloc = 0
        self.dstbuffer = ""
        self.BadTableFlag = False
        self.BlockSize = 0
        self.CLen = [0 for i in range(self.NC)]
        self.CTable = [0 for i in range(4096)]
        self.PTLen = [0 for i in range(self.NPT)]
        self.PTTable = [0 for i in range(256)]

    def Decompress(self, buffer, Version=2):
        if Version not in [1, 2]:
            print('Version can only be 1 or 2')
            raise TianoError
        if len(buffer) < 8:
            print('invalid buffer')
            raise TianoError
        self.dstbuffer == ""
        self.PBit = 4 if Version == 1 else 5
        self.srcbuffer = buffer[8:]
        self._ParseHeader(buffer[:8])
        self._FillBuf(self.BITBUFSIZ)
        self._Decode()
        return self.dstbuffer

    def _ParseHeader(self, buffer):
        Header = 'BBBB'
        Header_sz = struct.calcsize(Header)
        temp0, temp1, temp2, temp3 = struct.unpack(Header, buffer[:Header_sz])
        self.CompSize = temp0 + (temp1 << 8) + (temp2 << 16) + (temp3 << 24)
        temp0, temp1, temp2, temp3 = struct.unpack(Header, buffer[Header_sz:2 * Header_sz])
        self.OrigSize = temp0 + (temp1 << 8) + (temp2 << 16) + (temp3 << 24)
        if len(self.srcbuffer) != self.CompSize:
            print('Size denoted within header does not match buffer size')
            raise TianoError

    def _FillBuf(self, NumBits):
        self.BitBuf = 0xFFFFFFFF & (self.BitBuf << NumBits)
        while NumBits > self.BitCount:
            NumBits -= self.BitCount
            self.BitBuf |= 0xFFFFFFFF & (self.subBitBuf << NumBits)
            self.BitCount = 8
            self.subBitBuf = 0
            if self.CompSize > 0:
                self.CompSize -= 1
                self.subBitBuf = ord(self.srcbuffer[self.srcbufloc])
                self.srcbufloc += 1
                self.BitCount = 8
        self.BitCount = 0xFFFF & (self.BitCount - NumBits)
        self.BitBuf = self.BitBuf | (self.subBitBuf >> self.BitCount)

    def _Decode(self):
        BytesRemain = 0xFF
        DataIdx = 0

        while 1:
            CharC = self._DecodeC()
            if self.BadTableFlag:
                break
            if CharC < 256:
                if len(self.dstbuffer) >= self.OrigSize:
                    break
                self.dstbuffer += chr(CharC & 0xFF)
            else:
                CharC = 0xFFFF & (CharC - (self.UINT8_MAX + 1 - self.THRESHOLD))
                BytesRemain = 0xFFFF & (CharC - 1)
                DataIdx = len(self.dstbuffer) - self._DecodeP() - 1
                for Index in range(DataIdx, DataIdx + BytesRemain):
                    if len(self.dstbuffer) >= self.OrigSize:
                        break
                    if Index > self.OrigSize:
                        self.BadTableFlag = True
                        break
                    self.dstbuffer += self.dstbuffer[Index]
                if len(self.dstbuffer) >= self.OrigSize:
                    break

    def _DecodeC(self):
        if self.BlockSize == 0:
            self.BlockSize = 0xFFFF & self._GetBits(16)
            self.BadTableFlag = self._ReadPTLen(self.NT, self.TBIT, 3)
            if self.BadTableFlag:
                return 0
            self._ReadCLen()
            self.BadTableFlag = self._ReadPTLen(self.MAXNP, self.PBit, 0XFF)
            if self.BadTableFlag:
                return 0
        self.BlockSize -= 1
        Index2 = self.CTable[self.BitBuf >> (self.BITBUFSIZ - 12)]

        Mask = 1 << (self.BITBUFSIZ - 1 - 12)
        while Index2 >= self.NC:
            if self.BitBuf & Mask:
                Index2 = self.Right[Index2]
            else:
                Index2 = self.Left[Index2]
            Mask = Mask >> 1
        self._FillBuf(self.CLen[Index2])
        return Index2

    def _DecodeP(self):
        Val = self.PTTable[self.BitBuf >> (self.BITBUFSIZ - 8)]
        Mask = 1 << (self.BITBUFSIZ - 1 - 8)
        while Val >= self.MAXNP:
            if self.BitBuf & Mask:
                Val = self.Right[Val]
            else:
                Val = self.Left[Val]
            Mask = Mask >> 1
        self._FillBuf(self.PTLen[Val])
        Pos = Val
        if Val > 1:
            Pos = (1 << (Val - 1)) + self._GetBits(Val - 1)
        return Pos & 0xFFFFFFFF

    def _GetBits(self, NumBits):
        OutBits = self.BitBuf >> (self.BITBUFSIZ - NumBits)
        self._FillBuf(NumBits)
        return OutBits & 0xFFFFFFFF

    def _ReadCLen(self):
        Number = 0xFFFF & self._GetBits(self.CBIT)
        if Number == 0:
            CharC = 0xFFFF & self._GetBits(self.CBIT)
            self.CLen = [0 for i in range(self.NC)]
            self.CTable = [CharC for i in range(4096)]
            return
        Index = 0
        while Index < Number:
            CharC = self.PTTable[self.BitBuf >> (self.BITBUFSIZ - 8)]
            Mask = 1 << (self.BITBUFSIZ - 1 - 8)
            while CharC >= self.NT:
                if self.BitBuf & Mask:
                    CharC = self.Right[CharC]
                else:
                    CharC = self.Left[CharC]
                Mask = Mask >> 1
            self._FillBuf(self.PTLen[CharC])
            if CharC <= 2:
                if CharC == 0: CharC = 1
                elif CharC == 1: CharC = 0xFFFF & (self._GetBits(4) + 3)
                else: CharC = 0xFFFF & (self._GetBits(self.CBIT) + 20)
                CharC -= 1
                for tmp in range(CharC, -1, -1):
                    self.CLen[Index] = 0
                    Index += 1
                CharC = 0
            else:
                self.CLen[Index] = 0xFF & (CharC - 2)
                Index += 1
        for i in range(Index, self.NC):
            self.CLen[i] = 0
        (tmp, self.CTable) = self._MakeTable(self.NC, self.CLen, 12, self.CTable)
        return

    def _ReadPTLen(self, nn, nbit, Special):
        if nn > self.NPT:
            raise TianoError
        Number = 0xFFFF & self._GetBits(nbit)
        if (Number == 0):
            CharC = 0xFFFF & self._GetBits(nbit)
            self.PTTable = [CharC for i in range(256)]
            self.PTLen = [0 for i in range(nn)]
            return 0
        Index = 0
        while Index < Number:
            CharC = 0xFFFF & (self.BitBuf >> (self.BITBUFSIZ - 3))
            if CharC == 7:
                Mask = 1 << (self.BITBUFSIZ - 1 - 3)
                while (Mask & self.BitBuf):
                    Mask = Mask >> 1
                    CharC += 1
            self._FillBuf(3 if CharC < 7 else CharC - 3)
            self.PTLen[Index] = CharC
            Index += 1
            if Index == Special:
                CharC = 0xFFFF & self._GetBits(2)
                CharC -= 1
                while CharC >= 0:
                    self.PTLen[Index] = 0
                    Index += 1
                    CharC -= 1
        for i in range(Index, nn):
            self.PTLen[i] = 0
        (tmp, self.PTTable) = self._MakeTable(nn, self.PTLen, 8, self.PTTable)
        return tmp

    def _MakeTable(self, NumChar, BitLen, TableBits, Table):
        Count = [0 for i in range(17)]
        for Index in range(NumChar):
            if BitLen[Index] > 16:
                return (True, 0)
            Count[BitLen[Index]] += 1
        Start = [0 for i in range(18)]
        for Index in range(1, 17):
            WordofStart = Start[Index]
            WordofCount = Count[Index]
            Start[Index + 1] = 0xFFFF & (WordofStart + (WordofCount << (16 - Index)))
        if Start[17] != 0:
            return (True, 0)
        JuBits = 0xFFFF & (16 - TableBits)
        Weight = [0 for i in range(17)]
        for Index in range(1, TableBits + 1):
            Start[Index] = Start[Index] >> JuBits
            Weight[Index] = 0xFFFF & (1 << (TableBits - Index))
        for i in range(Index, 17):
            Weight[Index] = 0xFFFF & (1 << (16 - Index))
        Index = 0xFFFF & (Start[TableBits + 1] >> JuBits)
        if Index != 0:
            for Index3 in range(Index, 1 << TableBits):
                Table[Index] = 0
        Avail = NumChar
        Mask = 0xFFFF & (1 << 15 - TableBits)
        MaxTableLength = 0xFFFF & (1 << TableBits)
        for Char in range(NumChar):
            Len = BitLen[Char]
            if Len == 0 or Len >= 17:
                continue
            NextCode = 0xFFFF & (Start[Len] + Weight[Len])
            if Len <= TableBits:
                Index = Start[Len]
                if NextCode > MaxTableLength:
                    return (True, 0)
                while Index < NextCode:
                    Table[Index] = Char
                    Index += 1
                Start[Len] = Index
            else:
                Index3 = Start[Len]
                Pointer = Table[Index3 >> JuBits]
                Index = 0xFFFF & (Len - TableBits)
                while Index != 0:
                    if Pointer == 0:
                        self.Right[Avail] = 0
                        self.Left[Avail] = 0
                        Pointer = Avail
                        Avail += 1
                    if Index & Mask:
                        Pointer = self.Right[Pointer]
                    else:
                        Pointer = self.Left[Pointer]
                    Index3 = Index3 << 1
                    Index -= 1
                Start[Len] = NextCode
        return (False, Table)


CRCPOLY = 0xA001
WNDBIT = 19
WNDSIZ = (1 << WNDBIT)
BLKSIZ = 1 << 14
MAX_HASH_VAL = (3 * WNDSIZ + (WNDSIZ // 512 + 1) * UINT8_MAX)
NP = WNDBIT + 1
UINT8_BIT = 8
INIT_CRC = 0


class Compress:
    def __init__(self):
        self.dstbuffer = b''
        self.crcTable = [0 for i in range(256)]
        self.Text = [0 for i in range(WNDSIZ * 2 + MAXMATCH)]
        self.Level = [ 0 if i < WNDSIZ else 1 for i in range(WNDSIZ + UINT8_MAX + 1)]
        self.ChildCount = 0
        self.Position = [0 for i in range(WNDSIZ + UINT8_MAX + 1)]
        self.Parent = [0 for i in range(WNDSIZ * 2)]
        self.Prev = [0 for i in range(WNDSIZ * 2)]
        self.Next = [0 for i in range(MAX_HASH_VAL + 1)]
        self.BufSiz = BLKSIZ
        self.Buf = [0 for i in range(self.BufSiz)]
        self.mAvail = 1
        self.DstUpperLimit = 0

    def Compress(self, buffer):
        self.srcbuffer = buffer
        #self.PutDword(0)
        #self.PutDword(0)
        self.MakeCrcTable()
        self.OrigSize = 0
        self.CompSize = 0
        self.Crc = INIT_CRC
        # Compress it
        self.Encode()

        if len(self.dstbuffer) < self.DstUpperLimit:
            self.dstbuffer += b'\00'
        
        self.PutDword(len(self.srcbuffer))

        

    def PutDword(self, Dword):
        self.dstbuffer = struct.pack("<Q", Dword) + self.dstbuffer

    def MakeCrcTable(self):
        for Index in range(UINT8_MAX):
            Temp = Index
            for Index2 in range(UINT8_MAX):
                if Temp & 1:
                    Temp = (Temp >> 1) ^ CRCPOLY
                else:
                    Temp = Temp >> 1
            self.crcTable[Index] = Temp

    def Encode(self):
        self.InitSlide()
        self.HufEncodeStart()
        self.Remainder = self.FreadCrc(self.mText[WNDSIZ:], WNDSIZ + MAXMATCH)

        self.MatchLen = 0
        #Pos = WNDSIZ
        self.InsertNode()
        if self.MatchLen > self.Remainder:
            self.MatchLen = self.Remainder

    def InitSlide(self):
        for Index in range(1, WNDSIZ - 1):
            self.mnext[Index] = Index + 1

    def HufEncodeStart(self):
        #can move all to init
        self.CFreq = [0 for i in range(NC)]
        self.PFreq = [0 for i in range(NP)]
        self.OutputPos = 0
        self.OutputMask = 0
        self.InitPutBits()

    def InitPutBits(self):
        self.BitCount = UINT8_BIT
        self.SubBitBuf = 0

    def PutBits(self, Number, Value):
        pass

    def _SendBlock(self):
        pass

    def WritePTLen(self, Number, nbit, Special):
        pass

    def WriteCLen(self):
        pass

    def _EncodeP(self, Value):
        pass

    def _EncodeC(self, Value):
        pass

    def FreadCrc(self, Ptr, NumBits):
        pass

    def GetNextMatch(self):
        pass

    def Output(self):
        pass

    def HufEncodeEnd(self):
        pass

    def _CountLen(self, Index):
        pass

    def _MakeLen(self, Root):
        pass

    def _DownHeap(self, Index):
        pass

    def _MakeCode(self, Number, Len, Code):
        pass

    def _MakeTree(self, NParm, FreqParm, LenParm, CodeParm):
        pass

    def CountTFreq(self):
        pass

    def DeleteNode(self):
        pass

    def InsertNode(self):
        pass

    def Split(self, Old):
        pass

    def MakeChild(self, Parent, CharC, Child):
        pass

    def Child(self, NodeQ, CharC):
        pass

    def FreeMemory(self):
        pass

    def AllocateMemory(self):
        pass
