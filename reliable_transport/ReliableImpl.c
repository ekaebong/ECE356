#include "ReliableImpl.h"

// You can add necessary functions here


// reliImplCreate: Constructor. You can add variables to maintain your
// sliding window states.
// 'reli' provides an interface to call functions of struct Reliable.
// 'seqNum' indicates the initail sequence number in the SYN segment.
ReliableImpl *reliImplCreate(Reliable *_reli, uint32_t _seqNum)
{
    ReliableImpl *reliImpl = (ReliableImpl *)malloc(sizeof(ReliableImpl));
    reliImpl->reli = _reli;
    reliImpl->seqNum = _seqNum;

    //TODO: Your code here

    return reliImpl;
}

// reliImplClose: Destructor, free the memory for maintaining states.
void reliImplClose(ReliableImpl *reliImpl)
{
    //TODO: Your code here

    Free(reliImpl);
}

// reliImplChecksum: 16-bit Internet checksum (refer to RFC 1071 for calculation)
// This function should return the value of checksum (an unsigned 16-bit integer).
// You should calculate the checksum over 'buf', which is an array of char bytes
// 'len' ist the length of buf.
uint16_t reliImplChecksum(const char *buf, ssize_t len)
{
    //TODO: Your code here

    return 0;
}

// reliImplRecvAck: When an ACK or FINACK segment is received, the framework will
// call this function to handle the segment.
// The checksum will be verified before calling this function, so you
// do not need to verify checksum again in this function.
// Remember to call reliUpdateRWND to update the receive window size.
// Note that this function should return the reduction of bytes in flight
// (a non-positive integer) so that Reliable.h/c can update the bytes in flight.
// 'seg' is an instance of struct Segment (see Util.h/c)
// 'isFin'=True means 'seg' is a FINACK, otherwise it is an ACK.
int32_t reliImplRecvAck(ReliableImpl *reliImpl, const Segment *seg, bool isFin)
{
    //TODO: Your code here

    return 0;
}

// reliImplSendData: This function is called when a block of data should be sent out.
// You can call segPack in Util.h/c to encapsulate a segment and
// call reliSetTimer (see Reliable.h) to set a Timer for retransmission.
// Use reliSendto (see Reliable.h) to send a segment to the receiver.
// Note that this function should return the increment of bytes in flight
// (a non-negative integer) so that Reliable.h/c can update the bytes in flight.
// 'block' is an array of char bytes.
// 'blocklen' is the length of block.
// 'isFin'=True means a FIN segment should be sent out.
int32_t reliImplSendData(ReliableImpl *reliImpl, char *block, uint16_t blocklen, bool isFin)
{
    //TODO: Your code here

    return 0;
}

// reliImplRetransmission: A callback function for retransmission
// when you call reliSetTimer.
// In C/C++, you should NOT modify the arguments of this function.
void *reliImplRetransmission(void *args)
{
    //TODO: Your code here

    return 0;
}
