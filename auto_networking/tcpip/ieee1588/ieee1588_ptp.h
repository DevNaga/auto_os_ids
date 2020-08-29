#ifndef __AUTO_NETWORK_IEEE1588_PTP_H__
#define __AUTO_NETWORK_IEEE1588_PTP_H__

namespace auto_os::network {

#define TRANSPORT_SPECIFIC_DEFAULT 0
#define TRANSPORT_SPECIFIC_8021AS 1

enum class MessageType {
    eSync = 0,
    eDelay_Req = 1,
    ePdelay_Req = 2,
    ePdelay_Resp = 3,
    eFollow_Up = 8,
    eDelay_Resp = 9,
    ePdelay_Resp_Followup = 10,
    eAnnounce = 11,
    eSignalling = 12,
    eManagement = 13,
};

#define VERSION_PTP_IEEE_1588_2002 1
#define VERSION_PTP_IEEE_1588_2008 2

struct ieee1588_ptp {
    int transportSpecific; // 4 bits
    MessageType msgType; // 4 bits
    int reserved; // 4 bits
    int versionPTP; // 4 bits
    int messageLength; // 16 bits.. no padding
    int domainNumber; // 0 to 128 .. 8 bits
    int reserved; // 8 bits
    int flags;
    uint64_t correctionField;
    uint32_t reserved;
    uint8_t sourcePortIdentity[10];
};

}

#endif

