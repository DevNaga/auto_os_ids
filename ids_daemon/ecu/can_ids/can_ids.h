//
// Created by devnaga on 5/30/20.
//

#include <stdint.h>

#ifndef AUTO_OS_MIDDLEWARE_IDS_CAN_IDS_H
#define AUTO_OS_MIDDLEWARE_IDS_CAN_IDS_H

struct ids_can_ids_filter_set {
    uint32_t msgid;
    uint8_t is_11bit;
    uint8_t is_29bit;
};

struct ids_can_ids_filters {

};

#endif //AUTO_OS_CAN_IDS_H
