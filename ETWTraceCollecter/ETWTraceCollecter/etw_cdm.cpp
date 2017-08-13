#include <iostream>
#include <mutex>
#include <unordered_set>
#include "boost/functional/hash.hpp"

#include "avro/ValidSchema.hh"
#include "serialization/utils.h"
#include "serialization/avro_generic_serializer.h"

#include "etw_cdm.h"


extern template class tc_serialization::AvroGenericSerializer<tc_schema::TCCDMDatum>;

namespace etw_cdm {

struct ArrayHash {
    size_t operator() (const boost::array<uint8_t, 16> &a) {
        return boost::hash_range(a.begin(), a.end());
    }
};

static avro::ValidSchema schema(tc_serialization::utils::loadSchema(SCHEMA_FILE));
static tc_serialization::AvroGenericSerializer<tc_schema::TCCDMDatum> serializer(schema);
static std::mutex serializer_mutex;

static std::unordered_set<boost::array<uint8_t, 16>, ArrayHash> principal_htable; 
static std::mutex principal_htable_mutex;
/* ... */
static std::unordered_set<boost::array<uint8_t, 16>, ArrayHash> subject_htable;
static std::mutex subject_htable_mutex;
static std::unordered_set<boost::array<uint8_t, 16>, ArrayHash> fileobject_htable;
static std::mutex fileobject_htable_mutex;


static
boost::array<uint8_t, 16> nextUUID() {
    static boost::array<uint8_t, 16> uuid;
    int carry = 1;
    uint16_t tmp = 0;
	for (int i = 15; i >= 0; i--) {
	    if (uuid[i] == 255 && carry) {
	        uuid[i] = 0;
	    } else {
	        uuid[i] ++;
	        break;
	    }
	}
    return uuid;
}

static
std::vector<tc_schema::TCCDMDatum> parseEvent1(const output_format &output) {
    std::vector<tc_schema::TCCDMDatum> ret;
    /* Do parse here */
    return ret;
}

static 
std::vector<tc_schema::TCCDMDatum> parseEvent51(const output_format &output) {
    std::vector<tc_schema::TCCDMDatum> ret;
    tc_schema::TCCDMDatum event_record;
    tc_schema::Event event;
    event.uuid = nextUUID();
    // event.threadId = output.current_process_id;
    // event.name = output.systemcall_parameter;
    event_record.datum.set_Event(event);
    // event_record.source = tc_schema::SOURCE_LINUX_THEIA;
    event_record.CDMVersion = "17";
    ret.push_back(event_record);
    return ret;
}

std::vector<tc_schema::TCCDMDatum> convertToRecord(const output_format &output) {
    std::vector<tc_schema::TCCDMDatum> ret;

    switch(output.event_type) {
        case 1: ret = parseEvent1(output); break;
        /* ... */
        case 51: ret = parseEvent51(output); break;
        default: 
            std::cerr << "Unknown Event Type: " << output.event_type << std::endl;
    }
    return ret;
}

std::vector<uint8_t> serializeToBytes(const output_format &output) {
    std::vector<tc_schema::TCCDMDatum> records = convertToRecord(output);
    std::vector<uint8_t> ret;
    serializer_mutex.lock();
    for (auto cur : records) {
        std::vector<uint8_t> bytes = serializer.serializeToBytes(cur);
        ret.reserve(ret.size() + bytes.size());
        ret.insert(ret.end(), bytes.begin(), bytes.end());
    }
    serializer_mutex.unlock();
    return ret;
}

}

