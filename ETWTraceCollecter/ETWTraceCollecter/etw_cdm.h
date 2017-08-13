#ifndef ETW_CDM_H_
#define ETW_CDM_H_

#include <vector>
#include "tc_schema/cdm.h"
#include "trace_parser.h"

#define SCHEMA_FILE "TCCDMDatum.avsc"

namespace etw_cdm {

std::vector<uint8_t> serializeToBytes(const output_format &output);
std::vector<tc_schema::TCCDMDatum> convertToRecord(const output_format &output);
    
}



#endif
