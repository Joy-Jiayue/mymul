#include "encoding.h"

require_extension(EXT_ZCA);
WRITE_RD(sext_xlen(RVC_RS1 * RVC_RS2));  // 实现乘法操作

