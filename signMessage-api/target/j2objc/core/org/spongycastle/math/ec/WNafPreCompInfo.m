//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/WNafPreCompInfo.java
//

#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "org/spongycastle/math/ec/ECPoint.h"
#include "org/spongycastle/math/ec/WNafPreCompInfo.h"

@implementation OrgSpongycastleMathEcWNafPreCompInfo

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleMathEcWNafPreCompInfo_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (IOSObjectArray *)getPreComp {
  return preComp_;
}

- (void)setPreCompWithOrgSpongycastleMathEcECPointArray:(IOSObjectArray *)preComp {
  self->preComp_ = preComp;
}

- (IOSObjectArray *)getPreCompNeg {
  return preCompNeg_;
}

- (void)setPreCompNegWithOrgSpongycastleMathEcECPointArray:(IOSObjectArray *)preCompNeg {
  self->preCompNeg_ = preCompNeg;
}

- (OrgSpongycastleMathEcECPoint *)getTwice {
  return twice_;
}

- (void)setTwiceWithOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)twice {
  self->twice_ = twice;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[LOrgSpongycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, -1, -1, -1, -1 },
    { NULL, "[LOrgSpongycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 2, 1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleMathEcECPoint;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 3, 4, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(getPreComp);
  methods[2].selector = @selector(setPreCompWithOrgSpongycastleMathEcECPointArray:);
  methods[3].selector = @selector(getPreCompNeg);
  methods[4].selector = @selector(setPreCompNegWithOrgSpongycastleMathEcECPointArray:);
  methods[5].selector = @selector(getTwice);
  methods[6].selector = @selector(setTwiceWithOrgSpongycastleMathEcECPoint:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "preComp_", "[LOrgSpongycastleMathEcECPoint;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "preCompNeg_", "[LOrgSpongycastleMathEcECPoint;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "twice_", "LOrgSpongycastleMathEcECPoint;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "setPreComp", "[LOrgSpongycastleMathEcECPoint;", "setPreCompNeg", "setTwice", "LOrgSpongycastleMathEcECPoint;" };
  static const J2ObjcClassInfo _OrgSpongycastleMathEcWNafPreCompInfo = { "WNafPreCompInfo", "org.spongycastle.math.ec", ptrTable, methods, fields, 7, 0x1, 7, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleMathEcWNafPreCompInfo;
}

@end

void OrgSpongycastleMathEcWNafPreCompInfo_init(OrgSpongycastleMathEcWNafPreCompInfo *self) {
  NSObject_init(self);
  self->preComp_ = nil;
  self->preCompNeg_ = nil;
  self->twice_ = nil;
}

OrgSpongycastleMathEcWNafPreCompInfo *new_OrgSpongycastleMathEcWNafPreCompInfo_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcWNafPreCompInfo, init)
}

OrgSpongycastleMathEcWNafPreCompInfo *create_OrgSpongycastleMathEcWNafPreCompInfo_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcWNafPreCompInfo, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleMathEcWNafPreCompInfo)
