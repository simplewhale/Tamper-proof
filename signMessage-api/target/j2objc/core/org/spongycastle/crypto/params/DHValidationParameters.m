//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/DHValidationParameters.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/params/DHValidationParameters.h"
#include "org/spongycastle/util/Arrays.h"

@interface OrgSpongycastleCryptoParamsDHValidationParameters () {
 @public
  IOSByteArray *seed_;
  jint counter_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsDHValidationParameters, seed_, IOSByteArray *)

@implementation OrgSpongycastleCryptoParamsDHValidationParameters

- (instancetype)initWithByteArray:(IOSByteArray *)seed
                          withInt:(jint)counter {
  OrgSpongycastleCryptoParamsDHValidationParameters_initWithByteArray_withInt_(self, seed, counter);
  return self;
}

- (jint)getCounter {
  return counter_;
}

- (IOSByteArray *)getSeed {
  return seed_;
}

- (jboolean)isEqual:(id)o {
  if (!([o isKindOfClass:[OrgSpongycastleCryptoParamsDHValidationParameters class]])) {
    return false;
  }
  OrgSpongycastleCryptoParamsDHValidationParameters *other = (OrgSpongycastleCryptoParamsDHValidationParameters *) cast_chk(o, [OrgSpongycastleCryptoParamsDHValidationParameters class]);
  if (((OrgSpongycastleCryptoParamsDHValidationParameters *) nil_chk(other))->counter_ != self->counter_) {
    return false;
  }
  return OrgSpongycastleUtilArrays_areEqualWithByteArray_withByteArray_(self->seed_, other->seed_);
}

- (NSUInteger)hash {
  return counter_ ^ OrgSpongycastleUtilArrays_hashCodeWithByteArray_(seed_);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "I", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 3, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithByteArray:withInt:);
  methods[1].selector = @selector(getCounter);
  methods[2].selector = @selector(getSeed);
  methods[3].selector = @selector(isEqual:);
  methods[4].selector = @selector(hash);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "seed_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "counter_", "I", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "[BI", "equals", "LNSObject;", "hashCode" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoParamsDHValidationParameters = { "DHValidationParameters", "org.spongycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 5, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoParamsDHValidationParameters;
}

@end

void OrgSpongycastleCryptoParamsDHValidationParameters_initWithByteArray_withInt_(OrgSpongycastleCryptoParamsDHValidationParameters *self, IOSByteArray *seed, jint counter) {
  NSObject_init(self);
  self->seed_ = seed;
  self->counter_ = counter;
}

OrgSpongycastleCryptoParamsDHValidationParameters *new_OrgSpongycastleCryptoParamsDHValidationParameters_initWithByteArray_withInt_(IOSByteArray *seed, jint counter) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsDHValidationParameters, initWithByteArray_withInt_, seed, counter)
}

OrgSpongycastleCryptoParamsDHValidationParameters *create_OrgSpongycastleCryptoParamsDHValidationParameters_initWithByteArray_withInt_(IOSByteArray *seed, jint counter) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsDHValidationParameters, initWithByteArray_withInt_, seed, counter)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoParamsDHValidationParameters)
