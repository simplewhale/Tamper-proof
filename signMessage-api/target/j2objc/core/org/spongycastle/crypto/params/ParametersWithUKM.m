//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/params/ParametersWithUKM.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/System.h"
#include "org/spongycastle/crypto/CipherParameters.h"
#include "org/spongycastle/crypto/params/ParametersWithUKM.h"

@interface OrgSpongycastleCryptoParamsParametersWithUKM () {
 @public
  IOSByteArray *ukm_;
  id<OrgSpongycastleCryptoCipherParameters> parameters_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsParametersWithUKM, ukm_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoParamsParametersWithUKM, parameters_, id<OrgSpongycastleCryptoCipherParameters>)

@implementation OrgSpongycastleCryptoParamsParametersWithUKM

- (instancetype)initWithOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)parameters
                                                withByteArray:(IOSByteArray *)ukm {
  OrgSpongycastleCryptoParamsParametersWithUKM_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_(self, parameters, ukm);
  return self;
}

- (instancetype)initWithOrgSpongycastleCryptoCipherParameters:(id<OrgSpongycastleCryptoCipherParameters>)parameters
                                                withByteArray:(IOSByteArray *)ukm
                                                      withInt:(jint)ivOff
                                                      withInt:(jint)ivLen {
  OrgSpongycastleCryptoParamsParametersWithUKM_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_withInt_withInt_(self, parameters, ukm, ivOff, ivLen);
  return self;
}

- (IOSByteArray *)getUKM {
  return ukm_;
}

- (id<OrgSpongycastleCryptoCipherParameters>)getParameters {
  return parameters_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoCipherParameters;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoCipherParameters:withByteArray:);
  methods[1].selector = @selector(initWithOrgSpongycastleCryptoCipherParameters:withByteArray:withInt:withInt:);
  methods[2].selector = @selector(getUKM);
  methods[3].selector = @selector(getParameters);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "ukm_", "[B", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
    { "parameters_", "LOrgSpongycastleCryptoCipherParameters;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoCipherParameters;[B", "LOrgSpongycastleCryptoCipherParameters;[BII" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoParamsParametersWithUKM = { "ParametersWithUKM", "org.spongycastle.crypto.params", ptrTable, methods, fields, 7, 0x1, 4, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoParamsParametersWithUKM;
}

@end

void OrgSpongycastleCryptoParamsParametersWithUKM_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_(OrgSpongycastleCryptoParamsParametersWithUKM *self, id<OrgSpongycastleCryptoCipherParameters> parameters, IOSByteArray *ukm) {
  OrgSpongycastleCryptoParamsParametersWithUKM_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_withInt_withInt_(self, parameters, ukm, 0, ((IOSByteArray *) nil_chk(ukm))->size_);
}

OrgSpongycastleCryptoParamsParametersWithUKM *new_OrgSpongycastleCryptoParamsParametersWithUKM_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_(id<OrgSpongycastleCryptoCipherParameters> parameters, IOSByteArray *ukm) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsParametersWithUKM, initWithOrgSpongycastleCryptoCipherParameters_withByteArray_, parameters, ukm)
}

OrgSpongycastleCryptoParamsParametersWithUKM *create_OrgSpongycastleCryptoParamsParametersWithUKM_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_(id<OrgSpongycastleCryptoCipherParameters> parameters, IOSByteArray *ukm) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsParametersWithUKM, initWithOrgSpongycastleCryptoCipherParameters_withByteArray_, parameters, ukm)
}

void OrgSpongycastleCryptoParamsParametersWithUKM_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_withInt_withInt_(OrgSpongycastleCryptoParamsParametersWithUKM *self, id<OrgSpongycastleCryptoCipherParameters> parameters, IOSByteArray *ukm, jint ivOff, jint ivLen) {
  NSObject_init(self);
  self->ukm_ = [IOSByteArray newArrayWithLength:ivLen];
  self->parameters_ = parameters;
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(ukm, ivOff, self->ukm_, 0, ivLen);
}

OrgSpongycastleCryptoParamsParametersWithUKM *new_OrgSpongycastleCryptoParamsParametersWithUKM_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_withInt_withInt_(id<OrgSpongycastleCryptoCipherParameters> parameters, IOSByteArray *ukm, jint ivOff, jint ivLen) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoParamsParametersWithUKM, initWithOrgSpongycastleCryptoCipherParameters_withByteArray_withInt_withInt_, parameters, ukm, ivOff, ivLen)
}

OrgSpongycastleCryptoParamsParametersWithUKM *create_OrgSpongycastleCryptoParamsParametersWithUKM_initWithOrgSpongycastleCryptoCipherParameters_withByteArray_withInt_withInt_(id<OrgSpongycastleCryptoCipherParameters> parameters, IOSByteArray *ukm, jint ivOff, jint ivLen) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoParamsParametersWithUKM, initWithOrgSpongycastleCryptoCipherParameters_withByteArray_withInt_withInt_, parameters, ukm, ivOff, ivLen)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoParamsParametersWithUKM)