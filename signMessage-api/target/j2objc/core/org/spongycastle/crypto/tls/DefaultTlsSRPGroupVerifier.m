//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/DefaultTlsSRPGroupVerifier.java
//

#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "java/util/Vector.h"
#include "org/spongycastle/crypto/agreement/srp/SRP6StandardGroups.h"
#include "org/spongycastle/crypto/params/SRP6GroupParameters.h"
#include "org/spongycastle/crypto/tls/DefaultTlsSRPGroupVerifier.h"

J2OBJC_INITIALIZED_DEFN(OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier)

JavaUtilVector *OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_DEFAULT_GROUPS;

@implementation OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (instancetype)initWithJavaUtilVector:(JavaUtilVector *)groups {
  OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_initWithJavaUtilVector_(self, groups);
  return self;
}

- (jboolean)acceptWithOrgSpongycastleCryptoParamsSRP6GroupParameters:(OrgSpongycastleCryptoParamsSRP6GroupParameters *)group {
  for (jint i = 0; i < [((JavaUtilVector *) nil_chk(groups_)) size]; ++i) {
    if ([self areGroupsEqualWithOrgSpongycastleCryptoParamsSRP6GroupParameters:group withOrgSpongycastleCryptoParamsSRP6GroupParameters:(OrgSpongycastleCryptoParamsSRP6GroupParameters *) cast_chk([((JavaUtilVector *) nil_chk(groups_)) elementAtWithInt:i], [OrgSpongycastleCryptoParamsSRP6GroupParameters class])]) {
      return true;
    }
  }
  return false;
}

- (jboolean)areGroupsEqualWithOrgSpongycastleCryptoParamsSRP6GroupParameters:(OrgSpongycastleCryptoParamsSRP6GroupParameters *)a
                          withOrgSpongycastleCryptoParamsSRP6GroupParameters:(OrgSpongycastleCryptoParamsSRP6GroupParameters *)b {
  return a == b || ([self areParametersEqualWithJavaMathBigInteger:[((OrgSpongycastleCryptoParamsSRP6GroupParameters *) nil_chk(a)) getN] withJavaMathBigInteger:[((OrgSpongycastleCryptoParamsSRP6GroupParameters *) nil_chk(b)) getN]] && [self areParametersEqualWithJavaMathBigInteger:[a getG] withJavaMathBigInteger:[b getG]]);
}

- (jboolean)areParametersEqualWithJavaMathBigInteger:(JavaMathBigInteger *)a
                              withJavaMathBigInteger:(JavaMathBigInteger *)b {
  return a == b || [((JavaMathBigInteger *) nil_chk(a)) isEqual:b];
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "Z", 0x1, 1, 2, -1, -1, -1, -1 },
    { NULL, "Z", 0x4, 3, 4, -1, -1, -1, -1 },
    { NULL, "Z", 0x4, 5, 6, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(initWithJavaUtilVector:);
  methods[2].selector = @selector(acceptWithOrgSpongycastleCryptoParamsSRP6GroupParameters:);
  methods[3].selector = @selector(areGroupsEqualWithOrgSpongycastleCryptoParamsSRP6GroupParameters:withOrgSpongycastleCryptoParamsSRP6GroupParameters:);
  methods[4].selector = @selector(areParametersEqualWithJavaMathBigInteger:withJavaMathBigInteger:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "DEFAULT_GROUPS", "LJavaUtilVector;", .constantValue.asLong = 0, 0x1c, -1, 7, -1, -1 },
    { "groups_", "LJavaUtilVector;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaUtilVector;", "accept", "LOrgSpongycastleCryptoParamsSRP6GroupParameters;", "areGroupsEqual", "LOrgSpongycastleCryptoParamsSRP6GroupParameters;LOrgSpongycastleCryptoParamsSRP6GroupParameters;", "areParametersEqual", "LJavaMathBigInteger;LJavaMathBigInteger;", &OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_DEFAULT_GROUPS };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier = { "DefaultTlsSRPGroupVerifier", "org.spongycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 5, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier;
}

+ (void)initialize {
  if (self == [OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier class]) {
    OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_DEFAULT_GROUPS = new_JavaUtilVector_init();
    {
      [OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_DEFAULT_GROUPS addElementWithId:JreLoadStatic(OrgSpongycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_1024)];
      [OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_DEFAULT_GROUPS addElementWithId:JreLoadStatic(OrgSpongycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_1536)];
      [OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_DEFAULT_GROUPS addElementWithId:JreLoadStatic(OrgSpongycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_2048)];
      [OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_DEFAULT_GROUPS addElementWithId:JreLoadStatic(OrgSpongycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_3072)];
      [OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_DEFAULT_GROUPS addElementWithId:JreLoadStatic(OrgSpongycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_4096)];
      [OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_DEFAULT_GROUPS addElementWithId:JreLoadStatic(OrgSpongycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_6144)];
      [OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_DEFAULT_GROUPS addElementWithId:JreLoadStatic(OrgSpongycastleCryptoAgreementSrpSRP6StandardGroups, rfc5054_8192)];
    }
    J2OBJC_SET_INITIALIZED(OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier)
  }
}

@end

void OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_init(OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier *self) {
  OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_initWithJavaUtilVector_(self, OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_DEFAULT_GROUPS);
}

OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier *new_OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier, init)
}

OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier *create_OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier, init)
}

void OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_initWithJavaUtilVector_(OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier *self, JavaUtilVector *groups) {
  NSObject_init(self);
  self->groups_ = groups;
}

OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier *new_OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_initWithJavaUtilVector_(JavaUtilVector *groups) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier, initWithJavaUtilVector_, groups)
}

OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier *create_OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier_initWithJavaUtilVector_(JavaUtilVector *groups) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier, initWithJavaUtilVector_, groups)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoTlsDefaultTlsSRPGroupVerifier)