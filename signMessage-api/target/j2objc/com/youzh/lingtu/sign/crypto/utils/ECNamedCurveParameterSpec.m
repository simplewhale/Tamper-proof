//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/src/main/java/com/youzh/lingtu/sign/crypto/utils/ECNamedCurveParameterSpec.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "com/youzh/lingtu/sign/crypto/utils/ECNamedCurveParameterSpec.h"
#include "com/youzh/lingtu/sign/crypto/utils/ECParameterSpec.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/math/ec/ECCurve.h"
#include "org/spongycastle/math/ec/ECPoint.h"

@interface ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec () {
 @public
  NSString *name_;
}

@end

J2OBJC_FIELD_SETTER(ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec, name_, NSString *)

@implementation ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec

- (instancetype)initWithNSString:(NSString *)name
withOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
withOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)G
          withJavaMathBigInteger:(JavaMathBigInteger *)n {
  ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_(self, name, curve, G, n);
  return self;
}

- (instancetype)initWithNSString:(NSString *)name
withOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
withOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)G
          withJavaMathBigInteger:(JavaMathBigInteger *)n
          withJavaMathBigInteger:(JavaMathBigInteger *)h {
  ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(self, name, curve, G, n, h);
  return self;
}

- (instancetype)initWithNSString:(NSString *)name
withOrgSpongycastleMathEcECCurve:(OrgSpongycastleMathEcECCurve *)curve
withOrgSpongycastleMathEcECPoint:(OrgSpongycastleMathEcECPoint *)G
          withJavaMathBigInteger:(JavaMathBigInteger *)n
          withJavaMathBigInteger:(JavaMathBigInteger *)h
                   withByteArray:(IOSByteArray *)seed {
  ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_(self, name, curve, G, n, h, seed);
  return self;
}

- (NSString *)getName {
  return name_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 2, -1, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithNSString:withOrgSpongycastleMathEcECCurve:withOrgSpongycastleMathEcECPoint:withJavaMathBigInteger:);
  methods[1].selector = @selector(initWithNSString:withOrgSpongycastleMathEcECCurve:withOrgSpongycastleMathEcECPoint:withJavaMathBigInteger:withJavaMathBigInteger:);
  methods[2].selector = @selector(initWithNSString:withOrgSpongycastleMathEcECCurve:withOrgSpongycastleMathEcECPoint:withJavaMathBigInteger:withJavaMathBigInteger:withByteArray:);
  methods[3].selector = @selector(getName);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "name_", "LNSString;", .constantValue.asLong = 0, 0x2, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LNSString;LOrgSpongycastleMathEcECCurve;LOrgSpongycastleMathEcECPoint;LJavaMathBigInteger;", "LNSString;LOrgSpongycastleMathEcECCurve;LOrgSpongycastleMathEcECPoint;LJavaMathBigInteger;LJavaMathBigInteger;", "LNSString;LOrgSpongycastleMathEcECCurve;LOrgSpongycastleMathEcECPoint;LJavaMathBigInteger;LJavaMathBigInteger;[B" };
  static const J2ObjcClassInfo _ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec = { "ECNamedCurveParameterSpec", "com.youzh.lingtu.sign.crypto.utils", ptrTable, methods, fields, 7, 0x1, 4, 1, -1, -1, -1, -1, -1 };
  return &_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec;
}

@end

void ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_(ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec *self, NSString *name, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n) {
  ComYouzhLingtuSignCryptoUtilsECParameterSpec_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_(self, curve, G, n);
  self->name_ = name;
}

ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec *new_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_(NSString *name, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec, initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_, name, curve, G, n)
}

ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec *create_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_(NSString *name, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec, initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_, name, curve, G, n)
}

void ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec *self, NSString *name, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h) {
  ComYouzhLingtuSignCryptoUtilsECParameterSpec_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(self, curve, G, n, h);
  self->name_ = name;
}

ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec *new_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(NSString *name, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec, initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_, name, curve, G, n, h)
}

ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec *create_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_(NSString *name, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec, initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_, name, curve, G, n, h)
}

void ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_(ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec *self, NSString *name, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h, IOSByteArray *seed) {
  ComYouzhLingtuSignCryptoUtilsECParameterSpec_initWithOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_(self, curve, G, n, h, seed);
  self->name_ = name;
}

ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec *new_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_(NSString *name, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h, IOSByteArray *seed) {
  J2OBJC_NEW_IMPL(ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec, initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_, name, curve, G, n, h, seed)
}

ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec *create_ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec_initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_(NSString *name, OrgSpongycastleMathEcECCurve *curve, OrgSpongycastleMathEcECPoint *G, JavaMathBigInteger *n, JavaMathBigInteger *h, IOSByteArray *seed) {
  J2OBJC_CREATE_IMPL(ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec, initWithNSString_withOrgSpongycastleMathEcECCurve_withOrgSpongycastleMathEcECPoint_withJavaMathBigInteger_withJavaMathBigInteger_withByteArray_, name, curve, G, n, h, seed)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(ComYouzhLingtuSignCryptoUtilsECNamedCurveParameterSpec)
