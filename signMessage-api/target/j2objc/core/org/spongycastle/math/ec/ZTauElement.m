//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/ec/ZTauElement.java
//

#include "J2ObjC_source.h"
#include "java/math/BigInteger.h"
#include "org/spongycastle/math/ec/ZTauElement.h"

@implementation OrgSpongycastleMathEcZTauElement

- (instancetype)initWithJavaMathBigInteger:(JavaMathBigInteger *)u
                    withJavaMathBigInteger:(JavaMathBigInteger *)v {
  OrgSpongycastleMathEcZTauElement_initWithJavaMathBigInteger_withJavaMathBigInteger_(self, u, v);
  return self;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaMathBigInteger:withJavaMathBigInteger:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "u_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x11, -1, -1, -1, -1 },
    { "v_", "LJavaMathBigInteger;", .constantValue.asLong = 0, 0x11, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaMathBigInteger;LJavaMathBigInteger;" };
  static const J2ObjcClassInfo _OrgSpongycastleMathEcZTauElement = { "ZTauElement", "org.spongycastle.math.ec", ptrTable, methods, fields, 7, 0x0, 1, 2, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleMathEcZTauElement;
}

@end

void OrgSpongycastleMathEcZTauElement_initWithJavaMathBigInteger_withJavaMathBigInteger_(OrgSpongycastleMathEcZTauElement *self, JavaMathBigInteger *u, JavaMathBigInteger *v) {
  NSObject_init(self);
  self->u_ = u;
  self->v_ = v;
}

OrgSpongycastleMathEcZTauElement *new_OrgSpongycastleMathEcZTauElement_initWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *u, JavaMathBigInteger *v) {
  J2OBJC_NEW_IMPL(OrgSpongycastleMathEcZTauElement, initWithJavaMathBigInteger_withJavaMathBigInteger_, u, v)
}

OrgSpongycastleMathEcZTauElement *create_OrgSpongycastleMathEcZTauElement_initWithJavaMathBigInteger_withJavaMathBigInteger_(JavaMathBigInteger *u, JavaMathBigInteger *v) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleMathEcZTauElement, initWithJavaMathBigInteger_withJavaMathBigInteger_, u, v)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleMathEcZTauElement)
