//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/math/field/FiniteField.java
//

#include "J2ObjC_source.h"
#include "org/spongycastle/math/field/FiniteField.h"

@interface OrgSpongycastleMathFieldFiniteField : NSObject

@end

@implementation OrgSpongycastleMathFieldFiniteField

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, "LJavaMathBigInteger;", 0x401, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x401, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(getCharacteristic);
  methods[1].selector = @selector(getDimension);
  #pragma clang diagnostic pop
  static const J2ObjcClassInfo _OrgSpongycastleMathFieldFiniteField = { "FiniteField", "org.spongycastle.math.field", NULL, methods, NULL, 7, 0x609, 2, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleMathFieldFiniteField;
}

@end

J2OBJC_INTERFACE_TYPE_LITERAL_SOURCE(OrgSpongycastleMathFieldFiniteField)
