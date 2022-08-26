//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/paddings/ISO7816d4Padding.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/security/SecureRandom.h"
#include "org/spongycastle/crypto/InvalidCipherTextException.h"
#include "org/spongycastle/crypto/paddings/ISO7816d4Padding.h"

@implementation OrgSpongycastleCryptoPaddingsISO7816d4Padding

J2OBJC_IGNORE_DESIGNATED_BEGIN
- (instancetype)init {
  OrgSpongycastleCryptoPaddingsISO7816d4Padding_init(self);
  return self;
}
J2OBJC_IGNORE_DESIGNATED_END

- (void)init__WithJavaSecuritySecureRandom:(JavaSecuritySecureRandom *)random {
}

- (NSString *)getPaddingName {
  return @"ISO7816-4";
}

- (jint)addPaddingWithByteArray:(IOSByteArray *)inArg
                        withInt:(jint)inOff {
  jint added = (((IOSByteArray *) nil_chk(inArg))->size_ - inOff);
  *IOSByteArray_GetRef(inArg, inOff) = (jbyte) (jint) 0x80;
  inOff++;
  while (inOff < inArg->size_) {
    *IOSByteArray_GetRef(inArg, inOff) = (jbyte) 0;
    inOff++;
  }
  return added;
}

- (jint)padCountWithByteArray:(IOSByteArray *)inArg {
  jint count = ((IOSByteArray *) nil_chk(inArg))->size_ - 1;
  while (count > 0 && IOSByteArray_Get(inArg, count) == 0) {
    count--;
  }
  if (IOSByteArray_Get(inArg, count) != (jbyte) (jint) 0x80) {
    @throw new_OrgSpongycastleCryptoInvalidCipherTextException_initWithNSString_(@"pad block corrupted");
  }
  return inArg->size_ - count;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "V", 0x1, 0, 1, 2, -1, -1, -1 },
    { NULL, "LNSString;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 5, 6, 7, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(init);
  methods[1].selector = @selector(init__WithJavaSecuritySecureRandom:);
  methods[2].selector = @selector(getPaddingName);
  methods[3].selector = @selector(addPaddingWithByteArray:withInt:);
  methods[4].selector = @selector(padCountWithByteArray:);
  #pragma clang diagnostic pop
  static const void *ptrTable[] = { "init", "LJavaSecuritySecureRandom;", "LJavaLangIllegalArgumentException;", "addPadding", "[BI", "padCount", "[B", "LOrgSpongycastleCryptoInvalidCipherTextException;" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoPaddingsISO7816d4Padding = { "ISO7816d4Padding", "org.spongycastle.crypto.paddings", ptrTable, methods, NULL, 7, 0x1, 5, 0, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoPaddingsISO7816d4Padding;
}

@end

void OrgSpongycastleCryptoPaddingsISO7816d4Padding_init(OrgSpongycastleCryptoPaddingsISO7816d4Padding *self) {
  NSObject_init(self);
}

OrgSpongycastleCryptoPaddingsISO7816d4Padding *new_OrgSpongycastleCryptoPaddingsISO7816d4Padding_init() {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoPaddingsISO7816d4Padding, init)
}

OrgSpongycastleCryptoPaddingsISO7816d4Padding *create_OrgSpongycastleCryptoPaddingsISO7816d4Padding_init() {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoPaddingsISO7816d4Padding, init)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoPaddingsISO7816d4Padding)
