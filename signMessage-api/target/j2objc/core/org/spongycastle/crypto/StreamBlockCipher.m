//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/StreamBlockCipher.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "org/spongycastle/crypto/BlockCipher.h"
#include "org/spongycastle/crypto/DataLengthException.h"
#include "org/spongycastle/crypto/OutputLengthException.h"
#include "org/spongycastle/crypto/StreamBlockCipher.h"

#pragma clang diagnostic ignored "-Wprotocol"

@interface OrgSpongycastleCryptoStreamBlockCipher () {
 @public
  id<OrgSpongycastleCryptoBlockCipher> cipher_;
}

@end

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoStreamBlockCipher, cipher_, id<OrgSpongycastleCryptoBlockCipher>)

@implementation OrgSpongycastleCryptoStreamBlockCipher

- (instancetype)initWithOrgSpongycastleCryptoBlockCipher:(id<OrgSpongycastleCryptoBlockCipher>)cipher {
  OrgSpongycastleCryptoStreamBlockCipher_initWithOrgSpongycastleCryptoBlockCipher_(self, cipher);
  return self;
}

- (id<OrgSpongycastleCryptoBlockCipher>)getUnderlyingCipher {
  return cipher_;
}

- (jbyte)returnByteWithByte:(jbyte)inArg {
  return [self calculateByteWithByte:inArg];
}

- (jint)processBytesWithByteArray:(IOSByteArray *)inArg
                          withInt:(jint)inOff
                          withInt:(jint)len
                    withByteArray:(IOSByteArray *)outArg
                          withInt:(jint)outOff {
  if (inOff + len > ((IOSByteArray *) nil_chk(inArg))->size_) {
    @throw new_OrgSpongycastleCryptoDataLengthException_initWithNSString_(@"input buffer too small");
  }
  if (outOff + len > ((IOSByteArray *) nil_chk(outArg))->size_) {
    @throw new_OrgSpongycastleCryptoOutputLengthException_initWithNSString_(@"output buffer too short");
  }
  jint inStart = inOff;
  jint inEnd = inOff + len;
  jint outStart = outOff;
  while (inStart < inEnd) {
    *IOSByteArray_GetRef(outArg, outStart++) = [self calculateByteWithByte:IOSByteArray_Get(inArg, inStart++)];
  }
  return len;
}

- (jbyte)calculateByteWithByte:(jbyte)b {
  // can't call an abstract method
  [self doesNotRecognizeSelector:_cmd];
  return 0;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x4, -1, 0, -1, -1, -1, -1 },
    { NULL, "LOrgSpongycastleCryptoBlockCipher;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "B", 0x11, 1, 2, -1, -1, -1, -1 },
    { NULL, "I", 0x1, 3, 4, 5, -1, -1, -1 },
    { NULL, "B", 0x404, 6, 2, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoBlockCipher:);
  methods[1].selector = @selector(getUnderlyingCipher);
  methods[2].selector = @selector(returnByteWithByte:);
  methods[3].selector = @selector(processBytesWithByteArray:withInt:withInt:withByteArray:withInt:);
  methods[4].selector = @selector(calculateByteWithByte:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "cipher_", "LOrgSpongycastleCryptoBlockCipher;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoBlockCipher;", "returnByte", "B", "processBytes", "[BII[BI", "LOrgSpongycastleCryptoDataLengthException;", "calculateByte" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoStreamBlockCipher = { "StreamBlockCipher", "org.spongycastle.crypto", ptrTable, methods, fields, 7, 0x401, 5, 1, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoStreamBlockCipher;
}

@end

void OrgSpongycastleCryptoStreamBlockCipher_initWithOrgSpongycastleCryptoBlockCipher_(OrgSpongycastleCryptoStreamBlockCipher *self, id<OrgSpongycastleCryptoBlockCipher> cipher) {
  NSObject_init(self);
  self->cipher_ = cipher;
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoStreamBlockCipher)
