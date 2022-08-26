//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/TlsNullCipher.java
//

#include "IOSPrimitiveArray.h"
#include "J2ObjC_source.h"
#include "java/lang/System.h"
#include "org/spongycastle/crypto/Digest.h"
#include "org/spongycastle/crypto/tls/AlertDescription.h"
#include "org/spongycastle/crypto/tls/TlsContext.h"
#include "org/spongycastle/crypto/tls/TlsFatalAlert.h"
#include "org/spongycastle/crypto/tls/TlsMac.h"
#include "org/spongycastle/crypto/tls/TlsNullCipher.h"
#include "org/spongycastle/crypto/tls/TlsUtils.h"
#include "org/spongycastle/util/Arrays.h"

@implementation OrgSpongycastleCryptoTlsTlsNullCipher

- (instancetype)initWithOrgSpongycastleCryptoTlsTlsContext:(id<OrgSpongycastleCryptoTlsTlsContext>)context {
  OrgSpongycastleCryptoTlsTlsNullCipher_initWithOrgSpongycastleCryptoTlsTlsContext_(self, context);
  return self;
}

- (instancetype)initWithOrgSpongycastleCryptoTlsTlsContext:(id<OrgSpongycastleCryptoTlsTlsContext>)context
                           withOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)clientWriteDigest
                           withOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)serverWriteDigest {
  OrgSpongycastleCryptoTlsTlsNullCipher_initWithOrgSpongycastleCryptoTlsTlsContext_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_(self, context, clientWriteDigest, serverWriteDigest);
  return self;
}

- (jint)getPlaintextLimitWithInt:(jint)ciphertextLimit {
  jint result = ciphertextLimit;
  if (writeMac_ != nil) {
    result -= [writeMac_ getSize];
  }
  return result;
}

- (IOSByteArray *)encodePlaintextWithLong:(jlong)seqNo
                                withShort:(jshort)type
                            withByteArray:(IOSByteArray *)plaintext
                                  withInt:(jint)offset
                                  withInt:(jint)len {
  if (writeMac_ == nil) {
    return OrgSpongycastleUtilArrays_copyOfRangeWithByteArray_withInt_withInt_(plaintext, offset, offset + len);
  }
  IOSByteArray *mac = [writeMac_ calculateMacWithLong:seqNo withShort:type withByteArray:plaintext withInt:offset withInt:len];
  IOSByteArray *ciphertext = [IOSByteArray newArrayWithLength:len + ((IOSByteArray *) nil_chk(mac))->size_];
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(plaintext, offset, ciphertext, 0, len);
  JavaLangSystem_arraycopyWithId_withInt_withId_withInt_withInt_(mac, 0, ciphertext, len, mac->size_);
  return ciphertext;
}

- (IOSByteArray *)decodeCiphertextWithLong:(jlong)seqNo
                                 withShort:(jshort)type
                             withByteArray:(IOSByteArray *)ciphertext
                                   withInt:(jint)offset
                                   withInt:(jint)len {
  if (readMac_ == nil) {
    return OrgSpongycastleUtilArrays_copyOfRangeWithByteArray_withInt_withInt_(ciphertext, offset, offset + len);
  }
  jint macSize = [readMac_ getSize];
  if (len < macSize) {
    @throw new_OrgSpongycastleCryptoTlsTlsFatalAlert_initWithShort_(OrgSpongycastleCryptoTlsAlertDescription_decode_error);
  }
  jint macInputLen = len - macSize;
  IOSByteArray *receivedMac = OrgSpongycastleUtilArrays_copyOfRangeWithByteArray_withInt_withInt_(ciphertext, offset + macInputLen, offset + len);
  IOSByteArray *computedMac = [((OrgSpongycastleCryptoTlsTlsMac *) nil_chk(readMac_)) calculateMacWithLong:seqNo withShort:type withByteArray:ciphertext withInt:offset withInt:macInputLen];
  if (!OrgSpongycastleUtilArrays_constantTimeAreEqualWithByteArray_withByteArray_(receivedMac, computedMac)) {
    @throw new_OrgSpongycastleCryptoTlsTlsFatalAlert_initWithShort_(OrgSpongycastleCryptoTlsAlertDescription_bad_record_mac);
  }
  return OrgSpongycastleUtilArrays_copyOfRangeWithByteArray_withInt_withInt_(ciphertext, offset, offset + macInputLen);
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, NULL, 0x1, -1, 1, 2, -1, -1, -1 },
    { NULL, "I", 0x1, 3, 4, -1, -1, -1, -1 },
    { NULL, "[B", 0x1, 5, 6, 2, -1, -1, -1 },
    { NULL, "[B", 0x1, 7, 6, 2, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithOrgSpongycastleCryptoTlsTlsContext:);
  methods[1].selector = @selector(initWithOrgSpongycastleCryptoTlsTlsContext:withOrgSpongycastleCryptoDigest:withOrgSpongycastleCryptoDigest:);
  methods[2].selector = @selector(getPlaintextLimitWithInt:);
  methods[3].selector = @selector(encodePlaintextWithLong:withShort:withByteArray:withInt:withInt:);
  methods[4].selector = @selector(decodeCiphertextWithLong:withShort:withByteArray:withInt:withInt:);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "context_", "LOrgSpongycastleCryptoTlsTlsContext;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "writeMac_", "LOrgSpongycastleCryptoTlsTlsMac;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
    { "readMac_", "LOrgSpongycastleCryptoTlsTlsMac;", .constantValue.asLong = 0, 0x4, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LOrgSpongycastleCryptoTlsTlsContext;", "LOrgSpongycastleCryptoTlsTlsContext;LOrgSpongycastleCryptoDigest;LOrgSpongycastleCryptoDigest;", "LJavaIoIOException;", "getPlaintextLimit", "I", "encodePlaintext", "JS[BII", "decodeCiphertext" };
  static const J2ObjcClassInfo _OrgSpongycastleCryptoTlsTlsNullCipher = { "TlsNullCipher", "org.spongycastle.crypto.tls", ptrTable, methods, fields, 7, 0x1, 5, 3, -1, -1, -1, -1, -1 };
  return &_OrgSpongycastleCryptoTlsTlsNullCipher;
}

@end

void OrgSpongycastleCryptoTlsTlsNullCipher_initWithOrgSpongycastleCryptoTlsTlsContext_(OrgSpongycastleCryptoTlsTlsNullCipher *self, id<OrgSpongycastleCryptoTlsTlsContext> context) {
  NSObject_init(self);
  self->context_ = context;
  self->writeMac_ = nil;
  self->readMac_ = nil;
}

OrgSpongycastleCryptoTlsTlsNullCipher *new_OrgSpongycastleCryptoTlsTlsNullCipher_initWithOrgSpongycastleCryptoTlsTlsContext_(id<OrgSpongycastleCryptoTlsTlsContext> context) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoTlsTlsNullCipher, initWithOrgSpongycastleCryptoTlsTlsContext_, context)
}

OrgSpongycastleCryptoTlsTlsNullCipher *create_OrgSpongycastleCryptoTlsTlsNullCipher_initWithOrgSpongycastleCryptoTlsTlsContext_(id<OrgSpongycastleCryptoTlsTlsContext> context) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoTlsTlsNullCipher, initWithOrgSpongycastleCryptoTlsTlsContext_, context)
}

void OrgSpongycastleCryptoTlsTlsNullCipher_initWithOrgSpongycastleCryptoTlsTlsContext_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_(OrgSpongycastleCryptoTlsTlsNullCipher *self, id<OrgSpongycastleCryptoTlsTlsContext> context, id<OrgSpongycastleCryptoDigest> clientWriteDigest, id<OrgSpongycastleCryptoDigest> serverWriteDigest) {
  NSObject_init(self);
  if ((clientWriteDigest == nil) != (serverWriteDigest == nil)) {
    @throw new_OrgSpongycastleCryptoTlsTlsFatalAlert_initWithShort_(OrgSpongycastleCryptoTlsAlertDescription_internal_error);
  }
  self->context_ = context;
  OrgSpongycastleCryptoTlsTlsMac *clientWriteMac = nil;
  OrgSpongycastleCryptoTlsTlsMac *serverWriteMac = nil;
  if (clientWriteDigest != nil) {
    jint key_block_size = [clientWriteDigest getDigestSize] + [((id<OrgSpongycastleCryptoDigest>) nil_chk(serverWriteDigest)) getDigestSize];
    IOSByteArray *key_block = OrgSpongycastleCryptoTlsTlsUtils_calculateKeyBlockWithOrgSpongycastleCryptoTlsTlsContext_withInt_(context, key_block_size);
    jint offset = 0;
    clientWriteMac = new_OrgSpongycastleCryptoTlsTlsMac_initWithOrgSpongycastleCryptoTlsTlsContext_withOrgSpongycastleCryptoDigest_withByteArray_withInt_withInt_(context, clientWriteDigest, key_block, offset, [clientWriteDigest getDigestSize]);
    offset += [clientWriteDigest getDigestSize];
    serverWriteMac = new_OrgSpongycastleCryptoTlsTlsMac_initWithOrgSpongycastleCryptoTlsTlsContext_withOrgSpongycastleCryptoDigest_withByteArray_withInt_withInt_(context, serverWriteDigest, key_block, offset, [serverWriteDigest getDigestSize]);
    offset += [serverWriteDigest getDigestSize];
    if (offset != key_block_size) {
      @throw new_OrgSpongycastleCryptoTlsTlsFatalAlert_initWithShort_(OrgSpongycastleCryptoTlsAlertDescription_internal_error);
    }
  }
  if ([((id<OrgSpongycastleCryptoTlsTlsContext>) nil_chk(context)) isServer]) {
    self->writeMac_ = serverWriteMac;
    self->readMac_ = clientWriteMac;
  }
  else {
    self->writeMac_ = clientWriteMac;
    self->readMac_ = serverWriteMac;
  }
}

OrgSpongycastleCryptoTlsTlsNullCipher *new_OrgSpongycastleCryptoTlsTlsNullCipher_initWithOrgSpongycastleCryptoTlsTlsContext_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoTlsTlsContext> context, id<OrgSpongycastleCryptoDigest> clientWriteDigest, id<OrgSpongycastleCryptoDigest> serverWriteDigest) {
  J2OBJC_NEW_IMPL(OrgSpongycastleCryptoTlsTlsNullCipher, initWithOrgSpongycastleCryptoTlsTlsContext_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_, context, clientWriteDigest, serverWriteDigest)
}

OrgSpongycastleCryptoTlsTlsNullCipher *create_OrgSpongycastleCryptoTlsTlsNullCipher_initWithOrgSpongycastleCryptoTlsTlsContext_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoTlsTlsContext> context, id<OrgSpongycastleCryptoDigest> clientWriteDigest, id<OrgSpongycastleCryptoDigest> serverWriteDigest) {
  J2OBJC_CREATE_IMPL(OrgSpongycastleCryptoTlsTlsNullCipher, initWithOrgSpongycastleCryptoTlsTlsContext_withOrgSpongycastleCryptoDigest_withOrgSpongycastleCryptoDigest_, context, clientWriteDigest, serverWriteDigest)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(OrgSpongycastleCryptoTlsTlsNullCipher)
