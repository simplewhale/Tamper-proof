//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/Chacha20Poly1305.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsChacha20Poly1305")
#ifdef RESTRICT_OrgSpongycastleCryptoTlsChacha20Poly1305
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsChacha20Poly1305 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsChacha20Poly1305 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoTlsChacha20Poly1305

#if !defined (OrgSpongycastleCryptoTlsChacha20Poly1305_) && (INCLUDE_ALL_OrgSpongycastleCryptoTlsChacha20Poly1305 || defined(INCLUDE_OrgSpongycastleCryptoTlsChacha20Poly1305))
#define OrgSpongycastleCryptoTlsChacha20Poly1305_

#define RESTRICT_OrgSpongycastleCryptoTlsTlsCipher 1
#define INCLUDE_OrgSpongycastleCryptoTlsTlsCipher 1
#include "org/spongycastle/crypto/tls/TlsCipher.h"

@class IOSByteArray;
@class OrgSpongycastleCryptoEnginesChaCha7539Engine;
@class OrgSpongycastleCryptoParamsKeyParameter;
@protocol OrgSpongycastleCryptoMac;
@protocol OrgSpongycastleCryptoStreamCipher;
@protocol OrgSpongycastleCryptoTlsTlsContext;

@interface OrgSpongycastleCryptoTlsChacha20Poly1305 : NSObject < OrgSpongycastleCryptoTlsTlsCipher > {
 @public
  id<OrgSpongycastleCryptoTlsTlsContext> context_;
  OrgSpongycastleCryptoEnginesChaCha7539Engine *encryptCipher_;
  OrgSpongycastleCryptoEnginesChaCha7539Engine *decryptCipher_;
  IOSByteArray *encryptIV_;
  IOSByteArray *decryptIV_;
}

#pragma mark Public

- (instancetype)initWithOrgSpongycastleCryptoTlsTlsContext:(id<OrgSpongycastleCryptoTlsTlsContext>)context;

- (IOSByteArray *)decodeCiphertextWithLong:(jlong)seqNo
                                 withShort:(jshort)type
                             withByteArray:(IOSByteArray *)ciphertext
                                   withInt:(jint)offset
                                   withInt:(jint)len;

- (IOSByteArray *)encodePlaintextWithLong:(jlong)seqNo
                                withShort:(jshort)type
                            withByteArray:(IOSByteArray *)plaintext
                                  withInt:(jint)offset
                                  withInt:(jint)len;

- (jint)getPlaintextLimitWithInt:(jint)ciphertextLimit;

#pragma mark Protected

- (IOSByteArray *)calculateNonceWithLong:(jlong)seqNo
                           withByteArray:(IOSByteArray *)iv;

- (IOSByteArray *)calculateRecordMACWithOrgSpongycastleCryptoParamsKeyParameter:(OrgSpongycastleCryptoParamsKeyParameter *)macKey
                                                                  withByteArray:(IOSByteArray *)additionalData
                                                                  withByteArray:(IOSByteArray *)buf
                                                                        withInt:(jint)off
                                                                        withInt:(jint)len;

- (OrgSpongycastleCryptoParamsKeyParameter *)generateRecordMACKeyWithOrgSpongycastleCryptoStreamCipher:(id<OrgSpongycastleCryptoStreamCipher>)cipher;

- (IOSByteArray *)getAdditionalDataWithLong:(jlong)seqNo
                                  withShort:(jshort)type
                                    withInt:(jint)len;

- (OrgSpongycastleCryptoParamsKeyParameter *)initRecordWithOrgSpongycastleCryptoStreamCipher:(id<OrgSpongycastleCryptoStreamCipher>)cipher
                                                                                 withBoolean:(jboolean)forEncryption
                                                                                    withLong:(jlong)seqNo
                                                                               withByteArray:(IOSByteArray *)iv OBJC_METHOD_FAMILY_NONE;

- (void)updateRecordMACLengthWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)mac
                                                  withInt:(jint)len;

- (void)updateRecordMACTextWithOrgSpongycastleCryptoMac:(id<OrgSpongycastleCryptoMac>)mac
                                          withByteArray:(IOSByteArray *)buf
                                                withInt:(jint)off
                                                withInt:(jint)len;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleCryptoTlsChacha20Poly1305)

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsChacha20Poly1305, context_, id<OrgSpongycastleCryptoTlsTlsContext>)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsChacha20Poly1305, encryptCipher_, OrgSpongycastleCryptoEnginesChaCha7539Engine *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsChacha20Poly1305, decryptCipher_, OrgSpongycastleCryptoEnginesChaCha7539Engine *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsChacha20Poly1305, encryptIV_, IOSByteArray *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsChacha20Poly1305, decryptIV_, IOSByteArray *)

FOUNDATION_EXPORT void OrgSpongycastleCryptoTlsChacha20Poly1305_initWithOrgSpongycastleCryptoTlsTlsContext_(OrgSpongycastleCryptoTlsChacha20Poly1305 *self, id<OrgSpongycastleCryptoTlsTlsContext> context);

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsChacha20Poly1305 *new_OrgSpongycastleCryptoTlsChacha20Poly1305_initWithOrgSpongycastleCryptoTlsTlsContext_(id<OrgSpongycastleCryptoTlsTlsContext> context) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsChacha20Poly1305 *create_OrgSpongycastleCryptoTlsChacha20Poly1305_initWithOrgSpongycastleCryptoTlsTlsContext_(id<OrgSpongycastleCryptoTlsTlsContext> context);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoTlsChacha20Poly1305)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsChacha20Poly1305")