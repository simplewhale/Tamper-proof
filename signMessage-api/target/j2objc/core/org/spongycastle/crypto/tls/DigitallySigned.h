//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/DigitallySigned.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsDigitallySigned")
#ifdef RESTRICT_OrgSpongycastleCryptoTlsDigitallySigned
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsDigitallySigned 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsDigitallySigned 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoTlsDigitallySigned

#if !defined (OrgSpongycastleCryptoTlsDigitallySigned_) && (INCLUDE_ALL_OrgSpongycastleCryptoTlsDigitallySigned || defined(INCLUDE_OrgSpongycastleCryptoTlsDigitallySigned))
#define OrgSpongycastleCryptoTlsDigitallySigned_

@class IOSByteArray;
@class JavaIoInputStream;
@class JavaIoOutputStream;
@class OrgSpongycastleCryptoTlsSignatureAndHashAlgorithm;
@protocol OrgSpongycastleCryptoTlsTlsContext;

@interface OrgSpongycastleCryptoTlsDigitallySigned : NSObject {
 @public
  OrgSpongycastleCryptoTlsSignatureAndHashAlgorithm *algorithm_;
  IOSByteArray *signature_;
}

#pragma mark Public

- (instancetype)initWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm:(OrgSpongycastleCryptoTlsSignatureAndHashAlgorithm *)algorithm
                                                            withByteArray:(IOSByteArray *)signature;

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)output;

- (OrgSpongycastleCryptoTlsSignatureAndHashAlgorithm *)getAlgorithm;

- (IOSByteArray *)getSignature;

+ (OrgSpongycastleCryptoTlsDigitallySigned *)parseWithOrgSpongycastleCryptoTlsTlsContext:(id<OrgSpongycastleCryptoTlsTlsContext>)context
                                                                   withJavaIoInputStream:(JavaIoInputStream *)input;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoTlsDigitallySigned)

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsDigitallySigned, algorithm_, OrgSpongycastleCryptoTlsSignatureAndHashAlgorithm *)
J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsDigitallySigned, signature_, IOSByteArray *)

FOUNDATION_EXPORT void OrgSpongycastleCryptoTlsDigitallySigned_initWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm_withByteArray_(OrgSpongycastleCryptoTlsDigitallySigned *self, OrgSpongycastleCryptoTlsSignatureAndHashAlgorithm *algorithm, IOSByteArray *signature);

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsDigitallySigned *new_OrgSpongycastleCryptoTlsDigitallySigned_initWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm_withByteArray_(OrgSpongycastleCryptoTlsSignatureAndHashAlgorithm *algorithm, IOSByteArray *signature) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsDigitallySigned *create_OrgSpongycastleCryptoTlsDigitallySigned_initWithOrgSpongycastleCryptoTlsSignatureAndHashAlgorithm_withByteArray_(OrgSpongycastleCryptoTlsSignatureAndHashAlgorithm *algorithm, IOSByteArray *signature);

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsDigitallySigned *OrgSpongycastleCryptoTlsDigitallySigned_parseWithOrgSpongycastleCryptoTlsTlsContext_withJavaIoInputStream_(id<OrgSpongycastleCryptoTlsTlsContext> context, JavaIoInputStream *input);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoTlsDigitallySigned)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsDigitallySigned")
