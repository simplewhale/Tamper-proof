//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/tls/Certificate.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsCertificate")
#ifdef RESTRICT_OrgSpongycastleCryptoTlsCertificate
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsCertificate 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoTlsCertificate 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoTlsCertificate

#if !defined (OrgSpongycastleCryptoTlsCertificate_) && (INCLUDE_ALL_OrgSpongycastleCryptoTlsCertificate || defined(INCLUDE_OrgSpongycastleCryptoTlsCertificate))
#define OrgSpongycastleCryptoTlsCertificate_

@class IOSObjectArray;
@class JavaIoInputStream;
@class JavaIoOutputStream;
@class OrgSpongycastleAsn1X509Certificate;

@interface OrgSpongycastleCryptoTlsCertificate : NSObject {
 @public
  IOSObjectArray *certificateList_;
}

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1X509CertificateArray:(IOSObjectArray *)certificateList;

- (void)encodeWithJavaIoOutputStream:(JavaIoOutputStream *)output;

- (OrgSpongycastleAsn1X509Certificate *)getCertificateAtWithInt:(jint)index;

- (IOSObjectArray *)getCertificateList;

- (jint)getLength;

- (jboolean)isEmpty;

+ (OrgSpongycastleCryptoTlsCertificate *)parseWithJavaIoInputStream:(JavaIoInputStream *)input;

#pragma mark Protected

- (IOSObjectArray *)cloneCertificateList;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleCryptoTlsCertificate)

J2OBJC_FIELD_SETTER(OrgSpongycastleCryptoTlsCertificate, certificateList_, IOSObjectArray *)

inline OrgSpongycastleCryptoTlsCertificate *OrgSpongycastleCryptoTlsCertificate_get_EMPTY_CHAIN(void);
/*! INTERNAL ONLY - Use accessor function from above. */
FOUNDATION_EXPORT OrgSpongycastleCryptoTlsCertificate *OrgSpongycastleCryptoTlsCertificate_EMPTY_CHAIN;
J2OBJC_STATIC_FIELD_OBJ_FINAL(OrgSpongycastleCryptoTlsCertificate, EMPTY_CHAIN, OrgSpongycastleCryptoTlsCertificate *)

FOUNDATION_EXPORT void OrgSpongycastleCryptoTlsCertificate_initWithOrgSpongycastleAsn1X509CertificateArray_(OrgSpongycastleCryptoTlsCertificate *self, IOSObjectArray *certificateList);

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsCertificate *new_OrgSpongycastleCryptoTlsCertificate_initWithOrgSpongycastleAsn1X509CertificateArray_(IOSObjectArray *certificateList) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsCertificate *create_OrgSpongycastleCryptoTlsCertificate_initWithOrgSpongycastleAsn1X509CertificateArray_(IOSObjectArray *certificateList);

FOUNDATION_EXPORT OrgSpongycastleCryptoTlsCertificate *OrgSpongycastleCryptoTlsCertificate_parseWithJavaIoInputStream_(JavaIoInputStream *input);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoTlsCertificate)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoTlsCertificate")
