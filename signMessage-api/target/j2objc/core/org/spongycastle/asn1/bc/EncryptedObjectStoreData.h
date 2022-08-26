//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/asn1/bc/EncryptedObjectStoreData.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleAsn1BcEncryptedObjectStoreData")
#ifdef RESTRICT_OrgSpongycastleAsn1BcEncryptedObjectStoreData
#define INCLUDE_ALL_OrgSpongycastleAsn1BcEncryptedObjectStoreData 0
#else
#define INCLUDE_ALL_OrgSpongycastleAsn1BcEncryptedObjectStoreData 1
#endif
#undef RESTRICT_OrgSpongycastleAsn1BcEncryptedObjectStoreData

#if !defined (OrgSpongycastleAsn1BcEncryptedObjectStoreData_) && (INCLUDE_ALL_OrgSpongycastleAsn1BcEncryptedObjectStoreData || defined(INCLUDE_OrgSpongycastleAsn1BcEncryptedObjectStoreData))
#define OrgSpongycastleAsn1BcEncryptedObjectStoreData_

#define RESTRICT_OrgSpongycastleAsn1ASN1Object 1
#define INCLUDE_OrgSpongycastleAsn1ASN1Object 1
#include "org/spongycastle/asn1/ASN1Object.h"

@class IOSByteArray;
@class OrgSpongycastleAsn1ASN1OctetString;
@class OrgSpongycastleAsn1ASN1Primitive;
@class OrgSpongycastleAsn1X509AlgorithmIdentifier;

@interface OrgSpongycastleAsn1BcEncryptedObjectStoreData : OrgSpongycastleAsn1ASN1Object

#pragma mark Public

- (instancetype)initWithOrgSpongycastleAsn1X509AlgorithmIdentifier:(OrgSpongycastleAsn1X509AlgorithmIdentifier *)encryptionAlgorithm
                                                     withByteArray:(IOSByteArray *)encryptedContent;

- (OrgSpongycastleAsn1ASN1OctetString *)getEncryptedContent;

- (OrgSpongycastleAsn1X509AlgorithmIdentifier *)getEncryptionAlgorithm;

+ (OrgSpongycastleAsn1BcEncryptedObjectStoreData *)getInstanceWithId:(id)o;

- (OrgSpongycastleAsn1ASN1Primitive *)toASN1Primitive;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleAsn1BcEncryptedObjectStoreData)

FOUNDATION_EXPORT void OrgSpongycastleAsn1BcEncryptedObjectStoreData_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_(OrgSpongycastleAsn1BcEncryptedObjectStoreData *self, OrgSpongycastleAsn1X509AlgorithmIdentifier *encryptionAlgorithm, IOSByteArray *encryptedContent);

FOUNDATION_EXPORT OrgSpongycastleAsn1BcEncryptedObjectStoreData *new_OrgSpongycastleAsn1BcEncryptedObjectStoreData_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_(OrgSpongycastleAsn1X509AlgorithmIdentifier *encryptionAlgorithm, IOSByteArray *encryptedContent) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleAsn1BcEncryptedObjectStoreData *create_OrgSpongycastleAsn1BcEncryptedObjectStoreData_initWithOrgSpongycastleAsn1X509AlgorithmIdentifier_withByteArray_(OrgSpongycastleAsn1X509AlgorithmIdentifier *encryptionAlgorithm, IOSByteArray *encryptedContent);

FOUNDATION_EXPORT OrgSpongycastleAsn1BcEncryptedObjectStoreData *OrgSpongycastleAsn1BcEncryptedObjectStoreData_getInstanceWithId_(id o);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleAsn1BcEncryptedObjectStoreData)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleAsn1BcEncryptedObjectStoreData")
