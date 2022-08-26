//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/xmss/XMSSMTSignature.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSMTSignature")
#ifdef RESTRICT_OrgSpongycastlePqcCryptoXmssXMSSMTSignature
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSMTSignature 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSMTSignature 1
#endif
#undef RESTRICT_OrgSpongycastlePqcCryptoXmssXMSSMTSignature

#if !defined (OrgSpongycastlePqcCryptoXmssXMSSMTSignature_) && (INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSMTSignature || defined(INCLUDE_OrgSpongycastlePqcCryptoXmssXMSSMTSignature))
#define OrgSpongycastlePqcCryptoXmssXMSSMTSignature_

#define RESTRICT_OrgSpongycastlePqcCryptoXmssXMSSStoreableObjectInterface 1
#define INCLUDE_OrgSpongycastlePqcCryptoXmssXMSSStoreableObjectInterface 1
#include "org/spongycastle/pqc/crypto/xmss/XMSSStoreableObjectInterface.h"

@class IOSByteArray;
@protocol JavaUtilList;

@interface OrgSpongycastlePqcCryptoXmssXMSSMTSignature : NSObject < OrgSpongycastlePqcCryptoXmssXMSSStoreableObjectInterface >

#pragma mark Public

- (jlong)getIndex;

- (IOSByteArray *)getRandom;

- (id<JavaUtilList>)getReducedSignatures;

- (IOSByteArray *)toByteArray;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcCryptoXmssXMSSMTSignature)

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcCryptoXmssXMSSMTSignature)

#endif

#if !defined (OrgSpongycastlePqcCryptoXmssXMSSMTSignature_Builder_) && (INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSMTSignature || defined(INCLUDE_OrgSpongycastlePqcCryptoXmssXMSSMTSignature_Builder))
#define OrgSpongycastlePqcCryptoXmssXMSSMTSignature_Builder_

@class IOSByteArray;
@class OrgSpongycastlePqcCryptoXmssXMSSMTParameters;
@class OrgSpongycastlePqcCryptoXmssXMSSMTSignature;
@protocol JavaUtilList;

@interface OrgSpongycastlePqcCryptoXmssXMSSMTSignature_Builder : NSObject

#pragma mark Public

- (instancetype)initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters:(OrgSpongycastlePqcCryptoXmssXMSSMTParameters *)params;

- (OrgSpongycastlePqcCryptoXmssXMSSMTSignature *)build;

- (OrgSpongycastlePqcCryptoXmssXMSSMTSignature_Builder *)withIndexWithLong:(jlong)val;

- (OrgSpongycastlePqcCryptoXmssXMSSMTSignature_Builder *)withRandomWithByteArray:(IOSByteArray *)val;

- (OrgSpongycastlePqcCryptoXmssXMSSMTSignature_Builder *)withReducedSignaturesWithJavaUtilList:(id<JavaUtilList>)val;

- (OrgSpongycastlePqcCryptoXmssXMSSMTSignature_Builder *)withSignatureWithByteArray:(IOSByteArray *)val;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcCryptoXmssXMSSMTSignature_Builder)

FOUNDATION_EXPORT void OrgSpongycastlePqcCryptoXmssXMSSMTSignature_Builder_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_(OrgSpongycastlePqcCryptoXmssXMSSMTSignature_Builder *self, OrgSpongycastlePqcCryptoXmssXMSSMTParameters *params);

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoXmssXMSSMTSignature_Builder *new_OrgSpongycastlePqcCryptoXmssXMSSMTSignature_Builder_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_(OrgSpongycastlePqcCryptoXmssXMSSMTParameters *params) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoXmssXMSSMTSignature_Builder *create_OrgSpongycastlePqcCryptoXmssXMSSMTSignature_Builder_initWithOrgSpongycastlePqcCryptoXmssXMSSMTParameters_(OrgSpongycastlePqcCryptoXmssXMSSMTParameters *params);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcCryptoXmssXMSSMTSignature_Builder)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoXmssXMSSMTSignature")
