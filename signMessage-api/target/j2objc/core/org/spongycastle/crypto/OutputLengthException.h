//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/OutputLengthException.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoOutputLengthException")
#ifdef RESTRICT_OrgSpongycastleCryptoOutputLengthException
#define INCLUDE_ALL_OrgSpongycastleCryptoOutputLengthException 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoOutputLengthException 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoOutputLengthException

#if !defined (OrgSpongycastleCryptoOutputLengthException_) && (INCLUDE_ALL_OrgSpongycastleCryptoOutputLengthException || defined(INCLUDE_OrgSpongycastleCryptoOutputLengthException))
#define OrgSpongycastleCryptoOutputLengthException_

#define RESTRICT_OrgSpongycastleCryptoDataLengthException 1
#define INCLUDE_OrgSpongycastleCryptoDataLengthException 1
#include "org/spongycastle/crypto/DataLengthException.h"

@interface OrgSpongycastleCryptoOutputLengthException : OrgSpongycastleCryptoDataLengthException

#pragma mark Public

- (instancetype)initWithNSString:(NSString *)msg;

// Disallowed inherited constructors, do not use.

- (instancetype)init NS_UNAVAILABLE;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleCryptoOutputLengthException)

FOUNDATION_EXPORT void OrgSpongycastleCryptoOutputLengthException_initWithNSString_(OrgSpongycastleCryptoOutputLengthException *self, NSString *msg);

FOUNDATION_EXPORT OrgSpongycastleCryptoOutputLengthException *new_OrgSpongycastleCryptoOutputLengthException_initWithNSString_(NSString *msg) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoOutputLengthException *create_OrgSpongycastleCryptoOutputLengthException_initWithNSString_(NSString *msg);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoOutputLengthException)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoOutputLengthException")
