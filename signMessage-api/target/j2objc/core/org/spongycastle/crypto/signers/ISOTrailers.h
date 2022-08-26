//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/crypto/signers/ISOTrailers.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleCryptoSignersISOTrailers")
#ifdef RESTRICT_OrgSpongycastleCryptoSignersISOTrailers
#define INCLUDE_ALL_OrgSpongycastleCryptoSignersISOTrailers 0
#else
#define INCLUDE_ALL_OrgSpongycastleCryptoSignersISOTrailers 1
#endif
#undef RESTRICT_OrgSpongycastleCryptoSignersISOTrailers

#if !defined (OrgSpongycastleCryptoSignersISOTrailers_) && (INCLUDE_ALL_OrgSpongycastleCryptoSignersISOTrailers || defined(INCLUDE_OrgSpongycastleCryptoSignersISOTrailers))
#define OrgSpongycastleCryptoSignersISOTrailers_

@class JavaLangInteger;
@protocol OrgSpongycastleCryptoDigest;

@interface OrgSpongycastleCryptoSignersISOTrailers : NSObject

#pragma mark Public

- (instancetype)init;

+ (JavaLangInteger *)getTrailerWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest;

+ (jboolean)noTrailerAvailableWithOrgSpongycastleCryptoDigest:(id<OrgSpongycastleCryptoDigest>)digest;

@end

J2OBJC_STATIC_INIT(OrgSpongycastleCryptoSignersISOTrailers)

inline jint OrgSpongycastleCryptoSignersISOTrailers_get_TRAILER_IMPLICIT(void);
#define OrgSpongycastleCryptoSignersISOTrailers_TRAILER_IMPLICIT 188
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoSignersISOTrailers, TRAILER_IMPLICIT, jint)

inline jint OrgSpongycastleCryptoSignersISOTrailers_get_TRAILER_RIPEMD160(void);
#define OrgSpongycastleCryptoSignersISOTrailers_TRAILER_RIPEMD160 12748
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoSignersISOTrailers, TRAILER_RIPEMD160, jint)

inline jint OrgSpongycastleCryptoSignersISOTrailers_get_TRAILER_RIPEMD128(void);
#define OrgSpongycastleCryptoSignersISOTrailers_TRAILER_RIPEMD128 13004
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoSignersISOTrailers, TRAILER_RIPEMD128, jint)

inline jint OrgSpongycastleCryptoSignersISOTrailers_get_TRAILER_SHA1(void);
#define OrgSpongycastleCryptoSignersISOTrailers_TRAILER_SHA1 13260
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoSignersISOTrailers, TRAILER_SHA1, jint)

inline jint OrgSpongycastleCryptoSignersISOTrailers_get_TRAILER_SHA256(void);
#define OrgSpongycastleCryptoSignersISOTrailers_TRAILER_SHA256 13516
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoSignersISOTrailers, TRAILER_SHA256, jint)

inline jint OrgSpongycastleCryptoSignersISOTrailers_get_TRAILER_SHA512(void);
#define OrgSpongycastleCryptoSignersISOTrailers_TRAILER_SHA512 13772
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoSignersISOTrailers, TRAILER_SHA512, jint)

inline jint OrgSpongycastleCryptoSignersISOTrailers_get_TRAILER_SHA384(void);
#define OrgSpongycastleCryptoSignersISOTrailers_TRAILER_SHA384 14028
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoSignersISOTrailers, TRAILER_SHA384, jint)

inline jint OrgSpongycastleCryptoSignersISOTrailers_get_TRAILER_WHIRLPOOL(void);
#define OrgSpongycastleCryptoSignersISOTrailers_TRAILER_WHIRLPOOL 14284
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoSignersISOTrailers, TRAILER_WHIRLPOOL, jint)

inline jint OrgSpongycastleCryptoSignersISOTrailers_get_TRAILER_SHA224(void);
#define OrgSpongycastleCryptoSignersISOTrailers_TRAILER_SHA224 14540
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoSignersISOTrailers, TRAILER_SHA224, jint)

inline jint OrgSpongycastleCryptoSignersISOTrailers_get_TRAILER_SHA512_224(void);
#define OrgSpongycastleCryptoSignersISOTrailers_TRAILER_SHA512_224 14796
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoSignersISOTrailers, TRAILER_SHA512_224, jint)

inline jint OrgSpongycastleCryptoSignersISOTrailers_get_TRAILER_SHA512_256(void);
#define OrgSpongycastleCryptoSignersISOTrailers_TRAILER_SHA512_256 16588
J2OBJC_STATIC_FIELD_CONSTANT(OrgSpongycastleCryptoSignersISOTrailers, TRAILER_SHA512_256, jint)

FOUNDATION_EXPORT void OrgSpongycastleCryptoSignersISOTrailers_init(OrgSpongycastleCryptoSignersISOTrailers *self);

FOUNDATION_EXPORT OrgSpongycastleCryptoSignersISOTrailers *new_OrgSpongycastleCryptoSignersISOTrailers_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastleCryptoSignersISOTrailers *create_OrgSpongycastleCryptoSignersISOTrailers_init(void);

FOUNDATION_EXPORT JavaLangInteger *OrgSpongycastleCryptoSignersISOTrailers_getTrailerWithOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDigest> digest);

FOUNDATION_EXPORT jboolean OrgSpongycastleCryptoSignersISOTrailers_noTrailerAvailableWithOrgSpongycastleCryptoDigest_(id<OrgSpongycastleCryptoDigest> digest);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleCryptoSignersISOTrailers)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleCryptoSignersISOTrailers")
