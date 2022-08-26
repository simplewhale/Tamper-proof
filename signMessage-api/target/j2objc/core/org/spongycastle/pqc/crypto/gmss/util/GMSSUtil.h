//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/pqc/crypto/gmss/util/GMSSUtil.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoGmssUtilGMSSUtil")
#ifdef RESTRICT_OrgSpongycastlePqcCryptoGmssUtilGMSSUtil
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoGmssUtilGMSSUtil 0
#else
#define INCLUDE_ALL_OrgSpongycastlePqcCryptoGmssUtilGMSSUtil 1
#endif
#undef RESTRICT_OrgSpongycastlePqcCryptoGmssUtilGMSSUtil

#if !defined (OrgSpongycastlePqcCryptoGmssUtilGMSSUtil_) && (INCLUDE_ALL_OrgSpongycastlePqcCryptoGmssUtilGMSSUtil || defined(INCLUDE_OrgSpongycastlePqcCryptoGmssUtilGMSSUtil))
#define OrgSpongycastlePqcCryptoGmssUtilGMSSUtil_

@class IOSByteArray;
@class IOSObjectArray;

@interface OrgSpongycastlePqcCryptoGmssUtilGMSSUtil : NSObject

#pragma mark Public

- (instancetype)init;

- (jint)bytesToIntLittleEndianWithByteArray:(IOSByteArray *)bytes;

- (jint)bytesToIntLittleEndianWithByteArray:(IOSByteArray *)bytes
                                    withInt:(jint)offset;

- (IOSByteArray *)concatenateArrayWithByteArray2:(IOSObjectArray *)arraycp;

- (jint)getLogWithInt:(jint)intValue;

- (IOSByteArray *)intToBytesLittleEndianWithInt:(jint)value;

- (void)printArrayWithNSString:(NSString *)text
                 withByteArray:(IOSByteArray *)array;

- (void)printArrayWithNSString:(NSString *)text
                withByteArray2:(IOSObjectArray *)array;

- (jboolean)testPowerOfTwoWithInt:(jint)testValue;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastlePqcCryptoGmssUtilGMSSUtil)

FOUNDATION_EXPORT void OrgSpongycastlePqcCryptoGmssUtilGMSSUtil_init(OrgSpongycastlePqcCryptoGmssUtilGMSSUtil *self);

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoGmssUtilGMSSUtil *new_OrgSpongycastlePqcCryptoGmssUtilGMSSUtil_init(void) NS_RETURNS_RETAINED;

FOUNDATION_EXPORT OrgSpongycastlePqcCryptoGmssUtilGMSSUtil *create_OrgSpongycastlePqcCryptoGmssUtilGMSSUtil_init(void);

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastlePqcCryptoGmssUtilGMSSUtil)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastlePqcCryptoGmssUtilGMSSUtil")
