//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/core/org/spongycastle/util/encoders/Translator.java
//

#include "J2ObjC_header.h"

#pragma push_macro("INCLUDE_ALL_OrgSpongycastleUtilEncodersTranslator")
#ifdef RESTRICT_OrgSpongycastleUtilEncodersTranslator
#define INCLUDE_ALL_OrgSpongycastleUtilEncodersTranslator 0
#else
#define INCLUDE_ALL_OrgSpongycastleUtilEncodersTranslator 1
#endif
#undef RESTRICT_OrgSpongycastleUtilEncodersTranslator

#if !defined (OrgSpongycastleUtilEncodersTranslator_) && (INCLUDE_ALL_OrgSpongycastleUtilEncodersTranslator || defined(INCLUDE_OrgSpongycastleUtilEncodersTranslator))
#define OrgSpongycastleUtilEncodersTranslator_

@class IOSByteArray;

@protocol OrgSpongycastleUtilEncodersTranslator < JavaObject >

- (jint)getEncodedBlockSize;

- (jint)encodeWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)length
              withByteArray:(IOSByteArray *)outArg
                    withInt:(jint)outOff;

- (jint)getDecodedBlockSize;

- (jint)decodeWithByteArray:(IOSByteArray *)inArg
                    withInt:(jint)inOff
                    withInt:(jint)length
              withByteArray:(IOSByteArray *)outArg
                    withInt:(jint)outOff;

@end

J2OBJC_EMPTY_STATIC_INIT(OrgSpongycastleUtilEncodersTranslator)

J2OBJC_TYPE_LITERAL_HEADER(OrgSpongycastleUtilEncodersTranslator)

#endif

#pragma pop_macro("INCLUDE_ALL_OrgSpongycastleUtilEncodersTranslator")