//
//  Generated by the J2ObjC translator.  DO NOT EDIT!
//  source: /Users/alen/Downloads/signMessage-api/target/classes/BIP39/io/github/novacrypto/bip39/Validation/WordNotFoundException.java
//

#include "IOSClass.h"
#include "IOSObjectArray.h"
#include "J2ObjC_source.h"
#include "io/github/novacrypto/bip39/Validation/WordNotFoundException.h"
#include "java/lang/CharSequence.h"
#include "java/lang/Exception.h"

@interface IoGithubNovacryptoBip39ValidationWordNotFoundException () {
 @public
  id<JavaLangCharSequence> word_;
  id<JavaLangCharSequence> suggestion1_;
  id<JavaLangCharSequence> suggestion2_;
}

@end

J2OBJC_FIELD_SETTER(IoGithubNovacryptoBip39ValidationWordNotFoundException, word_, id<JavaLangCharSequence>)
J2OBJC_FIELD_SETTER(IoGithubNovacryptoBip39ValidationWordNotFoundException, suggestion1_, id<JavaLangCharSequence>)
J2OBJC_FIELD_SETTER(IoGithubNovacryptoBip39ValidationWordNotFoundException, suggestion2_, id<JavaLangCharSequence>)

@implementation IoGithubNovacryptoBip39ValidationWordNotFoundException

- (instancetype)initWithJavaLangCharSequence:(id<JavaLangCharSequence>)word
                    withJavaLangCharSequence:(id<JavaLangCharSequence>)suggestion1
                    withJavaLangCharSequence:(id<JavaLangCharSequence>)suggestion2 {
  IoGithubNovacryptoBip39ValidationWordNotFoundException_initWithJavaLangCharSequence_withJavaLangCharSequence_withJavaLangCharSequence_(self, word, suggestion1, suggestion2);
  return self;
}

- (id<JavaLangCharSequence>)getWord {
  return word_;
}

- (id<JavaLangCharSequence>)getSuggestion1 {
  return suggestion1_;
}

- (id<JavaLangCharSequence>)getSuggestion2 {
  return suggestion2_;
}

+ (const J2ObjcClassInfo *)__metadata {
  static J2ObjcMethodInfo methods[] = {
    { NULL, NULL, 0x1, -1, 0, -1, -1, -1, -1 },
    { NULL, "LJavaLangCharSequence;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaLangCharSequence;", 0x1, -1, -1, -1, -1, -1, -1 },
    { NULL, "LJavaLangCharSequence;", 0x1, -1, -1, -1, -1, -1, -1 },
  };
  #pragma clang diagnostic push
  #pragma clang diagnostic ignored "-Wobjc-multiple-method-names"
  #pragma clang diagnostic ignored "-Wundeclared-selector"
  methods[0].selector = @selector(initWithJavaLangCharSequence:withJavaLangCharSequence:withJavaLangCharSequence:);
  methods[1].selector = @selector(getWord);
  methods[2].selector = @selector(getSuggestion1);
  methods[3].selector = @selector(getSuggestion2);
  #pragma clang diagnostic pop
  static const J2ObjcFieldInfo fields[] = {
    { "word_", "LJavaLangCharSequence;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "suggestion1_", "LJavaLangCharSequence;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
    { "suggestion2_", "LJavaLangCharSequence;", .constantValue.asLong = 0, 0x12, -1, -1, -1, -1 },
  };
  static const void *ptrTable[] = { "LJavaLangCharSequence;LJavaLangCharSequence;LJavaLangCharSequence;" };
  static const J2ObjcClassInfo _IoGithubNovacryptoBip39ValidationWordNotFoundException = { "WordNotFoundException", "io.github.novacrypto.bip39.Validation", ptrTable, methods, fields, 7, 0x11, 4, 3, -1, -1, -1, -1, -1 };
  return &_IoGithubNovacryptoBip39ValidationWordNotFoundException;
}

@end

void IoGithubNovacryptoBip39ValidationWordNotFoundException_initWithJavaLangCharSequence_withJavaLangCharSequence_withJavaLangCharSequence_(IoGithubNovacryptoBip39ValidationWordNotFoundException *self, id<JavaLangCharSequence> word, id<JavaLangCharSequence> suggestion1, id<JavaLangCharSequence> suggestion2) {
  JavaLangException_initWithNSString_(self, NSString_java_formatWithNSString_withNSObjectArray_(@"Word not found in word list \"%s\", suggestions \"%s\", \"%s\"", [IOSObjectArray newArrayWithObjects:(id[]){ word, suggestion1, suggestion2 } count:3 type:NSObject_class_()]));
  self->word_ = word;
  self->suggestion1_ = suggestion1;
  self->suggestion2_ = suggestion2;
}

IoGithubNovacryptoBip39ValidationWordNotFoundException *new_IoGithubNovacryptoBip39ValidationWordNotFoundException_initWithJavaLangCharSequence_withJavaLangCharSequence_withJavaLangCharSequence_(id<JavaLangCharSequence> word, id<JavaLangCharSequence> suggestion1, id<JavaLangCharSequence> suggestion2) {
  J2OBJC_NEW_IMPL(IoGithubNovacryptoBip39ValidationWordNotFoundException, initWithJavaLangCharSequence_withJavaLangCharSequence_withJavaLangCharSequence_, word, suggestion1, suggestion2)
}

IoGithubNovacryptoBip39ValidationWordNotFoundException *create_IoGithubNovacryptoBip39ValidationWordNotFoundException_initWithJavaLangCharSequence_withJavaLangCharSequence_withJavaLangCharSequence_(id<JavaLangCharSequence> word, id<JavaLangCharSequence> suggestion1, id<JavaLangCharSequence> suggestion2) {
  J2OBJC_CREATE_IMPL(IoGithubNovacryptoBip39ValidationWordNotFoundException, initWithJavaLangCharSequence_withJavaLangCharSequence_withJavaLangCharSequence_, word, suggestion1, suggestion2)
}

J2OBJC_CLASS_TYPE_LITERAL_SOURCE(IoGithubNovacryptoBip39ValidationWordNotFoundException)
