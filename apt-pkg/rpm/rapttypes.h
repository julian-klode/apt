#ifndef PKGLIB_RAPTTYPES_H
#define PKGLIB_RAPTTYPES_H

/*
 * Layer of insulation against differing types used in rpm versions.
 * C happily converts enum to int etc automatically, C++ doesn't...
 */

#include <rpm/rpmtypes.h>
#include <rpm/rpmds.h>
typedef rpm_data_t raptTagData;
typedef rpm_count_t raptTagCount;
#ifdef RPM_HAVE_RPMTAGVAL
typedef rpm_tag_t raptTag;
typedef rpm_tagtype_t raptTagType;
#else
typedef rpmTag raptTag;
typedef rpmTagType raptTagType;
#endif
typedef rpmsenseFlags raptDepFlags;
typedef rpm_loff_t raptOffset;
typedef rpm_loff_t raptCallbackSize;
typedef uint32_t raptInt;
typedef uint32_t raptDbOffset;
#define RAPT_FILENAMES RPMTAG_FILENAMES

#define raptInitIterator(a,b,c,d) rpmtsInitIterator(a,(rpmTag)b,c,d)
#endif /* PKGLIB_RAPTTYPES_H */
