// -*- mode: c++; mode: fold -*-
// Description								/*{{{*/
// $Id: pkgcachegen.cc,v 1.53 2003/02/02 02:44:20 doogie Exp $
/* ######################################################################
   
   Package Cache Generator - Generator for the cache structure.
   
   This builds the cache structure from the abstract package list parser. 
   
   ##################################################################### */
									/*}}}*/
// Include Files							/*{{{*/
#define APT_COMPATIBILITY 986

#include <apt-pkg/pkgcachegen.h>
#include <apt-pkg/error.h>
#include <apt-pkg/version.h>
#include <apt-pkg/progress.h>
#include <apt-pkg/sourcelist.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/strutl.h>
#include <apt-pkg/sptr.h>
#include <apt-pkg/pkgsystem.h>

#include <apti18n.h>

#include <vector>

#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <system.h>
									/*}}}*/
typedef vector<pkgIndexFile *>::iterator FileIterator;

// CacheGenerator::pkgCacheGenerator - Constructor			/*{{{*/
// ---------------------------------------------------------------------
/* We set the diry flag and make sure that is written to the disk */
pkgCacheGenerator::pkgCacheGenerator(DynamicMMap *pMap,OpProgress *Prog) :
		    Map(*pMap), Cache(pMap,false), Progress(Prog),
		    FoundFileDeps(0)
{
   CurrentFile = 0;
   memset(UniqHash,0,sizeof(UniqHash));
   
   if (_error->PendingError() == true)
      return;

   if (Map.Size() == 0)
   {
      // Setup the map interface..
      Cache.HeaderP = (pkgCache::Header *)Map.Data();
      Map.RawAllocate(sizeof(pkgCache::Header));
      Map.UsePools(*Cache.HeaderP->Pools,sizeof(Cache.HeaderP->Pools)/sizeof(Cache.HeaderP->Pools[0]));
      
      // Starting header
      *Cache.HeaderP = pkgCache::Header();
      Cache.HeaderP->VerSysName = Map.WriteString(_system->VS->Label);
      Cache.HeaderP->Architecture = Map.WriteString(_config->Find("APT::Architecture"));
      Cache.ReMap(); 
   }
   else
   {
      // Map directly from the existing file
      Cache.ReMap(); 
      Map.UsePools(*Cache.HeaderP->Pools,sizeof(Cache.HeaderP->Pools)/sizeof(Cache.HeaderP->Pools[0]));
      if (Cache.VS != _system->VS)
      {
	 _error->Error(_("Cache has an incompatible versioning system"));
	 return;
      }      
   }
   
   Cache.HeaderP->Dirty = true;
   Map.Sync(0,sizeof(pkgCache::Header));
}
									/*}}}*/
// CacheGenerator::~pkgCacheGenerator - Destructor 			/*{{{*/
// ---------------------------------------------------------------------
/* We sync the data then unset the dirty flag in two steps so as to
   advoid a problem during a crash */
pkgCacheGenerator::~pkgCacheGenerator()
{
   if (_error->PendingError() == true)
      return;
   if (Map.Sync() == false)
      return;
   
   Cache.HeaderP->Dirty = false;
   Map.Sync(0,sizeof(pkgCache::Header));
}
									/*}}}*/
// CacheGenerator::MergeList - Merge the package list			/*{{{*/
// ---------------------------------------------------------------------
/* This provides the generation of the entries in the cache. Each loop
   goes through a single package record from the underlying parse engine. */
bool pkgCacheGenerator::MergeList(ListParser &List,
				  pkgCache::VerIterator *OutVer)
{
   List.Owner = this;

   // CNC:2003-02-20 - When --reinstall is used during a cache building
   //		       process, the algorithm is sligthly changed to
   //		       order the "better" architectures before, even if
   //		       they are already in the system.
   bool ReInstall = _config->FindB("APT::Get::ReInstall", false);

   unsigned int Counter = 0;
   while (List.Step() == true)
   {
      // Get a pointer to the package structure
      string PackageName = List.Package();
      if (PackageName.empty() == true)
	 return false;
      
      pkgCache::PkgIterator Pkg;
      if (NewPackage(Pkg,PackageName) == false)
	 return _error->Error(_("Error occured while processing %s (NewPackage)"),PackageName.c_str());
      Counter++;
      // CNC:2003-02-16
      if (Counter % 100 == 0 && Progress != 0) {
	 if (List.OrderedOffset() == true)
	    Progress->Progress(List.Offset());
	 else
	    Progress->Progress(Counter);
      }

      /* Get a pointer to the version structure. We know the list is sorted
         so we use that fact in the search. Insertion of new versions is
	 done with correct sorting */
      string Version = List.Version();
      if (Version.empty() == true)
      {
	 if (List.UsePackage(Pkg,pkgCache::VerIterator(Cache)) == false)
	    return _error->Error(_("Error occured while processing %s (UsePackage1)"),
				 PackageName.c_str());
	 continue;
      }

      // CNC:2002-07-09
      string Arch = List.Architecture();

      pkgCache::VerIterator Ver = Pkg.VersionList();
      map_ptrloc *Last = &Pkg->VersionList;
      int Res = 1;
      for (; Ver.end() == false; Last = &Ver->NextVer, Ver++)
      {
	 // 2003-02-20 - If the package is already installed, the
	 //              architecture doesn't matter, unless
	 //              --reinstall has been used.
	 if (!ReInstall && List.IsDatabase())
	    Res = Cache.VS->CmpVersion(Version, Ver.VerStr());
	 else
	    Res = Cache.VS->CmpVersionArch(Version,Arch,
					   Ver.VerStr(),Ver.Arch());
	 if (Res >= 0)
	    break;
      }
      
      /* We already have a version for this item, record that we
         saw it */
      unsigned long Hash = List.VersionHash();
      if (Res == 0 && Ver->Hash == Hash)
      {
	 if (List.UsePackage(Pkg,Ver) == false)
	    return _error->Error(_("Error occured while processing %s (UsePackage2)"),
				 PackageName.c_str());

	 if (NewFileVer(Ver,List) == false)
	    return _error->Error(_("Error occured while processing %s (NewFileVer1)"),
				 PackageName.c_str());
	 
	 // Read only a single record and return
	 if (OutVer != 0)
	 {
	    *OutVer = Ver;
	    FoundFileDeps |= List.HasFileDeps();
	    return true;
	 }
	 
	 continue;
      }      

      // Skip to the end of the same version set.
      if (Res == 0)
      {
	 // CNC:2003-02-20 - Unless this package is already installed.
	 if (!List.IsDatabase())
	 for (; Ver.end() == false; Last = &Ver->NextVer, Ver++)
	 {
	    // CNC:2002-07-09
	    Res = Cache.VS->CmpVersionArch(Version,Arch,
			    		   Ver.VerStr(),Ver.Arch());
	    if (Res != 0)
	       break;
	 }
      }

      // Add a new version
      *Last = NewVersion(Ver,Version,*Last);
      Ver->ParentPkg = Pkg.Index();
      Ver->Hash = Hash;
      if (List.NewVersion(Ver) == false)
	 return _error->Error(_("Error occured while processing %s (NewVersion1)"),
			      PackageName.c_str());

      if (List.UsePackage(Pkg,Ver) == false)
	 return _error->Error(_("Error occured while processing %s (UsePackage3)"),
			      PackageName.c_str());
      
      if (NewFileVer(Ver,List) == false)
	 return _error->Error(_("Error occured while processing %s (NewVersion2)"),
			      PackageName.c_str());

      // Read only a single record and return
      if (OutVer != 0)
      {
	 *OutVer = Ver;
	 FoundFileDeps |= List.HasFileDeps();
	 return true;
      }      
   }

   FoundFileDeps |= List.HasFileDeps();

   if (Cache.HeaderP->PackageCount >= (1ULL<<sizeof(Cache.PkgP->ID)*8)-1)
      return _error->Error(_("Wow, you exceeded the number of package "
			     "names this APT is capable of."));
   if (Cache.HeaderP->VersionCount >= (1ULL<<(sizeof(Cache.VerP->ID)*8))-1)
      return _error->Error(_("Wow, you exceeded the number of versions "
			     "this APT is capable of."));
   if (Cache.HeaderP->DependsCount >= (1ULL<<(sizeof(Cache.DepP->ID)*8))-1ULL)
      return _error->Error(_("Wow, you exceeded the number of dependencies "
			     "this APT is capable of."));
   return true;
}
									/*}}}*/
// CacheGenerator::MergeFileProvides - Merge file provides   		/*{{{*/
// ---------------------------------------------------------------------
/* If we found any file depends while parsing the main list we need to 
   resolve them. Since it is undesired to load the entire list of files
   into the cache as virtual packages we do a two stage effort. MergeList
   identifies the file depends and this creates Provdies for them by
   re-parsing all the indexs. */
bool pkgCacheGenerator::MergeFileProvides(ListParser &List)
{
   List.Owner = this;
   
   unsigned int Counter = 0;
   while (List.Step() == true)
   {
      string PackageName = List.Package();
      if (PackageName.empty() == true)
	 return false;
      string Version = List.Version();
      if (Version.empty() == true)
	 continue;
      
      pkgCache::PkgIterator Pkg = Cache.FindPkg(PackageName);
      if (Pkg.end() == true)
#if 0
	 // CNC:2003-03-03 - Ignore missing packages. This will happen when
	 //		     a package is placed in Allow-Duplicated and
	 //		     then removed, but the source cache is still
	 //		     counting with it as Allow-Duplicated. No good
	 //		     way to handle that right now.
	 return _error->Error(_("Error occured while processing %s (FindPkg)"),
				PackageName.c_str());
#else
	 continue;
#endif

      Counter++;
      // CNC:2003-02-16
      if (Counter % 100 == 0 && Progress != 0) {
	 if (List.OrderedOffset() == true)
	    Progress->Progress(List.Offset());
	 else
	    Progress->Progress(Counter);
      }

      string Arch = List.Architecture();
      pkgCache::VerIterator Ver = Pkg.VersionList();
      for (; Ver.end() == false; Ver++)
      {
	 // We'd want to check against versionhash but repomd filelists
	 // don't carry all the necessary data. Settle for ver-arch match.
	 if (strcmp(Version.c_str(), Ver.VerStr()) == 0 &&
	     strcmp(Arch.c_str(), Ver.Arch()) == 0)
	 {
	    if (List.CollectFileProvides(Cache,Ver) == false)
	       return _error->Error(_("Error occured while processing %s (CollectFileProvides)"),PackageName.c_str());
	    break;
	 }
      }
      
      // CNC:2003-03-03 - Ignore missing versions. This will happen when
      //		  a package is placed in Allow-Duplicated and
      //		  then removed, but the source cache is still
      //		  counting with it as Allow-Duplicated. No good
      //		  way to handle that right now.
#if 0
      if (Ver.end() == true)
	 _error->Warning(_("Package %s %s was not found while processing file dependencies"),PackageName.c_str(),Version.c_str());
#endif
   }

   return true;
}
									/*}}}*/
// CacheGenerator::NewPackage - Add a new package			/*{{{*/
// ---------------------------------------------------------------------
/* This creates a new package structure and adds it to the hash table */
bool pkgCacheGenerator::NewPackage(pkgCache::PkgIterator &Pkg,
				   const string & Name)
{
// CNC:2003-02-17 - Optimized.
#if 0
   Pkg = Cache.FindPkg(Name);
   if (Pkg.end() == false)
      return true;
#else
   pkgCache::Package *P = Cache.FindPackage(Name.c_str());
   if (P != NULL) {
      Pkg = pkgCache::PkgIterator(Cache, P);
      return true;
   }
#endif
       
   // Get a structure
   unsigned long Package = Map.Allocate(sizeof(pkgCache::Package));
   if (Package == 0)
      return false;
   
   Pkg = pkgCache::PkgIterator(Cache,Cache.PkgP + Package);
   
   // Insert it into the hash table
   unsigned long Hash = Cache.Hash(Name);
   Pkg->NextPackage = Cache.HeaderP->HashTable[Hash];
   Cache.HeaderP->HashTable[Hash] = Package;
   
   // Set the name and the ID
   Pkg->Name = Map.WriteString(Name);
   if (Pkg->Name == 0)
      return false;
   Pkg->ID = Cache.HeaderP->PackageCount++;
   
   return true;
}
									/*}}}*/
// CacheGenerator::NewFileVer - Create a new File<->Version association	/*{{{*/
// ---------------------------------------------------------------------
/* */
bool pkgCacheGenerator::NewFileVer(pkgCache::VerIterator &Ver,
				   ListParser &List)
{
   if (CurrentFile == 0)
      return true;
   
   // Get a structure
   unsigned long VerFile = Map.Allocate(sizeof(pkgCache::VerFile));
   if (VerFile == 0)
      return 0;
   
   pkgCache::VerFileIterator VF(Cache,Cache.VerFileP + VerFile);
   VF->File = CurrentFile - Cache.PkgFileP;
   
   // Link it to the end of the list
   map_ptrloc *Last = &Ver->FileList;
   for (pkgCache::VerFileIterator V = Ver.FileList(); V.end() == false; V++)
      Last = &V->NextFile;
   VF->NextFile = *Last;
   *Last = VF.Index();
   
   VF->Offset = List.Offset();
   VF->Size = List.Size();
   if (Cache.HeaderP->MaxVerFileSize < VF->Size)
      Cache.HeaderP->MaxVerFileSize = VF->Size;
   Cache.HeaderP->VerFileCount++;
   
   return true;
}
									/*}}}*/
// CacheGenerator::NewVersion - Create a new Version 			/*{{{*/
// ---------------------------------------------------------------------
/* This puts a version structure in the linked list */
unsigned long pkgCacheGenerator::NewVersion(pkgCache::VerIterator &Ver,
					    const string & VerStr,
					    unsigned long Next)
{
   // Get a structure
   unsigned long Version = Map.Allocate(sizeof(pkgCache::Version));
   if (Version == 0)
      return 0;
   
   // Fill it in
   Ver = pkgCache::VerIterator(Cache,Cache.VerP + Version);
   Ver->NextVer = Next;
   Ver->ID = Cache.HeaderP->VersionCount++;
   Ver->VerStr = Map.WriteString(VerStr);
   if (Ver->VerStr == 0)
      return 0;
   
   return Version;
}
									/*}}}*/
// ListParser::NewDepends - Create a dependency element			/*{{{*/
// ---------------------------------------------------------------------
/* This creates a dependency element in the tree. It is linked to the
   version and to the package that it is pointing to. */
bool pkgCacheGenerator::ListParser::NewDepends(pkgCache::VerIterator Ver,
					       const string & PackageName,
					       const string & Version,
					       unsigned int Op,
					       unsigned int Type)
{
   pkgCache &Cache = Owner->Cache;
   
   // Get a structure
   unsigned long Dependency = Owner->Map.Allocate(sizeof(pkgCache::Dependency));
   if (Dependency == 0)
      return false;
   
   // Fill it in
   pkgCache::DepIterator Dep(Cache,Cache.DepP + Dependency);
   Dep->ParentVer = Ver.Index();
   Dep->Type = Type;
   Dep->CompareOp = Op;
   Dep->ID = Cache.HeaderP->DependsCount++;
   
   // Locate the target package
   pkgCache::PkgIterator Pkg;
   if (Owner->NewPackage(Pkg,PackageName) == false)
      return false;
   
   // Probe the reverse dependency list for a version string that matches
   if (Version.empty() == false)
   {
/*      for (pkgCache::DepIterator I = Pkg.RevDependsList(); I.end() == false; I++)
	 if (I->Version != 0 && I.TargetVer() == Version)
	    Dep->Version = I->Version;*/
      if (Dep->Version == 0)
	 if ((Dep->Version = WriteString(Version)) == 0)
	    return false;
   }
      
   // Link it to the package
   Dep->Package = Pkg.Index();
   Dep->NextRevDepends = Pkg->RevDepends;
   Pkg->RevDepends = Dep.Index();
   
   /* Link it to the version (at the end of the list)
      Caching the old end point speeds up generation substantially */
   if (OldDepVer != Ver)
   {
      OldDepLast = &Ver->DependsList;
      for (pkgCache::DepIterator D = Ver.DependsList(); D.end() == false; D++)
	 OldDepLast = &D->NextDepends;
      OldDepVer = Ver;
   }

   // Is it a file dependency?
   if (PackageName[0] == '/')
      FoundFileDeps = true;
   
   Dep->NextDepends = *OldDepLast;
   *OldDepLast = Dep.Index();
   OldDepLast = &Dep->NextDepends;

   return true;
}
									/*}}}*/
// ListParser::NewProvides - Create a Provides element			/*{{{*/
// ---------------------------------------------------------------------
/* */
bool pkgCacheGenerator::ListParser::NewProvides(pkgCache::VerIterator Ver,
					        const string & PackageName,
						const string & Version)
{
   pkgCache &Cache = Owner->Cache;

// PM:2006-02-07 allow self-referencing provides for now at least...
#if 0
   // We do not add self referencing provides
   if (Ver.ParentPkg().Name() == PackageName)
      return true;
#endif
   
   // Get a structure
   unsigned long Provides = Owner->Map.Allocate(sizeof(pkgCache::Provides));
   if (Provides == 0)
      return false;
   Cache.HeaderP->ProvidesCount++;
   
   // Fill it in
   pkgCache::PrvIterator Prv(Cache,Cache.ProvideP + Provides,Cache.PkgP);
   Prv->Version = Ver.Index();
   Prv->NextPkgProv = Ver->ProvidesList;
   Ver->ProvidesList = Prv.Index();
   if (Version.empty() == false && (Prv->ProvideVersion = WriteString(Version)) == 0)
      return false;
   
   // Locate the target package
   pkgCache::PkgIterator Pkg;
   if (Owner->NewPackage(Pkg,PackageName) == false)
      return false;
   
   // Link it to the package
   Prv->ParentPkg = Pkg.Index();
   Prv->NextProvides = Pkg->ProvidesList;
   Pkg->ProvidesList = Prv.Index();
   
   return true;
}
									/*}}}*/
// CacheGenerator::SelectFile - Select the current file being parsed	/*{{{*/
// ---------------------------------------------------------------------
/* This is used to select which file is to be associated with all newly
   added versions. The caller is responsible for setting the IMS fields. */
bool pkgCacheGenerator::SelectFile(const string & File, const string & Site,
				   const pkgIndexFile &Index,
				   unsigned long Flags)
{
   // Get some space for the structure
   CurrentFile = Cache.PkgFileP + Map.Allocate(sizeof(*CurrentFile));
   if (CurrentFile == Cache.PkgFileP)
      return false;
   
   // Fill it in
   CurrentFile->FileName = Map.WriteString(File);
   CurrentFile->Site = WriteUniqString(Site);
   CurrentFile->NextFile = Cache.HeaderP->FileList;
   CurrentFile->Flags = Flags;
   CurrentFile->ID = Cache.HeaderP->PackageFileCount;
   CurrentFile->IndexType = WriteUniqString(Index.GetType()->Label);
   PkgFileName = File;
   Cache.HeaderP->FileList = CurrentFile - Cache.PkgFileP;
   Cache.HeaderP->PackageFileCount++;

   if (CurrentFile->FileName == 0)
      return false;
   
   if (Progress != 0)
      Progress->SubProgress(Index.Size());
   return true;
}
									/*}}}*/
// CacheGenerator::WriteUniqueString - Insert a unique string		/*{{{*/
// ---------------------------------------------------------------------
/* This is used to create handles to strings. Given the same text it
   always returns the same number */
unsigned long pkgCacheGenerator::WriteUniqString(const char *S,
						 unsigned int Size)
{
   /* We use a very small transient hash table here, this speeds up generation
      by a fair amount on slower machines */
   pkgCache::StringItem *&Bucket = UniqHash[(S[0]*5 + S[1]) % _count(UniqHash)];
   if (Bucket != 0 && 
       stringcmp(S,S+Size,Cache.StrP + Bucket->String) == 0)
      return Bucket->String;
   
   // Search for an insertion point
   pkgCache::StringItem *I = Cache.StringItemP + Cache.HeaderP->StringList;
   int Res = 1;
   map_ptrloc *Last = &Cache.HeaderP->StringList;
   for (; I != Cache.StringItemP; Last = &I->NextItem, 
        I = Cache.StringItemP + I->NextItem)
   {
      Res = stringcmp(S,S+Size,Cache.StrP + I->String);
      if (Res >= 0)
	 break;
   }
   
   // Match
   if (Res == 0)
   {
      Bucket = I;
      return I->String;
   }
   
   // Get a structure
   unsigned long Item = Map.Allocate(sizeof(pkgCache::StringItem));
   if (Item == 0)
      return 0;

   // Fill in the structure
   pkgCache::StringItem *ItemP = Cache.StringItemP + Item;
   ItemP->NextItem = I - Cache.StringItemP;
   *Last = Item;
   ItemP->String = Map.WriteString(S,Size);
   if (ItemP->String == 0)
      return 0;
   
   Bucket = ItemP;
   return ItemP->String;
}
									/*}}}*/

// CheckValidity - Check that a cache is up-to-date			/*{{{*/
// ---------------------------------------------------------------------
/* This just verifies that each file in the list of index files exists,
   has matching attributes with the cache and the cache does not have
   any extra files. */
static bool CheckValidity(string CacheFile, FileIterator Start, 
                          FileIterator End,MMap **OutMap = 0)
{
   // No file, certainly invalid
   if (CacheFile.empty() == true || FileExists(CacheFile) == false)
      return false;
   
   // CNC:2003-02-20 - When --reinstall is used during a cache building
   //		       process, the algorithm is sligthly changed to
   //		       order the "better" architectures before, even if
   //		       they are already in the system. Thus, we rebuild
   //		       the cache when it's used.
   bool ReInstall = _config->FindB("APT::Get::ReInstall", false);
   if (ReInstall == true)
      return false;

   // Map it
   FileFd CacheF(CacheFile,FileFd::ReadOnly);
   SPtr<MMap> Map = new MMap(CacheF,MMap::Public | MMap::ReadOnly);
   pkgCache Cache(Map);
   if (_error->PendingError() == true || Map->Size() == 0)
   {
      _error->Discard();
      return false;
   }
   
   // CNC:2003-11-24
   if (_system->OptionsHash() != Cache.HeaderP->OptionsHash)
      return false;

   /* Now we check every index file, see if it is in the cache,
      verify the IMS data and check that it is on the disk too.. */
   SPtrArray<bool> Visited = new bool[Cache.HeaderP->PackageFileCount];
   memset(Visited,0,sizeof(*Visited)*Cache.HeaderP->PackageFileCount);
   for (; Start != End; Start++)
   {      
      if ((*Start)->HasPackages() == false)
	 continue;
    
      if ((*Start)->Exists() == false)
      {
	 // CNC:2002-07-04
	 /*_error->WarningE("stat",_("Couldn't stat source package list %s"),
	 		  (*Start)->Describe().c_str());*/
	 continue;
      }

      // Band-aid for cache corruption issue (RH bugzilla #211254) 
      // until real cause and cure is found
      for (pkgCache::PkgFileIterator File = Cache.FileBegin(); 
	    File.end() == false; File++) {
	 if (File.FileName() == NULL) {
	    _error->Warning(_("Cache corruption detected, band-aid applied."));
	    _error->Warning(_("See https://bugzilla.redhat.com/bugzilla/show_bug.cgi?id=211254 for further info."));
	    return false;
	 }
      }

      // FindInCache is also expected to do an IMS check.
      pkgCache::PkgFileIterator File = (*Start)->FindInCache(Cache);
      if (File.end() == true)
	 return false;
      
      Visited[File->ID] = true;
   }
   
   for (unsigned I = 0; I != Cache.HeaderP->PackageFileCount; I++)
      if (Visited[I] == false)
	 return false;
   
   if (_error->PendingError() == true)
   {
      _error->Discard();
      return false;
   }
   
   if (OutMap != 0)
      *OutMap = Map.UnGuard();
   return true;
}
									/*}}}*/
// ComputeSize - Compute the total size of a bunch of files		/*{{{*/
// ---------------------------------------------------------------------
/* Size is kind of an abstract notion that is only used for the progress
   meter */
static unsigned long ComputeSize(FileIterator Start,FileIterator End)
{
   unsigned long TotalSize = 0;
   for (; Start != End; Start++)
   {
      if ((*Start)->HasPackages() == false)
	 continue;      
      if ((*Start)->Exists() == false)
	 continue;
      TotalSize += (*Start)->Size();
   }
   return TotalSize;
}
									/*}}}*/
// BuildCache - Merge the list of index files into the cache		/*{{{*/
// ---------------------------------------------------------------------
/* */
static bool BuildCache(pkgCacheGenerator &Gen,
		       OpProgress &Progress,
		       unsigned long &CurrentSize,unsigned long TotalSize,
		       FileIterator Start, FileIterator End)
{
   FileIterator I;
   for (I = Start; I != End; I++)
   {
      if ((*I)->HasPackages() == false)
	 continue;
      
      if ((*I)->Exists() == false)
	 continue;

      if ((*I)->FindInCache(Gen.GetCache()).end() == false)
      {
	 _error->Warning("Duplicate sources.list entry %s",
			 (*I)->Describe().c_str());
	 continue;
      }
      
      unsigned long Size = (*I)->Size();
      Progress.OverallProgress(CurrentSize,TotalSize,Size,_("Reading Package Lists"));
      CurrentSize += Size;
      
      if ((*I)->Merge(Gen,Progress) == false)
	 return false;
   }   

   // CNC:2003-03-03 - Code that was here has been moved to its own function.
   
   return true;
}
									/*}}}*/
// CNC:2003-03-03
// CollectFileProvides - Merge the file provides into the cache		/*{{{*/
// ---------------------------------------------------------------------
/* */
static bool CollectFileProvides(pkgCacheGenerator &Gen,
				OpProgress &Progress,
				unsigned long &CurrentSize,unsigned long TotalSize,
			        FileIterator Start, FileIterator End)
{
   for (FileIterator I = Start; I != End; I++)
   {
      if ((*I)->HasPackages() == false || (*I)->Exists() == false)
	 continue;

      unsigned long Size = (*I)->Size();
      Progress.OverallProgress(CurrentSize,TotalSize,Size,_("Reading Package Lists"));
      CurrentSize += Size;

      if ((*I)->MergeFileProvides(Gen,Progress) == false)
	 return false;
   }
   return true;
}
									/*}}}*/
// MakeStatusCache - Construct the status cache				/*{{{*/
// ---------------------------------------------------------------------
/* This makes sure that the status cache (the cache that has all 
   index files from the sources list and all local ones) is ready
   to be mmaped. If OutMap is not zero then a MMap object representing
   the cache will be stored there. This is pretty much mandetory if you
   are using AllowMem. AllowMem lets the function be run as non-root
   where it builds the cache 'fast' into a memory buffer. */
bool pkgMakeStatusCache(pkgSourceList &List,OpProgress &Progress,
			MMap **OutMap,bool AllowMem)
{
   unsigned long MapSize = _config->FindI("APT::Cache-Limit",256*1024*1024);
   
   vector<pkgIndexFile *> Files(List.begin(),List.end());
   unsigned long EndOfSource = Files.size();
   if (_system->AddStatusFiles(Files) == false)
      return false;
   
   // Decide if we can write to the files..
   string CacheFile = _config->FindFile("Dir::Cache::pkgcache");
   string SrcCacheFile = _config->FindFile("Dir::Cache::srcpkgcache");
   
   // Decide if we can write to the cache
   bool Writeable = false;
   if (CacheFile.empty() == false)
      Writeable = access(flNotFile(CacheFile).c_str(),W_OK) == 0;
   else
      if (SrcCacheFile.empty() == false)
	 Writeable = access(flNotFile(SrcCacheFile).c_str(),W_OK) == 0;
   
   if (Writeable == false && AllowMem == false && CacheFile.empty() == false)
      return _error->Error(_("Unable to write to %s"),flNotFile(CacheFile).c_str());
   
   Progress.OverallProgress(0,1,1,_("Reading Package Lists"));
   
   // Cache is OK, Fin.
   if (CheckValidity(CacheFile,Files.begin(),Files.end(),OutMap) == true)
   {
      Progress.OverallProgress(1,1,1,_("Reading Package Lists"));
      return true;
   }
   
   // CNC:2002-07-03
#if DYING
   if (_system->PreProcess(Files.begin(),Files.end(),Progress) == false) 
   {
       _error->Error(_("Error pre-processing package lists"));
       return false;
   }
#endif
   /* At this point we know we need to reconstruct the package cache,
      begin. */
   SPtr<FileFd> CacheF;
   SPtr<DynamicMMap> Map;
   if (Writeable == true && CacheFile.empty() == false)
   {
      unlink(CacheFile.c_str());
      CacheF = new FileFd(CacheFile,FileFd::WriteEmpty);
      if (_error->PendingError() == true)
	 return false;
      fchmod(CacheF->Fd(),0644);
      Map = new DynamicMMap(*CacheF,MMap::Public,MapSize);
   }
   else
   {
      // Just build it in memory..
      Map = new DynamicMMap(MMap::Public,MapSize);
   }
   
   // Lets try the source cache.
   unsigned long CurrentSize = 0;
   unsigned long TotalSize = 0;
   if (CheckValidity(SrcCacheFile,Files.begin(),
		     Files.begin()+EndOfSource) == true)
   {
      // Preload the map with the source cache
      FileFd SCacheF(SrcCacheFile,FileFd::ReadOnly);
      if (SCacheF.Read((unsigned char *)Map->Data() + Map->RawAllocate(SCacheF.Size()),
		       SCacheF.Size()) == false)
	 return false;

      TotalSize = ComputeSize(Files.begin()+EndOfSource,Files.end());

      // CNC:2003-03-18
      // For the file provides collection phase.
      unsigned long SrcSize = ComputeSize(Files.begin(),
					  Files.begin()+EndOfSource);
      TotalSize = TotalSize+(TotalSize+SrcSize);
      
      // Build the status cache
      pkgCacheGenerator Gen(Map.Get(),&Progress);
      if (_error->PendingError() == true)
	 return false;
      if (BuildCache(Gen,Progress,CurrentSize,TotalSize,
		     Files.begin()+EndOfSource,Files.end()) == false)
	 return false;

      // CNC:2003-03-18
      if (Gen.HasFileDeps() == true) {
	 // There are new file dependencies. Collect over all packages.
	 Gen.GetCache().HeaderP->HasFileDeps = true;
	 if (CollectFileProvides(Gen,Progress,CurrentSize,TotalSize,
				 Files.begin(),Files.end()) == false)
	    return false;
      } else if (Gen.GetCache().HeaderP->HasFileDeps == true) {
	 // Jump entries which are not going to be parsed.
	 CurrentSize += SrcSize;
	 // No new file dependencies. Collect over the new packages.
	 if (CollectFileProvides(Gen,Progress,CurrentSize,TotalSize,
				 Files.begin()+EndOfSource,Files.end()) == false)
	    return false;
      }
   }
   else
   {
      TotalSize = ComputeSize(Files.begin(),Files.end());

      // CNC:2003-03-18
      // For the file provides collection phase.
      unsigned long SrcSize = ComputeSize(Files.begin(),
					  Files.begin()+EndOfSource);
      TotalSize = (TotalSize*2)+SrcSize;
      
      // Build the source cache
      pkgCacheGenerator Gen(Map.Get(),&Progress);
      if (_error->PendingError() == true)
	 return false;
      if (BuildCache(Gen,Progress,CurrentSize,TotalSize,
		     Files.begin(),Files.begin()+EndOfSource) == false)
	 return false;

      // CNC:2003-11-24
      Gen.GetCache().HeaderP->OptionsHash = _system->OptionsHash();

      // CNC:2003-03-18
      if (Gen.HasFileDeps() == true) {
	 // There are file dependencies. Collect over source packages.
	 Gen.GetCache().HeaderP->HasFileDeps = true;
	 if (CollectFileProvides(Gen,Progress,CurrentSize,TotalSize,
		     Files.begin(),Files.begin()+EndOfSource) == false)
	    return false;
	 // Reset to check for new file dependencies in the status cache.
	 Gen.ResetFileDeps();
      } else {
	 // Jump entries which are not going to be parsed.
	 CurrentSize += SrcSize;
      }
      
      // Write it back
      // CNC:2003-03-03 - Notice that it is without the file provides. This
      // is on purpose, since file requires introduced later on the status
      // cache (database) must be considered when collecting file provides,
      // even if using the sources cache (above).
      if (Writeable == true && SrcCacheFile.empty() == false)
      {
	 unlink(SrcCacheFile.c_str());
	 FileFd SCacheF(SrcCacheFile,FileFd::WriteEmpty);
	 if (_error->PendingError() == true)
	    return false;
	 fchmod(SCacheF.Fd(),0644);
	 
	 // Write out the main data
	 if (SCacheF.Write(Map->Data(),Map->Size()) == false)
	    return _error->Error(_("IO Error saving source cache"));
	 SCacheF.Sync();
	 
	 // Write out the proper header
	 Gen.GetCache().HeaderP->Dirty = false;
	 if (SCacheF.Seek(0) == false ||
	     SCacheF.Write(Map->Data(),sizeof(*Gen.GetCache().HeaderP)) == false)
	    return _error->Error(_("IO Error saving source cache"));
	 Gen.GetCache().HeaderP->Dirty = true;
	 SCacheF.Sync();
      }
      
      // Build the status cache
      if (BuildCache(Gen,Progress,CurrentSize,TotalSize,
		     Files.begin()+EndOfSource,Files.end()) == false)
	 return false;

      // CNC:2003-03-18
      if (Gen.HasFileDeps() == true) {
	 // There are new file dependencies. Collect over all packages.
	 Gen.GetCache().HeaderP->HasFileDeps = true;
	 if (CollectFileProvides(Gen,Progress,CurrentSize,TotalSize,
				 Files.begin(),Files.end()) == false)
	    return false;
      } else if (Gen.GetCache().HeaderP->HasFileDeps == true) {
	 // Jump entries which are not going to be parsed.
	 CurrentSize += SrcSize;
	 // No new file dependencies. Collect over the new packages.
	 if (CollectFileProvides(Gen,Progress,CurrentSize,TotalSize,
		     Files.begin()+EndOfSource,Files.end()) == false)
	    return false;
      }
   }

   if (_error->PendingError() == true)
      return false;
   if (OutMap != 0)
   {
      if (CacheF != 0)
      {
	 delete Map.UnGuard();
	 *OutMap = new MMap(*CacheF,MMap::Public | MMap::ReadOnly);
      }
      else
      {
	 *OutMap = Map.UnGuard();
      }      
   }

   // CNC:2003-03-07 - Signal to the system so that it can free it's
   //		       internal caches, if any.
   _system->CacheBuilt();
   
   return true;
}
									/*}}}*/
// MakeOnlyStatusCache - Build a cache with just the status files	/*{{{*/
// ---------------------------------------------------------------------
/* */
bool pkgMakeOnlyStatusCache(OpProgress &Progress,DynamicMMap **OutMap)
{
   unsigned long MapSize = _config->FindI("APT::Cache-Limit",256*1024*1024);
   vector<pkgIndexFile *> Files;
   unsigned long EndOfSource = Files.size();
   if (_system->AddStatusFiles(Files) == false)
      return false;
   
   SPtr<DynamicMMap> Map;   
   Map = new DynamicMMap(MMap::Public,MapSize);
   unsigned long CurrentSize = 0;
   unsigned long TotalSize = 0;
   
   TotalSize = ComputeSize(Files.begin()+EndOfSource,Files.end());

   // CNC:2003-03-18
   // For the file provides collection phase.
   TotalSize *= 2;
   
   // Build the status cache
   Progress.OverallProgress(0,1,1,_("Reading Package Lists"));
   pkgCacheGenerator Gen(Map.Get(),&Progress);
   if (_error->PendingError() == true)
      return false;
   if (BuildCache(Gen,Progress,CurrentSize,TotalSize,
		  Files.begin()+EndOfSource,Files.end()) == false)
      return false;

   // CNC:2003-03-18
   if (Gen.HasFileDeps() == true) {
      if (CollectFileProvides(Gen,Progress,CurrentSize,TotalSize,
			      Files.begin()+EndOfSource,Files.end()) == false)
	 return false;
   }
   
   if (_error->PendingError() == true)
      return false;
   *OutMap = Map.UnGuard();

   // CNC:2003-03-07 - Signal to the system so that it can free it's
   //		       internal caches, if any.
   _system->CacheBuilt();
   
   
   return true;
}
									/*}}}*/

// vim:sts=3:sw=3
