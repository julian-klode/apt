
/*
 ######################################################################

 RPM database and hdlist related handling

 ######################################################################
 */

#include <config.h>

#ifdef HAVE_RPM

#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <utime.h>
#include <unistd.h>
#include <signal.h>
#include <assert.h>
#include <libgen.h>
#include <cstring>
#include <sstream>
#include <algorithm>

#include <apt-pkg/error.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/md5.h>
#include <apt-pkg/crc-16.h>

#include "rpmhandler.h"
#include "rpmpackagedata.h"
#include "raptheader.h"

#ifdef APT_WITH_REPOMD
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xmlreader.h>
#include <sstream>
#include "repomd.h"
#ifdef WITH_SQLITE3
#include "sqlite.h"
#endif
#include "xmlutil.h"
#endif

#include <apti18n.h>

#include <rpm/rpmts.h>
#include <rpm/rpmdb.h>
#include <rpm/rpmds.h>
#include <rpm/rpmsq.h>

using namespace std;

// An attempt to deal with false zero epochs from repomd. With older rpm's we
// can only blindly trust the repo admin created the repository with options
// suitable for those versions. For rpm >= 4.2.1 this is linked with
// promoteepoch behavior - if promoteepoch is used then epoch hiding must
// not happen.
bool HideZeroEpoch;

static rpmds rpmlibProv = NULL;

string RPMHandler::EVR() const
{
   string e = Epoch();
   string evr = Version() + '-' + Release();

   if (!e.empty() && !(HideZeroEpoch && e == "0")) {
      e += ":";
      evr.insert(0, e);
   }
   return evr;
} 

unsigned int RPMHandler::DepOp(raptDepFlags rpmflags) const
{
   unsigned int Op = 0;
   raptDepFlags flags = (raptDepFlags)(rpmflags & RPMSENSE_SENSEMASK);
   if (flags == RPMSENSE_ANY) {
      Op = pkgCache::Dep::NoOp;
   } else if (flags & RPMSENSE_LESS) {
      if (flags & RPMSENSE_EQUAL)
	  Op = pkgCache::Dep::LessEq;
      else
	  Op = pkgCache::Dep::Less;
   } else if (flags & RPMSENSE_GREATER) {
      if (flags & RPMSENSE_EQUAL)
	  Op = pkgCache::Dep::GreaterEq;
      else
	  Op = pkgCache::Dep::Greater;
   } else if (flags & RPMSENSE_EQUAL) {
      Op = pkgCache::Dep::Equals;
   } else {
      /* can't happen, right? */
      _error->Error(_("Impossible flags %d in %s"), rpmflags, Name().c_str());
   }
      
   return Op;
}

bool RPMHandler::HasFile(const char *File) const
{
   if (*File == '\0')
      return false;
   
   vector<string> Files;
   FileList(Files);
   vector<string>::const_iterator I = find(Files.begin(), Files.end(), File);
   return (I != Files.end());
}

bool RPMHandler::InternalDep(const char *name, const char *ver, raptDepFlags flag)  const
{
   if (strncmp(name, "rpmlib(", strlen("rpmlib(")) == 0) {
     if (rpmlibProv == NULL)
         rpmdsRpmlib(&rpmlibProv, NULL);

     rpmds ds = rpmdsSingle(RPMTAG_PROVIDENAME,
			    name, ver?ver:NULL, flag);
     int res = rpmdsSearch(rpmlibProv, ds) >= 0;
     rpmdsFree(ds);
     if (res) 
	 return true;
   }

   return false; 
}

bool RPMHandler::PutDep(const char *name, const char *ver, raptDepFlags flags, 
			unsigned int Type, vector<Dependency*> &Deps) const
{
   if (InternalDep(name, ver, flags) == true) {
      return true;
   }

   if (Type == pkgCache::Dep::Depends) {
      if (flags & RPMSENSE_PREREQ)
	 Type = pkgCache::Dep::PreDepends;
      else if (flags & RPMSENSE_MISSINGOK)
	 Type = pkgCache::Dep::Suggests;
      else
	 Type = pkgCache::Dep::Depends;
   }

   Dependency *Dep = new Dependency;
   Dep->Name = name;
   Dep->Version = ver;

   if (HideZeroEpoch && Dep->Version.substr(0, 2) == "0:") {
      Dep->Version = Dep->Version.substr(2);
   }

   Dep->Op = DepOp(flags);
   Dep->Type = Type;
   Deps.push_back(Dep);
   return true;
}

string RPMHdrHandler::Epoch() const
{
   raptInt val;
   ostringstream epoch("");
   raptHeader h(HeaderP);

   if (h.getTag(RPMTAG_EPOCH, val)) {
      epoch << val;
   }
   return epoch.str();
}

off_t RPMHdrHandler::GetITag(raptTag Tag) const
{
   raptInt val = 0;
   raptHeader h(HeaderP);

   h.getTag(Tag, val); 
   return val;
}

string RPMHdrHandler::GetSTag(raptTag Tag) const
{
   string str = "";
   raptHeader h(HeaderP);

   h.getTag(Tag, str);
   return str;
}


bool RPMHdrHandler::PRCO(unsigned int Type, vector<Dependency*> &Deps) const
{
   rpmTag deptype = RPMTAG_REQUIRENAME;
   switch (Type) {
      case pkgCache::Dep::Depends:
	 deptype = RPMTAG_REQUIRENAME;
	 break;
      case pkgCache::Dep::Obsoletes:
	 deptype = RPMTAG_OBSOLETENAME;
	 break;
      case pkgCache::Dep::Conflicts:
	 deptype = RPMTAG_CONFLICTNAME;
	 break;
      case pkgCache::Dep::Provides:
	 deptype = RPMTAG_PROVIDENAME;
	 break;
      case pkgCache::Dep::Suggests:
	 deptype = RPMTAG_SUGGESTNAME;
	 break;
#if 0 // Enhances dep type is not even known to apt, sigh..
      case pkgCache::Dep::Enhances:
	 deptype = RPMTAG_ENHANCES;
	 break;
#endif
      default:
	 /* can't happen... right? */
	 return false;
	 break;
   }
   rpmds ds = NULL;
   ds = rpmdsNew(HeaderP, deptype, 0);
   if (ds != NULL) {
      while (rpmdsNext(ds) >= 0) {
	 PutDep(rpmdsN(ds), rpmdsEVR(ds), rpmdsFlags(ds), Type, Deps);
      }
   }
   rpmdsFree(ds);
   return true;
}

bool RPMHdrHandler::FileList(vector<string> &FileList) const
{
   raptHeader h(HeaderP);
   h.getTag(RPMTAG_FILENAMES, FileList);
   // it's ok for a package not have files 
   return true; 
}

bool RPMHdrHandler::ChangeLog(vector<ChangeLogEntry *> &ChangeLogs) const
{
   vector<string> names, texts;
   vector<raptInt> times;
   raptHeader h(HeaderP);

   if (h.getTag(RPMTAG_CHANGELOGTIME, times)) {
      h.getTag(RPMTAG_CHANGELOGNAME, names);
      h.getTag(RPMTAG_CHANGELOGTEXT, texts);
   
      vector<raptInt>::const_iterator timei = times.begin();
      vector<string>::const_iterator namei = names.begin();
      vector<string>::const_iterator texti = texts.begin();
      while (timei != times.end() && namei != names.end() && 
				     texti != texts.end()) {
	 ChangeLogEntry *Entry = new ChangeLogEntry;
	 Entry->Time = *(timei);
	 Entry->Author = *(namei);
	 Entry->Text = *(texti);
	 timei++; namei++; texti++;
	 ChangeLogs.push_back(Entry);
      }
   }
      
   return true;
}

RPMFileHandler::RPMFileHandler(string File)
{
   ID = File;
   FD = Fopen(File.c_str(), "r");
   if (FD == NULL)
   {
      /*
      _error->Error(_("could not open RPM package list file %s: %s"),
		    File.c_str(), rpmErrorString());
      */
      return;
   }
   iSize = fdSize(FD);
}

RPMFileHandler::RPMFileHandler(FileFd *File)
{
   FD = fdDup(File->Fd());
   if (FD == NULL)
   {
      /*
      _error->Error(_("could not create RPM file descriptor: %s"),
		    rpmErrorString());
      */
      return;
   }
   iSize = fdSize(FD);
}

RPMFileHandler::~RPMFileHandler()
{
   if (HeaderP != NULL)
      headerFree(HeaderP);
   if (FD != NULL)
      Fclose(FD);
}

bool RPMFileHandler::Skip()
{
   if (FD == NULL)
      return false;
   iOffset = lseek(Fileno(FD),0,SEEK_CUR);
   if (HeaderP != NULL)
       headerFree(HeaderP);
   HeaderP = headerRead(FD, HEADER_MAGIC_YES);
   return (HeaderP != NULL);
}

bool RPMFileHandler::Jump(off_t Offset)
{
   if (FD == NULL)
      return false;
   if (lseek(Fileno(FD),Offset,SEEK_SET) != Offset)
      return false;
   return Skip();
}

void RPMFileHandler::Rewind()
{
   if (FD == NULL)
      return;
   iOffset = lseek(Fileno(FD),0,SEEK_SET);
   if (iOffset != 0)
      _error->Error(_("could not rewind RPMFileHandler"));
}

string RPMFileHandler::FileName() const
{
   return GetSTag(CRPMTAG_FILENAME);
}

string RPMFileHandler::Directory() const
{
   return GetSTag(CRPMTAG_DIRECTORY);
}

off_t RPMFileHandler::FileSize() const
{
   return GetITag(CRPMTAG_FILESIZE);
}

string RPMFileHandler::Hash() const
{
   return GetSTag(CRPMTAG_MD5);
}

string RPMFileHandler::HashType() const
{
   return "MD5-Hash";
}

bool RPMSingleFileHandler::Skip()
{
   if (FD == NULL)
      return false;
   if (HeaderP != NULL) {
      headerFree(HeaderP);
      HeaderP = NULL;
      return false;
   }
   rpmts TS = rpmtsCreate();
   rpmtsSetVSFlags(TS, (rpmVSFlags_e)-1);
   int rc = rpmReadPackageFile(TS, FD, sFilePath.c_str(), &HeaderP);
   if (rc != RPMRC_OK && rc != RPMRC_NOTTRUSTED && rc != RPMRC_NOKEY) {
      _error->Error(_("Failed reading file %s"), sFilePath.c_str());
      HeaderP = NULL;
   }
   rpmtsFree(TS);
   return (HeaderP != NULL);
}

bool RPMSingleFileHandler::Jump(off_t Offset)
{
   assert(Offset == 0);
   Rewind();
   return RPMFileHandler::Jump(Offset);
}

void RPMSingleFileHandler::Rewind()
{
   if (FD == NULL)
      return;
   if (HeaderP != NULL) {
      HeaderP = NULL;
      headerFree(HeaderP);
   }
   lseek(Fileno(FD),0,SEEK_SET);
}

off_t RPMSingleFileHandler::FileSize() const
{
   struct stat S;
   if (stat(sFilePath.c_str(),&S) != 0)
      return 0;
   return S.st_size;
}

string RPMSingleFileHandler::Hash() const
{
   raptHash MD5(HashType());;
   FileFd File(sFilePath, FileFd::ReadOnly);
   MD5.AddFD(File.Fd(), File.Size());
   File.Close();
   return MD5.Result();
}

bool RPMSingleFileHandler::ChangeLog(vector<ChangeLogEntry* > &ChangeLogs) const
{
   return RPMHdrHandler::ChangeLog(ChangeLogs);
}

RPMDirHandler::RPMDirHandler(string DirName)
   : sDirName(DirName)
{
   ID = DirName;
   TS = NULL;
   Dir = opendir(sDirName.c_str());
   if (Dir == NULL)
      return;
   iSize = 0;
   while (nextFileName() != NULL)
      iSize += 1;
   rewinddir(Dir);
   TS = rpmtsCreate();
   rpmtsSetVSFlags(TS, (rpmVSFlags_e)-1);
}

const char *RPMDirHandler::nextFileName()
{
   for (struct dirent *Ent = readdir(Dir); Ent != 0; Ent = readdir(Dir))
   {
      const char *name = Ent->d_name;

      if (name[0] == '.')
	 continue;

      if (flExtension(name) != "rpm")
	 continue;

      // Make sure it is a file and not something else
      sFilePath = flCombine(sDirName,name);
      struct stat St;
      if (stat(sFilePath.c_str(),&St) != 0 || S_ISREG(St.st_mode) == 0)
	 continue;

      sFileName = name;
      
      return name;
   } 
   return NULL;
}

RPMDirHandler::~RPMDirHandler()
{
   if (HeaderP != NULL)
      headerFree(HeaderP);
   if (TS != NULL)
      rpmtsFree(TS);
   if (Dir != NULL)
      closedir(Dir);
}

bool RPMDirHandler::Skip()
{
   if (Dir == NULL)
      return false;
   if (HeaderP != NULL) {
      headerFree(HeaderP);
      HeaderP = NULL;
   }
   const char *fname = nextFileName();
   bool Res = false;
   for (; fname != NULL; fname = nextFileName()) {
      iOffset++;
      if (fname == NULL)
	 break;
      FD_t FD = Fopen(sFilePath.c_str(), "r");
      if (FD == NULL)
	 continue;
      int rc = rpmReadPackageFile(TS, FD, fname, &HeaderP);
      Fclose(FD);
      if (rc != RPMRC_OK
	  && rc != RPMRC_NOTTRUSTED
	  && rc != RPMRC_NOKEY)
	 continue;
      Res = true;
      break;
   }
   return Res;
}

bool RPMDirHandler::Jump(off_t Offset)
{
   if (Dir == NULL)
      return false;
   rewinddir(Dir);
   iOffset = 0;
   while (1) {
      if (iOffset+1 == Offset)
	 return Skip();
      if (nextFileName() == NULL)
	 break;
      iOffset++;
   }
   return false;
}

void RPMDirHandler::Rewind()
{
   rewinddir(Dir);
   iOffset = 0;
}

off_t RPMDirHandler::FileSize() const
{
   if (Dir == NULL)
      return 0;
   struct stat St;
   if (stat(sFilePath.c_str(),&St) != 0) {
      _error->Errno("stat",_("Unable to determine the file size"));
      return 0;
   }
   return St.st_size;
}

string RPMDirHandler::Hash() const
{
   if (Dir == NULL)
      return "";
   raptHash MD5(HashType());
   FileFd File(sFilePath, FileFd::ReadOnly);
   MD5.AddFD(File.Fd(), File.Size());
   File.Close();
   return MD5.Result();
}

string RPMDirHandler::HashType() const
{
   return "MD5-Hash";
}

RPMDBHandler::RPMDBHandler(bool WriteLock)
   : Handler(0), WriteLock(WriteLock)
{
   RpmIter = NULL;
   string Dir = _config->Find("RPM::RootDir", "/");
   
   rpmReadConfigFiles(NULL, NULL);
   ID = DataPath(false);

   RPMPackageData::Singleton()->InitMinArchScore();

   // Everytime we open a database for writing, it has its
   // mtime changed, and kills our cache validity. As we never
   // change any information in the database directly, we will
   // restore the mtime and save our cache.
   struct stat St;
   stat(DataPath(false).c_str(), &St);
   DbFileMtime = St.st_mtime;

   Handler = rpmtsCreate();
   rpmtsSetVSFlags(Handler, (rpmVSFlags_e)-1);
   rpmtsSetRootDir(Handler, Dir.c_str());

   RpmIter = raptInitIterator(Handler, RPMDBI_PACKAGES, NULL, 0);
   if (RpmIter == NULL) {
      _error->Error(_("could not create RPM database iterator"));
      return;
   }
   // iSize = rpmdbGetIteratorCount(RpmIter);
   // This doesn't seem to work right now. Code in rpm (4.0.4, at least)
   // returns a 0 from rpmdbGetIteratorCount() if raptInitIterator() is
   // called with RPMDBI_PACKAGES or with keyp == NULL. The algorithm
   // below will be used until there's support for it.
   iSize = 0;
   rpmdbMatchIterator countIt;
   countIt = raptInitIterator(Handler, RPMDBI_PACKAGES, NULL, 0);
   while (rpmdbNextIterator(countIt) != NULL)
      iSize++;
   rpmdbFreeIterator(countIt);

   // Restore just after opening the database, and just after closing.
   if (WriteLock) {
      struct utimbuf Ut;
      Ut.actime = DbFileMtime;
      Ut.modtime = DbFileMtime;
      utime(DataPath(false).c_str(), &Ut);
   }
}

RPMDBHandler::~RPMDBHandler()
{
   if (RpmIter != NULL)
      rpmdbFreeIterator(RpmIter);

   /* 
    * If termination signal, do nothing as rpmdb has already freed
    * our ts set behind our back and rpmtsFree() will crash and burn with a 
    * doublefree within rpmlib.
    * There's a WTF involved as rpmCheckSignals() actually calls exit()
    * so we shouldn't even get here really?!
    */
   if (rpmsqIsCaught(SIGINT) || 
       rpmsqIsCaught(SIGQUIT) ||
       rpmsqIsCaught(SIGHUP) ||
       rpmsqIsCaught(SIGTERM) ||
       rpmsqIsCaught(SIGPIPE)) {
      /* do nothing */
   } else if (Handler != NULL) {
      rpmtsFree(Handler);
   }

   // Restore just after opening the database, and just after closing.
   if (WriteLock) {
      struct utimbuf Ut;
      Ut.actime = DbFileMtime;
      Ut.modtime = DbFileMtime;
      utime(DataPath(false).c_str(), &Ut);
   }
}

string RPMDBHandler::DataPath(bool DirectoryOnly)
{
   string File = "Packages";
   char *tmp = (char *) rpmExpand("%{_dbpath}", NULL);
   string DBPath(_config->Find("RPM::RootDir")+tmp);
   free(tmp);

   if (DirectoryOnly == true)
       return DBPath;
   else
       return DBPath+"/"+File;
}

bool RPMDBHandler::Skip()
{
   if (RpmIter == NULL)
       return false;
   HeaderP = rpmdbNextIterator(RpmIter);
   iOffset = rpmdbGetIteratorOffset(RpmIter);
   if (HeaderP == NULL)
      return false;
   return true;
}

bool RPMDBHandler::Jump(off_t Offset)
{
   iOffset = Offset;
   // rpmdb indexes are hardcoded uint32_t, the size must match here
   raptDbOffset rpmOffset = iOffset;
   if (RpmIter == NULL)
      return false;
   rpmdbFreeIterator(RpmIter);
   if (iOffset == 0)
      RpmIter = raptInitIterator(Handler, RPMDBI_PACKAGES, NULL, 0);
   else {
      RpmIter = raptInitIterator(Handler, RPMDBI_PACKAGES,
				  &rpmOffset, sizeof(rpmOffset));
      iOffset = rpmOffset;
   }
   HeaderP = rpmdbNextIterator(RpmIter);
   return true;
}

bool RPMDBHandler::JumpByName(string PkgName, bool Provides)
{
   raptTag tag = (raptTag)(Provides ? RPMTAG_PROVIDES : RPMDBI_LABEL);
   if (RpmIter == NULL) return false;
   rpmdbFreeIterator(RpmIter);
   RpmIter = raptInitIterator(Handler, tag, PkgName.c_str(), 0);
   HeaderP = rpmdbNextIterator(RpmIter);
   return (HeaderP != NULL);
}

void RPMDBHandler::Rewind()
{
   if (RpmIter == NULL)
      return;
   rpmdbFreeIterator(RpmIter);   
   RpmIter = raptInitIterator(Handler, RPMDBI_PACKAGES, NULL, 0);
   iOffset = 0;
}
#endif

#ifdef APT_WITH_REPOMD
RPMRepomdHandler::RPMRepomdHandler(repomdXML const *repomd): RPMHandler(),
      Primary(NULL), Root(NULL), HavePrimary(false)
{
   ID = repomd->ID();
   // Try to figure where in the world our files might be... 
   string base = ID.substr(0, ID.size() - strlen("repomd.xml"));
   PrimaryPath = base + flNotDir(repomd->FindURI("primary"));
   FilelistPath = base + flNotDir(repomd->FindURI("filelists"));
   OtherPath = base + flNotDir(repomd->FindURI("other"));

   xmlTextReaderPtr Index;
   Index = xmlReaderForFile(PrimaryPath.c_str(), NULL,
                          XML_PARSE_NONET|XML_PARSE_NOBLANKS);
   if (Index == NULL) {
      _error->Error(_("Failed to open package index %s"), PrimaryPath.c_str());
      return;
   }

   if (xmlTextReaderRead(Index) == 1) {
      xmlChar *pkgs = xmlTextReaderGetAttribute(Index, (xmlChar*)"packages");
      iSize = atoi((char*)pkgs);
      xmlFree(pkgs);
   } else {
      iSize = 0;
   }
   xmlFreeTextReader(Index);

}

bool RPMRepomdHandler::LoadPrimary()
{
   xmlChar *packages = NULL;
   off_t pkgcount = 0;

   Primary = xmlReadFile(PrimaryPath.c_str(), NULL, XML_PARSE_NONET|XML_PARSE_NOBLANKS);
   if ((Root = xmlDocGetRootElement(Primary)) == NULL) {
      _error->Error(_("Failed to open package index %s"), PrimaryPath.c_str());
      goto error;
   }
   if (xmlStrncmp(Root->name, (xmlChar*)"metadata", strlen("metadata")) != 0) {
      _error->Error(_("Corrupted package index %s"), PrimaryPath.c_str());
      goto error;
   }

   packages = xmlGetProp(Root, (xmlChar*)"packages");
   iSize = atoi((char*)packages);
   xmlFree(packages);
   for (xmlNode *n = Root->children; n; n = n->next) {
      if (n->type != XML_ELEMENT_NODE ||
          xmlStrcmp(n->name, (xmlChar*)"package") != 0)
         continue;
      Pkgs.push_back(n);
      pkgcount++;
   }
   PkgIter = Pkgs.begin();

   // There seem to be broken version(s) of createrepo around which report
   // to have one more package than is in the repository. Warn and work around.
   if (iSize != pkgcount) {
      _error->Warning(_("Inconsistent metadata, package count doesn't match in %s"), ID.c_str());
      iSize = pkgcount;
   }
   HavePrimary = true;

   return true;

error:
   if (Primary) {
      xmlFreeDoc(Primary);
   }
   return false;
}

bool RPMRepomdHandler::Skip()
{
   if (HavePrimary == false) {
      LoadPrimary();
   }
   if (PkgIter == Pkgs.end()) {
      return false;
   }
   NodeP = *PkgIter;
   iOffset = PkgIter - Pkgs.begin();

   PkgIter++;
   return true;
}

bool RPMRepomdHandler::Jump(off_t Offset)
{
   if (HavePrimary == false) {
      LoadPrimary();
   }
   if (Offset >= iSize) {
      return false;
   }
   iOffset = Offset;
   NodeP = Pkgs[Offset];
   // This isn't strictly necessary as Skip() and Jump() aren't mixed
   // in practise but doesn't hurt either...
   PkgIter = Pkgs.begin() + Offset + 1;
   return true;

}

void RPMRepomdHandler::Rewind()
{
   iOffset = 0;
   PkgIter = Pkgs.begin();
}

string RPMRepomdHandler::Name() const
{
   return XmlFindNodeContent(NodeP, "name");
}

string RPMRepomdHandler::Arch() const
{
   return XmlFindNodeContent(NodeP, "arch");
}

string RPMRepomdHandler::Packager() const
{
   return XmlFindNodeContent(NodeP, "packager");
}

string RPMRepomdHandler::Summary() const
{
   return XmlFindNodeContent(NodeP, "summary");
}

string RPMRepomdHandler::Description() const
{
   return XmlFindNodeContent(NodeP, "description");
}

string RPMRepomdHandler::Group() const
{
   xmlNode *n = XmlFindNode(NodeP, "format");
   return XmlFindNodeContent(n, "group");
}

string RPMRepomdHandler::Vendor() const
{
   xmlNode *n = XmlFindNode(NodeP, "format");
   return XmlFindNodeContent(n, "vendor");
}

string RPMRepomdHandler::Release() const
{
   xmlNode *n = XmlFindNode(NodeP, "version");
   return XmlGetProp(n, "rel");
}

string RPMRepomdHandler::Version() const
{
   xmlNode *n = XmlFindNode(NodeP, "version");
   return XmlGetProp(n, "ver");
}

string RPMRepomdHandler::Epoch() const
{
   string epoch;
   xmlNode *n = XmlFindNode(NodeP, "version");
   epoch = XmlGetProp(n, "epoch");
   // XXX createrepo stomps epoch zero on packages without epoch, hide
   // them. Rpm treats zero and empty equally anyway so it doesn't matter.
   if (epoch == "0")
      epoch = "";
   return epoch;
}

string RPMRepomdHandler::FileName() const
{
   xmlNode *n;
   string str = "";
   if ((n = XmlFindNode(NodeP, "location"))) {
      xmlChar *prop = xmlGetProp(n, (xmlChar*)"href");
      str = basename((char*)prop);
      xmlFree(prop);
   }
   return str;
}

string RPMRepomdHandler::Directory() const
{
   xmlNode *n;
   string str = "";
   if ((n = XmlFindNode(NodeP, "location"))) {
      xmlChar *prop = xmlGetProp(n, (xmlChar*)"href");
      if (prop) {
	 str = dirname((char*)prop);
	 xmlFree(prop);
      }
   }
   return str;
}

string RPMRepomdHandler::Hash() const
{
   xmlNode *n;
   string str = "";
   if ((n = XmlFindNode(NodeP, "checksum"))) {
      xmlChar *content = xmlNodeGetContent(n);
      str = (char*)content;
      xmlFree(content);
   }
   return str;
}

string RPMRepomdHandler::HashType() const
{
   xmlNode *n;
   string str = "";
   if ((n = XmlFindNode(NodeP, "checksum"))) {
      xmlChar *prop = xmlGetProp(n, (xmlChar*)"type");
      str = (char*)prop;
      xmlFree(prop);
   }
   return chk2hash(str);
}

off_t RPMRepomdHandler::FileSize() const
{
   xmlNode *n;
   off_t size = 0;
   if ((n = XmlFindNode(NodeP, "size"))) {
      xmlChar *prop = xmlGetProp(n, (xmlChar*)"package");
      size = atol((char*)prop);
      xmlFree(prop);
   } 
   return size;
}

off_t RPMRepomdHandler::InstalledSize() const
{
   xmlNode *n;
   off_t size = 0;
   if ((n = XmlFindNode(NodeP, "size"))) {
      xmlChar *prop = xmlGetProp(n, (xmlChar*)"installed");
      size = atol((char*)prop);
      xmlFree(prop);
   } 
   return size;
}

string RPMRepomdHandler::SourceRpm() const
{
   xmlNode *n = XmlFindNode(NodeP, "format");
   return XmlFindNodeContent(n, "sourcerpm");
}

bool RPMRepomdHandler::PRCO(unsigned int Type, vector<Dependency*> &Deps) const
{
   xmlNode *format = XmlFindNode(NodeP, "format");
   xmlNode *prco = NULL;

   switch (Type) {
      case pkgCache::Dep::Depends:
         prco = XmlFindNode(format, "requires");
         break;
      case pkgCache::Dep::Conflicts:
         prco = XmlFindNode(format, "conflicts");
         break;
      case pkgCache::Dep::Obsoletes:
         prco = XmlFindNode(format, "obsoletes");
         break;
      case pkgCache::Dep::Provides:
         prco = XmlFindNode(format, "provides");
         break;
   }

   if (! prco) {
      return true;
   }
   for (xmlNode *n = prco->children; n; n = n->next) {
      unsigned int RpmOp = 0;
      string deptype, depver;
      xmlChar *depname, *flags;
      if ((depname = xmlGetProp(n, (xmlChar*)"name")) == NULL) continue;

      if ((flags = xmlGetProp(n, (xmlChar*)"flags"))) {
         deptype = string((char*)flags);
	 xmlFree(flags);

         xmlChar *epoch = xmlGetProp(n, (xmlChar*)"epoch");
         if (epoch) {
            depver += string((char*)epoch) + ":";
	    xmlFree(epoch);
	 }
         xmlChar *ver = xmlGetProp(n, (xmlChar*)"ver");
         if (ver) {
            depver += string((char*)ver);
	    xmlFree(ver);
	 }
         xmlChar *rel = xmlGetProp(n, (xmlChar*)"rel");
         if (rel) {
            depver += "-" + string((char*)rel);
	    xmlFree(rel);
	 }


         if (deptype == "EQ") {
	    RpmOp = RPMSENSE_EQUAL;
	 } else if (deptype == "GE") {
	    RpmOp = RPMSENSE_GREATER | RPMSENSE_EQUAL;
	 } else if (deptype == "GT") {
	    RpmOp = RPMSENSE_GREATER;
	 } else if (deptype == "LE") {
	    RpmOp = RPMSENSE_LESS | RPMSENSE_EQUAL;
	 } else if (deptype == "LT") {
	    RpmOp = RPMSENSE_LESS;
	 } else {
	    // wtf, unknown dependency type?
	    _error->Warning(_("Ignoring unknown dependency type %s"), 
			      deptype.c_str());
	    continue;
	 }
      } else {
	 RpmOp = RPMSENSE_ANY;
      }

      if (Type == pkgCache::Dep::Depends) {
	 xmlChar *pre = xmlGetProp(n, (xmlChar*)"pre"); 
	 if (pre) {
	    RpmOp |= RPMSENSE_PREREQ;
	    xmlFree(pre);
	 }
      }
      PutDep((char*)depname, depver.c_str(), (raptDepFlags) RpmOp, Type, Deps);
      xmlFree(depname);
   }
   return true;
}

// XXX HasFile() usage with repomd with full filelists is slower than
// having the user manually look it up, literally. So we only support the 
// more common files which are stored in primary.xml which supports fast
// random access.
bool RPMRepomdHandler::HasFile(const char *File) const
{
   if (*File == '\0')
      return false;
   
   vector<string> Files;
   ShortFileList(Files);
   vector<string>::const_iterator I = find(Files.begin(), Files.end(), File);
   return (I != Files.end());
}

bool RPMRepomdHandler::ShortFileList(vector<string> &FileList) const
{
   xmlNode *format = XmlFindNode(NodeP, "format");
   for (xmlNode *n = format->children; n; n = n->next) {
      if (xmlStrcmp(n->name, (xmlChar*)"file") != 0)  continue;
      xmlChar *Filename = xmlNodeGetContent(n);
      FileList.push_back(string((char*)Filename));
      xmlFree(Filename);
   }
   return true;
}

bool RPMRepomdHandler::FileList(vector<string> &FileList) const
{
   RPMRepomdFLHandler *FL = new RPMRepomdFLHandler(FilelistPath);
   bool res = FL->Jump(iOffset);
   res &= FL->FileList(FileList);
   delete FL;
   return res; 
}

bool RPMRepomdHandler::ChangeLog(vector<ChangeLogEntry* > &ChangeLogs) const
{
   RPMRepomdOtherHandler *OL = new RPMRepomdOtherHandler(OtherPath);
   bool res = OL->Jump(iOffset);
   res &= OL->ChangeLog(ChangeLogs);
   delete OL;
   return res; 
}

RPMRepomdHandler::~RPMRepomdHandler()
{
   xmlFreeDoc(Primary);
}

RPMRepomdReaderHandler::RPMRepomdReaderHandler(string File) : RPMHandler(),
   XmlFile(NULL), XmlPath(File), NodeP(NULL)
{
   ID = File;
   iOffset = -1;

   if (FileExists(XmlPath)) {
      XmlFile = xmlReaderForFile(XmlPath.c_str(), NULL,
                                  XML_PARSE_NONET|XML_PARSE_NOBLANKS);
      if (XmlFile == NULL) {
        xmlFreeTextReader(XmlFile);
        _error->Error(_("Failed to open filelist index %s"), XmlPath.c_str());
        goto error;
      }

      // seek into first package in xml
      int ret = xmlTextReaderRead(XmlFile);
      if (ret == 1) {
        xmlChar *pkgs = xmlTextReaderGetAttribute(XmlFile, (xmlChar*)"packages");
        iSize = atoi((char*)pkgs);
        xmlFree(pkgs);
      }
      while (ret == 1) {
        if (xmlStrcmp(xmlTextReaderConstName(XmlFile),
                     (xmlChar*)"package") == 0) {
           break;
        }
        ret = xmlTextReaderRead(XmlFile);
      }
   }
   return;

error:
   if (XmlFile) {
       xmlFreeTextReader(XmlFile);
   }
}

bool RPMRepomdReaderHandler::Jump(off_t Offset)
{
   bool res = false;
   while (iOffset != Offset) {
      res = Skip();
      if (res == false)
	 break;
   }
      
   return res;
}

void RPMRepomdReaderHandler::Rewind()
{
   // XXX Ignore rewinds when already at start, any other cases we can't
   // handle at the moment. Other cases shouldn't be needed due to usage
   // patterns but just in case...
   if (iOffset != -1) {
      _error->Error(_("Internal error: xmlReader cannot rewind"));
   }
}

bool RPMRepomdReaderHandler::Skip()
{
   if (iOffset +1 >= iSize) {
      return false;
   }
   if (iOffset >= 0) {
      xmlTextReaderNext(XmlFile);
   }
   NodeP = xmlTextReaderExpand(XmlFile);
   iOffset++;

   return true;
}

string RPMRepomdReaderHandler::FindTag(const char *Tag) const
{
   string str = "";
   if (NodeP) {
       xmlChar *attr = xmlGetProp(NodeP, (xmlChar*)Tag);
       if (attr) {
          str = (char*)attr;
          xmlFree(attr);
       }
   }
   return str;
}

string RPMRepomdReaderHandler::FindVerTag(const char *Tag) const
{
   string str = "";
   for (xmlNode *n = NodeP->children; n; n = n->next) {
      if (xmlStrcmp(n->name, (xmlChar*)"version") != 0)  continue;
      xmlChar *attr = xmlGetProp(n, (xmlChar*)Tag);
      if (attr) {
	 str = (char*)attr;
	 xmlFree(attr);
      }
   }
   return str;
}

RPMRepomdReaderHandler::~RPMRepomdReaderHandler()
{
   xmlFreeTextReader(XmlFile);
}

bool RPMRepomdFLHandler::FileList(vector<string> &FileList) const
{
   for (xmlNode *n = NodeP->children; n; n = n->next) {
      if (xmlStrcmp(n->name, (xmlChar*)"file") != 0)  continue;
      xmlChar *Filename = xmlNodeGetContent(n);
      FileList.push_back(string((char*)Filename));
      xmlFree(Filename);
   }
   return true;
}

bool RPMRepomdOtherHandler::ChangeLog(vector<ChangeLogEntry* > &ChangeLogs) const
{
   // Changelogs aren't necessarily available at all
   if (! XmlFile) {
      return false;
   }

   for (xmlNode *n = NodeP->children; n; n = n->next) {
      if (xmlStrcmp(n->name, (xmlChar*)"changelog") != 0)  continue;
      ChangeLogEntry *Entry = new ChangeLogEntry;
      xmlChar *Text = xmlNodeGetContent(n);
      xmlChar *Time = xmlGetProp(n, (xmlChar*)"date");
      xmlChar *Author = xmlGetProp(n, (xmlChar*)"author");
      Entry->Text = string((char*)Text);
      Entry->Time = atoi((char*)Time);
      Entry->Author = string((char*)Author);
      ChangeLogs.push_back(Entry);
      xmlFree(Text);
      xmlFree(Time);
      xmlFree(Author);
   }
   return true;
}

#ifdef WITH_SQLITE3
static SqliteQuery * prcoQuery(SqliteDB *db, const string & what)
{
   ostringstream sql;
   sql << "select name, flags, epoch, version, release from " << what << " where pkgKey = ?" << endl;
   return db->Query(sql.str());
}

RPMSqliteHandler::RPMSqliteHandler(repomdXML const *repomd) : 
   Primary(NULL), Filelists(NULL), Other(NULL),
   Packages(NULL), Provides(NULL), Requires(NULL), Conflicts(NULL), Obsoletes(NULL),
   Files(NULL), Changes(NULL)
   
{
   ID = repomd->ID();
   // Try to figure where in the world our files might be... 
   string base = ID.substr(0, ID.size() - strlen("repomd.xml"));
   DBPath = base + flNotDir(repomd->FindURI("primary_db"));
   FilesDBPath = base + flNotDir(repomd->FindURI("filelists_db"));
   OtherDBPath = base + flNotDir(repomd->FindURI("other_db"));

   Primary = new SqliteDB(DBPath);
   Primary->Exclusive(true);

   // see if it's a db scheme we support
   SqliteQuery *DBI = Primary->Query("select * from db_info");
   DBI->Step();
   DBVersion = DBI->GetColI("dbversion");
   delete DBI;
   if (DBVersion < 10) {
      _error->Error(_("Unsupported database scheme (%d)"), DBVersion);
      return;
   } 

   // XXX TODO: We dont need all of these on cache generation 
   Packages = Primary->Query("select pkgKey, pkgId, name, arch, version, epoch, release, summary, description, rpm_vendor, rpm_group, rpm_sourcerpm, rpm_packager, size_package, size_installed, location_href from packages");

   Provides = prcoQuery(Primary, "provides");
   Requires = prcoQuery(Primary, "requires");
   Conflicts = prcoQuery(Primary, "conflicts");;
   Obsoletes = prcoQuery(Primary, "obsoletes");

   Filelists = new SqliteDB(FilesDBPath);
   Filelists->Exclusive(true);
   Files = Filelists->Query("select dirname, filenames from filelist where pkgKey=?");

   // XXX open these only if needed? 
   if (FileExists(OtherDBPath)) {
      Other = new SqliteDB(OtherDBPath);
      Other->Exclusive(true);
      Changes = Other->Query("select * from changelog where pkgKey=?");
   }

   DBI = Primary->Query("select count(pkgId) as numpkgs from packages");
   DBI->Step();
   iSize = DBI->GetColI("numpkgs");
   delete DBI;
}

RPMSqliteHandler::~RPMSqliteHandler()
{
   if (Packages) delete Packages;
   if (Provides) delete Provides;
   if (Requires) delete Requires;
   if (Conflicts) delete Conflicts;
   if (Obsoletes) delete Obsoletes;
   if (Files) delete Files;
   if (Changes) delete Changes;
   if (Primary) delete Primary;
   if (Filelists) delete Filelists;
   if (Other) delete Other;
}


bool RPMSqliteHandler::Skip()
{
   bool res = Packages->Step();
   if (res)
      iOffset++;
   return res;
}

bool RPMSqliteHandler::Jump(off_t Offset)
{
   Rewind();
   while (1) {
      if (iOffset + 1 == Offset)
	 return Skip();
      if (Skip() == false)
	 break;
   }
   return false;
}

void RPMSqliteHandler::Rewind()
{
   Packages->Rewind();
   iOffset = 0;
}

string RPMSqliteHandler::Name() const
{
   return Packages->GetCol("name");
}

string RPMSqliteHandler::Version() const
{
   return Packages->GetCol("version");
}

string RPMSqliteHandler::Release() const
{
   return Packages->GetCol("release");
}

string RPMSqliteHandler::Epoch() const
{
   return Packages->GetCol("epoch");
}

string RPMSqliteHandler::Arch() const
{
   return Packages->GetCol("arch");
}

string RPMSqliteHandler::Group() const
{
   return Packages->GetCol("rpm_group");
}

string RPMSqliteHandler::Packager() const
{
   return Packages->GetCol("rpm_packager");
}
string RPMSqliteHandler::Vendor() const
{
   return Packages->GetCol("rpm_vendor");
}

string RPMSqliteHandler::Summary() const
{
   return Packages->GetCol("summary");
}

string RPMSqliteHandler::Description() const
{
   return Packages->GetCol("description");
}

string RPMSqliteHandler::SourceRpm() const
{
   return Packages->GetCol("rpm_sourcerpm");
}

string RPMSqliteHandler::FileName() const
{
   return flNotDir(Packages->GetCol("location_href"));
}

string RPMSqliteHandler::Directory() const
{
   return flNotFile(Packages->GetCol("location_href"));
}

off_t RPMSqliteHandler::FileSize() const
{
   return Packages->GetColI("size_package");
}

off_t RPMSqliteHandler::InstalledSize() const
{
   return Packages->GetColI("size_installed");
}

string RPMSqliteHandler::Hash() const
{
   return Packages->GetCol("pkgId");
}

string RPMSqliteHandler::HashType() const
{
   return chk2hash(Packages->GetCol("checksum_type"));
}

bool RPMSqliteHandler::PRCO(unsigned int Type, vector<Dependency*> &Deps) const
{
   SqliteQuery *prco = NULL;
   switch (Type) {
      case pkgCache::Dep::Depends:
	 prco = Requires;
         break;
      case pkgCache::Dep::Conflicts:
	 prco = Conflicts;
         break;
      case pkgCache::Dep::Obsoletes:
	 prco = Obsoletes;
         break;
      case pkgCache::Dep::Provides:
	 prco = Provides;
         break;
   }

   unsigned long pkgKey;
   Packages->Get("pkgKey", pkgKey);
   if (!(prco->Rewind() && prco->Bind(1, pkgKey)))
      return false;
   
   string deptype, depver, depname;
   string e, v, r;

   while (prco->Step()) {
      unsigned int RpmOp = 0;

      depname.clear(); deptype.clear(); depver.clear();

      prco->Get("flags", deptype);
      if (deptype.empty()) {
	 RpmOp = RPMSENSE_ANY;
      } else {
	 if (deptype == "EQ") {
	    RpmOp = RPMSENSE_EQUAL;
	 } else if (deptype == "GE") {
	    RpmOp = RPMSENSE_GREATER | RPMSENSE_EQUAL;
	 } else if (deptype == "GT") {
	    RpmOp = RPMSENSE_GREATER;
	 } else if (deptype == "LE") {
	    RpmOp = RPMSENSE_LESS | RPMSENSE_EQUAL;
	 } else if (deptype == "LT") {
	    RpmOp = RPMSENSE_LESS;
	 } else {
	    // wtf, unknown dependency type?
	    _error->Warning(_("Ignoring unknown dependency type %s"), 
			      deptype.c_str());
	    continue;
	 }
	 e.clear(); v.clear(); r.clear();

	 prco->Get("epoch", e);
	 prco->Get("version", v);
	 prco->Get("release", r);
	 if (! e.empty()) {
	    depver += e;
	    depver += ":";
	 }
	 if (! v.empty()) {
	    depver += v;
	 }
	 if (! r.empty()) {
	    depver += "-";
	    depver += r;
	 }
      }
      prco->Get("name", depname);
      PutDep(depname.c_str(), depver.c_str(), (raptDepFlags) RpmOp, Type, Deps);
   }
   return true;
}

bool RPMSqliteHandler::FileList(vector<string> &FileList) const
{
   unsigned long pkgKey;
   string dir, filenames, fn;

   Packages->Get("pkgKey", pkgKey);
   Files->Rewind();
   if (!(Files->Rewind() && Files->Bind(1, pkgKey)))
      return false;

   while (Files->Step()) {
      Files->Get("dirname", dir);
      Files->Get("filenames", filenames);
      string::size_type end, start = 0;
      dir += "/";

      do {
	 end = filenames.find_first_of("/", start);
	 fn = dir;
	 fn += (end == string::npos) ? filenames.substr(start) :
				       filenames.substr(start, end - start);
	 FileList.push_back(fn);
	 start = end + 1;
      } while (end != string::npos);
   }
   return true;
}

bool RPMSqliteHandler::ChangeLog(vector<ChangeLogEntry* > &ChangeLogs) const
{
   unsigned long pkgKey;
   Packages->Get("pkgKey", pkgKey);

   if (!(Changes && Changes->Rewind() && Changes->Bind(1, pkgKey)))
      return false;

   while (Changes->Step()) {
      ChangeLogEntry *Entry = new ChangeLogEntry;
      Entry->Time = Changes->GetColI("date");
      Entry->Author = Changes->GetCol("author");
      Entry->Text = Changes->GetCol("changelog");
      ChangeLogs.push_back(Entry);
   }
   return true;
}
#endif /* WITH_SQLITE3 */

#endif /* APT_WITH_REPOMD */


// vim:sts=3:sw=3
