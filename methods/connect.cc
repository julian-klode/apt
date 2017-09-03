// -*- mode: cpp; mode: fold -*-
// Description								/*{{{*/
// $Id: connect.cc,v 1.10.2.1 2004/01/16 18:58:50 mdz Exp $
/* ######################################################################

   Connect - Replacement connect call

   This was originally authored by Jason Gunthorpe <jgg@debian.org>
   and is placed in the Public Domain, do with it what you will.
      
   ##################################################################### */
									/*}}}*/
// Include Files							/*{{{*/
#include <config.h>

#include <apt-pkg/acquire-method.h>
#include <apt-pkg/configuration.h>
#include <apt-pkg/error.h>
#include <apt-pkg/fileutl.h>
#include <apt-pkg/srvrec.h>
#include <apt-pkg/strutl.h>

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include <set>
#include <sstream>
#include <string>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// Internet stuff
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "aptmethod.h"
#include "connect.h"
#include "rfc2553emu.h"
#include <apti18n.h>
									/*}}}*/

static std::string LastHost;
static int LastPort = 0;
static struct addrinfo *LastHostAddr = 0;
static struct addrinfo *LastUsed = 0;

static std::vector<SrvRec> SrvRecords;

// Set of IP/hostnames that we timed out before or couldn't resolve
static std::set<std::string> bad_addr;

// RotateDNS - Select a new server from a DNS rotation			/*{{{*/
// ---------------------------------------------------------------------
/* This is called during certain errors in order to recover by selecting a 
   new server */
void RotateDNS()
{
   if (LastUsed != 0 && LastUsed->ai_next != 0)
      LastUsed = LastUsed->ai_next;
   else
      LastUsed = LastHostAddr;
}
									/*}}}*/
static bool ConnectionAllowed(char const * const Service, std::string const &Host)/*{{{*/
{
   if (unlikely(Host.empty())) // the only legal empty host (RFC2782 '.' target) is detected by caller
      return false;
   if (APT::String::Endswith(Host, ".onion") && _config->FindB("Acquire::BlockDotOnion", true))
   {
      // TRANSLATOR: %s is e.g. Tor's ".onion" which would likely fail or leak info (RFC7686)
      _error->Error(_("Direct connection to %s domains is blocked by default."), ".onion");
      if (strcmp(Service, "http") == 0)
	_error->Error(_("If you meant to use Tor remember to use %s instead of %s."), "tor+http", "http");
      return false;
   }
   return true;
}
									/*}}}*/

// File Descriptor based Fd /*{{{*/
struct FdFd : public MethodFd
{
   int fd = -1;
   int Fd() APT_OVERRIDE { return fd; }
   ssize_t Read(void *buf, size_t count) APT_OVERRIDE { return ::read(fd, buf, count); }
   ssize_t Write(void *buf, size_t count) APT_OVERRIDE { return ::write(fd, buf, count); }
   int Close() APT_OVERRIDE
   {
      int result = 0;
      if (fd != -1)
	 result = ::close(fd);
      fd = -1;
      return result;
   }
};

bool MethodFd::HasPending()
{
   return false;
}
std::unique_ptr<MethodFd> MethodFd::FromFd(int iFd)
{
   FdFd *fd = new FdFd();
   fd->fd = iFd;
   return std::unique_ptr<MethodFd>(fd);
}
									/*}}}*/
// DoConnect - Attempt a connect operation				/*{{{*/
// ---------------------------------------------------------------------
/* This helper function attempts a connection to a single address. */
static bool AssignBlame(int Fd, std::string const &Host, const char *Name, const char *Service, aptMethod *Owner)
{
   // Check the socket for an error condition
   unsigned int Err;
   unsigned int Len = sizeof(Err);
   if (getsockopt(Fd, SOL_SOCKET, SO_ERROR, &Err, &Len) != 0)
      return _error->Errno("getsockopt", _("Failed"));

   if (Err != 0)
   {
      errno = Err;
      if (errno == ECONNREFUSED)
	 Owner->SetFailReason("ConnectionRefused");
      else if (errno == ETIMEDOUT)
	 Owner->SetFailReason("ConnectionTimedOut");
      bad_addr.insert(bad_addr.begin(), std::string(Name));
      return _error->Errno("connect", _("Could not connect to %s:%s (%s)."), Host.c_str(),
			   Service, Name);
   }

   return true;
}
static bool DoConnect(struct addrinfo *Addr6, struct addrinfo *Addr4, std::string const &Host,
		      unsigned long TimeOut, std::unique_ptr<MethodFd> &Fd, aptMethod *Owner)
{
   // Show a status indicator
   char Name6[NI_MAXHOST];
   char Service6[NI_MAXSERV];
   char Name4[NI_MAXHOST];
   char Service4[NI_MAXSERV];
   std::unique_ptr<FdFd> fd6(new FdFd());
   std::unique_ptr<FdFd> fd4(new FdFd());

   Name6[0] = 0;
   Service6[0] = 0;
   Name4[0] = 0;
   Service4[0] = 0;
   if (Addr6 != nullptr)
      getnameinfo(Addr6->ai_addr, Addr6->ai_addrlen,
		  Name6, sizeof(Name6), Service6, sizeof(Service6),
		  NI_NUMERICHOST | NI_NUMERICSERV);
   if (Addr4 != nullptr)
      getnameinfo(Addr4->ai_addr, Addr4->ai_addrlen,
		  Name4, sizeof(Name4), Service4, sizeof(Service4),
		  NI_NUMERICHOST | NI_NUMERICSERV);
   if (*Name6 && *Name4)
      Owner->Status(_("Connecting to %s (%s, %s)"), Host.c_str(), Name6, Name4);
   else if (*Name6)
      Owner->Status(_("Connecting to %s (%s)"), Host.c_str(), Name6);
   else if (*Name4)
      Owner->Status(_("Connecting to %s (%s)"), Host.c_str(), Name4);

   // if that addr did timeout before, we do not try it again
   if (bad_addr.find(std::string(Name6)) != bad_addr.end() && bad_addr.find(std::string(Name4)) != bad_addr.end())
      return false;

   /* If this is an IP rotation store the IP we are using.. If something goes
      wrong this will get tacked onto the end of the error message */
   if (LastHostAddr->ai_next != 0)
   {
      std::stringstream ss;
      ioprintf(ss, _("[IP: %s,%s %s,%s]"), Name6, Name4, Service6, Service4);
      Owner->SetIP(ss.str());
   }
      
   // Get a socket
   if (Addr6 != nullptr && (fd6->fd = socket(Addr6->ai_family, Addr6->ai_socktype, Addr6->ai_protocol)) < 0)
   {
      _error->Errno("socket", _("Could not create a socket for %s (f=%u t=%u p=%u)"),
		    Name6, Addr6->ai_family, Addr6->ai_socktype, Addr6->ai_protocol);
   }

   if (Addr4 != nullptr && (fd4->fd = socket(Addr4->ai_family, Addr4->ai_socktype, Addr4->ai_protocol)) < 0)
   {
      _error->Errno("socket", _("Could not create a socket for %s (f=%u t=%u p=%u)"),
		    Name4, Addr4->ai_family, Addr4->ai_socktype, Addr4->ai_protocol);
   }

   if (fd6->Fd() != -1)
      SetNonBlock(fd6->Fd(), true);
   if (fd4->Fd() != -1)
      SetNonBlock(fd4->Fd(), true);

   fd_set Set;
   struct timeval fallbackTimeout = {
       .tv_sec = 0,
       .tv_usec = 300 * 1000,
   };
   struct timeval normalTimeout = {
       .tv_sec = (time_t)TimeOut,
       .tv_usec = 0,
   };
   FD_ZERO(&Set);

   if (fd6->Fd() != -1)
   {
      if (connect(fd6->Fd(), Addr6->ai_addr, Addr6->ai_addrlen) < 0 &&
	  errno != EINPROGRESS)
      {
	 fd6->Close();
	 _error->Errno("connect", _("Cannot initiate the connection "
				    "to %s:%s (%s)."),
		       Host.c_str(), Service6, Name6);
      }
   }

   if (fd6->Fd() != -1)
   {

      FD_SET(fd6->Fd(), &Set);
      int Res;
      do
      {
	 Res = select(fd6->Fd() + 1, 0, &Set, 0, &fallbackTimeout);
      } while (Res < 0 && errno == EINTR);
   }

   if (fd4->Fd() != -1 && (fd6->Fd() == -1 || !FD_ISSET(fd6->Fd(), &Set)))
   {
      if (connect(fd4->Fd(), Addr4->ai_addr, Addr4->ai_addrlen) < 0 &&
	  errno != EINPROGRESS)
      {
	 fd4->Close();
	 _error->Errno("connect", _("Cannot initiate the connection "
				    "to %s:%s (%s)."),
		       Host.c_str(), Service4, Name4);
      }
   }
   else
   {
      fd4->Close();
   }

   // Wait for both IPv6 and IPv4 connection
   int Res = 0;
   if (fd6->Fd() != -1 || fd4->Fd() != -1)
   {
      if (fd6->Fd() != -1)
	 FD_SET(fd6->Fd(), &Set);
      if (fd4->Fd() != -1)
	 FD_SET(fd4->Fd(), &Set);
      do
      {
	 Res = select(MAX(fd6->Fd(), fd4->Fd()) + 1, 0, &Set, 0, &normalTimeout);
      } while (Res < 0 && errno == EINTR);
   }

   if (Res <= 0)
   {
      if (*Name6)
	 bad_addr.insert(bad_addr.begin(), std::string(Name6));
      if (*Name4)
	 bad_addr.insert(bad_addr.begin(), std::string(Name4));
      Owner->SetFailReason("Timeout");
      return _error->Error(_("Could not connect to %s:(%s,%s) (%s, %s), "
			     "connection timed out"),
			   Host.c_str(), Service6, Service4, Name6, Name4);
   }

   if (fd6->Fd() != -1 && AssignBlame(fd6->Fd(), Host, Name6, Service6, Owner))
   {
      Owner->SetFailReason("");
      _error->Discard();
      Fd = std::move(fd6);
      return true;
   }
   if (fd4->Fd() != -1 && AssignBlame(fd4->Fd(), Host, Name4, Service4, Owner))
   {
      Owner->SetFailReason("");
      _error->Discard();
      Fd = std::move(fd4);
      return true;
   }

   return false;
}

									/*}}}*/
// Connect to a given Hostname						/*{{{*/
static bool ConnectToHostname(std::string const &Host, int const Port,
			      const char *const Service, int DefPort, std::unique_ptr<MethodFd> &Fd,
			      unsigned long const TimeOut, aptMethod *const Owner)
{
   if (ConnectionAllowed(Service, Host) == false)
      return false;
   // Convert the port name/number
   char ServStr[300];
   if (Port != 0)
      snprintf(ServStr,sizeof(ServStr),"%i", Port);
   else
      snprintf(ServStr,sizeof(ServStr),"%s", Service);
   
   /* We used a cached address record.. Yes this is against the spec but
      the way we have setup our rotating dns suggests that this is more
      sensible */
   if (LastHost != Host || LastPort != Port)
   {
      Owner->Status(_("Connecting to %s"),Host.c_str());

      // Free the old address structure
      if (LastHostAddr != 0)
      {
	 freeaddrinfo(LastHostAddr);
	 LastHostAddr = 0;
	 LastUsed = 0;
      }
      
      // We only understand SOCK_STREAM sockets.
      struct addrinfo Hints;
      memset(&Hints,0,sizeof(Hints));
      Hints.ai_socktype = SOCK_STREAM;
      Hints.ai_flags = 0;
#ifdef AI_IDN
      if (_config->FindB("Acquire::Connect::IDN", true) == true)
	 Hints.ai_flags |= AI_IDN;
#endif
      // see getaddrinfo(3): only return address if system has such a address configured
      // useful if system is ipv4 only, to not get ipv6, but that fails if the system has
      // no address configured: e.g. offline and trying to connect to localhost.
      if (_config->FindB("Acquire::Connect::AddrConfig", true) == true)
	 Hints.ai_flags |= AI_ADDRCONFIG;
      Hints.ai_protocol = 0;
      
      if(_config->FindB("Acquire::ForceIPv4", false) == true)
         Hints.ai_family = AF_INET;
      else if(_config->FindB("Acquire::ForceIPv6", false) == true)
         Hints.ai_family = AF_INET6;
      else
         Hints.ai_family = AF_UNSPEC;

      // if we couldn't resolve the host before, we don't try now
      if(bad_addr.find(Host) != bad_addr.end()) 
	 return _error->Error(_("Could not resolve '%s'"),Host.c_str());

      // Resolve both the host and service simultaneously
      while (1)
      {
	 int Res;
	 if ((Res = getaddrinfo(Host.c_str(),ServStr,&Hints,&LastHostAddr)) != 0 ||
	     LastHostAddr == 0)
	 {
	    if (Res == EAI_NONAME || Res == EAI_SERVICE)
	    {
	       if (DefPort != 0)
	       {
		  snprintf(ServStr, sizeof(ServStr), "%i", DefPort);
		  DefPort = 0;
		  continue;
	       }
	       bad_addr.insert(bad_addr.begin(), Host);
	       Owner->SetFailReason("ResolveFailure");
	       return _error->Error(_("Could not resolve '%s'"),Host.c_str());
	    }
	    
	    if (Res == EAI_AGAIN)
	    {
	       Owner->SetFailReason("TmpResolveFailure");
	       return _error->Error(_("Temporary failure resolving '%s'"),
				    Host.c_str());
	    }
	    if (Res == EAI_SYSTEM)
	       return _error->Errno("getaddrinfo", _("System error resolving '%s:%s'"),
                                      Host.c_str(),ServStr);
	    return _error->Error(_("Something wicked happened resolving '%s:%s' (%i - %s)"),
				 Host.c_str(),ServStr,Res,gai_strerror(Res));
	 }
	 break;
      }
      
      LastHost = Host;
      LastPort = Port;
   }

   // When we have an IP rotation stay with the last IP.
   struct addrinfo *CurHost = LastHostAddr;
   if (LastUsed != 0)
       CurHost = LastUsed;

   std::vector<struct addrinfo *> ipv6Addrs;
   std::vector<struct addrinfo *> ipv4Addrs;

   while (CurHost != 0)
   {
      if (CurHost->ai_family == AF_INET6)
      {
	 ipv6Addrs.push_back(CurHost);
      }
      else
      {
	 ipv4Addrs.push_back(CurHost);
      }

      // Ignore UNIX domain sockets
      do
      {
	 CurHost = CurHost->ai_next;
      }
      while (CurHost != 0 && CurHost->ai_family == AF_UNIX);

      /* If we reached the end of the search list then wrap around to the
         start */
      if (CurHost == 0 && LastUsed != 0)
	 CurHost = LastHostAddr;
      
      // Reached the end of the search cycle
      if (CurHost == LastUsed)
	 break;
      
      if (CurHost != 0)
	 _error->Discard();
   }

   std::vector<struct addrinfo *>::const_iterator ipv6iter = ipv6Addrs.cbegin(), ipv4iter = ipv4Addrs.cbegin();

   while (ipv6iter != ipv6Addrs.end() || ipv4iter != ipv4Addrs.end())
   {
      if (DoConnect(ipv6iter != ipv6Addrs.end() ? *ipv6iter : nullptr, ipv4iter != ipv4Addrs.end() ? *ipv4iter : nullptr, Host, TimeOut, Fd, Owner) == true)
      {
	 LastUsed = CurHost;
	 return true;
      }
      Fd->Close();

      ipv6iter++;
      ipv4iter++;
   }

   if (_error->PendingError() == true)
      return false;   
   return _error->Error(_("Unable to connect to %s:%s:"),Host.c_str(),ServStr);
}
									/*}}}*/
// Connect - Connect to a server					/*{{{*/
// ---------------------------------------------------------------------
/* Performs a connection to the server (including SRV record lookup) */
bool Connect(std::string Host, int Port, const char *Service,
	     int DefPort, std::unique_ptr<MethodFd> &Fd,
	     unsigned long TimeOut, aptMethod *Owner)
{
   if (_error->PendingError() == true)
      return false;

   if (ConnectionAllowed(Service, Host) == false)
      return false;

   if(LastHost != Host || LastPort != Port)
   {
      SrvRecords.clear();
      if (_config->FindB("Acquire::EnableSrvRecords", true) == true)
      {
         GetSrvRecords(Host, DefPort, SrvRecords);
	 // RFC2782 defines that a lonely '.' target is an abort reason
	 if (SrvRecords.size() == 1 && SrvRecords[0].target.empty())
	    return _error->Error("SRV records for %s indicate that "
		  "%s service is not available at this domain", Host.c_str(), Service);
      }
   }

   size_t stackSize = 0;
   // try to connect in the priority order of the srv records
   std::string initialHost{std::move(Host)};
   auto const initialPort = Port;
   while(SrvRecords.empty() == false)
   {
      _error->PushToStack();
      ++stackSize;
      // PopFromSrvRecs will also remove the server
      auto Srv = PopFromSrvRecs(SrvRecords);
      Host = Srv.target;
      Port = Srv.port;
      auto const ret = ConnectToHostname(Host, Port, Service, DefPort, Fd, TimeOut, Owner);
      if (ret)
      {
	 while(stackSize--)
	    _error->RevertToStack();
         return true;
      }
   }
   Host = std::move(initialHost);
   Port = initialPort;

   // we have no (good) SrvRecords for this host, connect right away
   _error->PushToStack();
   ++stackSize;
   auto const ret = ConnectToHostname(Host, Port, Service, DefPort, Fd,
	 TimeOut, Owner);
   while(stackSize--)
      if (ret)
	 _error->RevertToStack();
      else
	 _error->MergeWithStack();
   return ret;
}
									/*}}}*/
// UnwrapSocks - Handle SOCKS setup					/*{{{*/
// ---------------------------------------------------------------------
/* This does socks magic */
static bool TalkToSocksProxy(int const ServerFd, std::string const &Proxy,
			     char const *const type, bool const ReadWrite, uint8_t *const ToFrom,
			     unsigned int const Size, unsigned int const Timeout)
{
   if (WaitFd(ServerFd, ReadWrite, Timeout) == false)
      return _error->Error("Waiting for the SOCKS proxy %s to %s timed out", URI::SiteOnly(Proxy).c_str(), type);
   if (ReadWrite == false)
   {
      if (FileFd::Read(ServerFd, ToFrom, Size) == false)
	 return _error->Error("Reading the %s from SOCKS proxy %s failed", type, URI::SiteOnly(Proxy).c_str());
   }
   else
   {
      if (FileFd::Write(ServerFd, ToFrom, Size) == false)
	 return _error->Error("Writing the %s to SOCKS proxy %s failed", type, URI::SiteOnly(Proxy).c_str());
   }
   return true;
}

bool UnwrapSocks(std::string Host, int Port, URI Proxy, std::unique_ptr<MethodFd> &Fd,
		 unsigned long Timeout, aptMethod *Owner)
{
   /* We implement a very basic SOCKS5 client here complying mostly to RFC1928 expect
    * for not offering GSSAPI auth which is a must (we only do no or user/pass auth).
    * We also expect the SOCKS5 server to do hostname lookup (aka socks5h) */
   std::string const ProxyInfo = URI::SiteOnly(Proxy);
   Owner->Status(_("Connecting to %s (%s)"), "SOCKS5h proxy", ProxyInfo.c_str());
#define APT_WriteOrFail(TYPE, DATA, LENGTH)                                               \
   if (TalkToSocksProxy(Fd->Fd(), ProxyInfo, TYPE, true, DATA, LENGTH, Timeout) == false) \
   return false
#define APT_ReadOrFail(TYPE, DATA, LENGTH)                                                 \
   if (TalkToSocksProxy(Fd->Fd(), ProxyInfo, TYPE, false, DATA, LENGTH, Timeout) == false) \
   return false
   if (Host.length() > 255)
      return _error->Error("Can't use SOCKS5h as hostname %s is too long!", Host.c_str());
   if (Proxy.User.length() > 255 || Proxy.Password.length() > 255)
      return _error->Error("Can't use user&pass auth as they are too long (%lu and %lu) for the SOCKS5!", Proxy.User.length(), Proxy.Password.length());
   if (Proxy.User.empty())
   {
      uint8_t greeting[] = {0x05, 0x01, 0x00};
      APT_WriteOrFail("greet-1", greeting, sizeof(greeting));
   }
   else
   {
      uint8_t greeting[] = {0x05, 0x02, 0x00, 0x02};
      APT_WriteOrFail("greet-2", greeting, sizeof(greeting));
   }
   uint8_t greeting[2];
   APT_ReadOrFail("greet back", greeting, sizeof(greeting));
   if (greeting[0] != 0x05)
      return _error->Error("SOCKS proxy %s greets back with wrong version: %d", ProxyInfo.c_str(), greeting[0]);
   if (greeting[1] == 0x00)
      ; // no auth has no method-dependent sub-negotiations
   else if (greeting[1] == 0x02)
   {
      if (Proxy.User.empty())
	 return _error->Error("SOCKS proxy %s negotiated user&pass auth, but we had not offered it!", ProxyInfo.c_str());
      // user&pass auth sub-negotiations are defined by RFC1929
      std::vector<uint8_t> auth = {{0x01, static_cast<uint8_t>(Proxy.User.length())}};
      std::copy(Proxy.User.begin(), Proxy.User.end(), std::back_inserter(auth));
      auth.push_back(static_cast<uint8_t>(Proxy.Password.length()));
      std::copy(Proxy.Password.begin(), Proxy.Password.end(), std::back_inserter(auth));
      APT_WriteOrFail("user&pass auth", auth.data(), auth.size());
      uint8_t authstatus[2];
      APT_ReadOrFail("auth report", authstatus, sizeof(authstatus));
      if (authstatus[0] != 0x01)
	 return _error->Error("SOCKS proxy %s auth status response with wrong version: %d", ProxyInfo.c_str(), authstatus[0]);
      if (authstatus[1] != 0x00)
	 return _error->Error("SOCKS proxy %s reported authorization failure: username or password incorrect? (%d)", ProxyInfo.c_str(), authstatus[1]);
   }
   else
      return _error->Error("SOCKS proxy %s greets back having not found a common authorization method: %d", ProxyInfo.c_str(), greeting[1]);
   union {
      uint16_t *i;
      uint8_t *b;
   } portu;
   uint16_t port = htons(static_cast<uint16_t>(Port));
   portu.i = &port;
   std::vector<uint8_t> request = {{0x05, 0x01, 0x00, 0x03, static_cast<uint8_t>(Host.length())}};
   std::copy(Host.begin(), Host.end(), std::back_inserter(request));
   request.push_back(portu.b[0]);
   request.push_back(portu.b[1]);
   APT_WriteOrFail("request", request.data(), request.size());
   uint8_t response[4];
   APT_ReadOrFail("first part of response", response, sizeof(response));
   if (response[0] != 0x05)
      return _error->Error("SOCKS proxy %s response with wrong version: %d", ProxyInfo.c_str(), response[0]);
   if (response[2] != 0x00)
      return _error->Error("SOCKS proxy %s has unexpected non-zero reserved field value: %d", ProxyInfo.c_str(), response[2]);
   std::string bindaddr;
   if (response[3] == 0x01) // IPv4 address
   {
      uint8_t ip4port[6];
      APT_ReadOrFail("IPv4+Port of response", ip4port, sizeof(ip4port));
      portu.b[0] = ip4port[4];
      portu.b[1] = ip4port[5];
      port = ntohs(*portu.i);
      strprintf(bindaddr, "%d.%d.%d.%d:%d", ip4port[0], ip4port[1], ip4port[2], ip4port[3], port);
   }
   else if (response[3] == 0x03) // hostname
   {
      uint8_t namelength;
      APT_ReadOrFail("hostname length of response", &namelength, 1);
      uint8_t hostname[namelength + 2];
      APT_ReadOrFail("hostname of response", hostname, sizeof(hostname));
      portu.b[0] = hostname[namelength];
      portu.b[1] = hostname[namelength + 1];
      port = ntohs(*portu.i);
      hostname[namelength] = '\0';
      strprintf(bindaddr, "%s:%d", hostname, port);
   }
   else if (response[3] == 0x04) // IPv6 address
   {
      uint8_t ip6port[18];
      APT_ReadOrFail("IPv6+port of response", ip6port, sizeof(ip6port));
      portu.b[0] = ip6port[16];
      portu.b[1] = ip6port[17];
      port = ntohs(*portu.i);
      strprintf(bindaddr, "[%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X:%02X%02X]:%d",
		ip6port[0], ip6port[1], ip6port[2], ip6port[3], ip6port[4], ip6port[5], ip6port[6], ip6port[7],
		ip6port[8], ip6port[9], ip6port[10], ip6port[11], ip6port[12], ip6port[13], ip6port[14], ip6port[15],
		port);
   }
   else
      return _error->Error("SOCKS proxy %s destination address is of unknown type: %d",
			   ProxyInfo.c_str(), response[3]);
   if (response[1] != 0x00)
   {
      char const *errstr = nullptr;
      auto errcode = response[1];
      // Tor error reporting can be a bit arcane, lets try to detect & fix it up
      if (bindaddr == "0.0.0.0:0")
      {
	 auto const lastdot = Host.rfind('.');
	 if (lastdot == std::string::npos || Host.substr(lastdot) != ".onion")
	    ;
	 else if (errcode == 0x01)
	 {
	    auto const prevdot = Host.rfind('.', lastdot - 1);
	    if (lastdot == 16 && prevdot == std::string::npos)
	       ; // valid .onion address
	    else if (prevdot != std::string::npos && (lastdot - prevdot) == 17)
	       ; // valid .onion address with subdomain(s)
	    else
	    {
	       errstr = "Invalid hostname: onion service name must be 16 characters long";
	       Owner->SetFailReason("SOCKS");
	    }
	 }
	 // in all likelihood the service is either down or the address has
	 // a typo and so "Host unreachable" is the better understood error
	 // compared to the technically correct "TLL expired".
	 else if (errcode == 0x06)
	    errcode = 0x04;
      }
      if (errstr == nullptr)
      {
	 switch (errcode)
	 {
	 case 0x01:
	    errstr = "general SOCKS server failure";
	    Owner->SetFailReason("SOCKS");
	    break;
	 case 0x02:
	    errstr = "connection not allowed by ruleset";
	    Owner->SetFailReason("SOCKS");
	    break;
	 case 0x03:
	    errstr = "Network unreachable";
	    Owner->SetFailReason("ConnectionTimedOut");
	    break;
	 case 0x04:
	    errstr = "Host unreachable";
	    Owner->SetFailReason("ConnectionTimedOut");
	    break;
	 case 0x05:
	    errstr = "Connection refused";
	    Owner->SetFailReason("ConnectionRefused");
	    break;
	 case 0x06:
	    errstr = "TTL expired";
	    Owner->SetFailReason("Timeout");
	    break;
	 case 0x07:
	    errstr = "Command not supported";
	    Owner->SetFailReason("SOCKS");
	    break;
	 case 0x08:
	    errstr = "Address type not supported";
	    Owner->SetFailReason("SOCKS");
	    break;
	 default:
	    errstr = "Unknown error";
	    Owner->SetFailReason("SOCKS");
	    break;
	 }
      }
      return _error->Error("SOCKS proxy %s could not connect to %s (%s) due to: %s (%d)",
			   ProxyInfo.c_str(), Host.c_str(), bindaddr.c_str(), errstr, response[1]);
   }
   else if (Owner->DebugEnabled())
      ioprintf(std::clog, "http: SOCKS proxy %s connection established to %s (%s)\n",
	       ProxyInfo.c_str(), Host.c_str(), bindaddr.c_str());

   if (WaitFd(Fd->Fd(), true, Timeout) == false)
      return _error->Error("SOCKS proxy %s reported connection to %s (%s), but timed out",
			   ProxyInfo.c_str(), Host.c_str(), bindaddr.c_str());
#undef APT_ReadOrFail
#undef APT_WriteOrFail

   return true;
}
									/*}}}*/
// UnwrapTLS - Handle TLS connections 					/*{{{*/
// ---------------------------------------------------------------------
/* Performs a TLS handshake on the socket */
struct TlsFd : public MethodFd
{
   std::unique_ptr<MethodFd> UnderlyingFd;
   gnutls_session_t session;
   gnutls_certificate_credentials_t credentials;
   std::string hostname;

   int Fd() APT_OVERRIDE { return UnderlyingFd->Fd(); }

   ssize_t Read(void *buf, size_t count) APT_OVERRIDE
   {
      return HandleError(gnutls_record_recv(session, buf, count));
   }
   ssize_t Write(void *buf, size_t count) APT_OVERRIDE
   {
      return HandleError(gnutls_record_send(session, buf, count));
   }

   template <typename T>
   T HandleError(T err)
   {
      if (err < 0 && gnutls_error_is_fatal(err))
	 errno = EIO;
      else if (err < 0)
	 errno = EAGAIN;
      else
	 errno = 0;
      return err;
   }

   int Close() APT_OVERRIDE
   {
      auto err = HandleError(gnutls_bye(session, GNUTLS_SHUT_RDWR));
      auto lower = UnderlyingFd->Close();
      return err < 0 ? HandleError(err) : lower;
   }

   bool HasPending() APT_OVERRIDE
   {
      return gnutls_record_check_pending(session) > 0;
   }
};

bool UnwrapTLS(std::string Host, std::unique_ptr<MethodFd> &Fd,
	       unsigned long Timeout, aptMethod *Owner)
{
   if (_config->FindB("Acquire::AllowTLS", true) == false)
      return _error->Error("TLS support has been disabled: Acquire::AllowTLS is false.");

   int err;
   TlsFd *tlsFd = new TlsFd();

   tlsFd->hostname = Host;
   tlsFd->UnderlyingFd = MethodFd::FromFd(-1); // For now

   if ((err = gnutls_init(&tlsFd->session, GNUTLS_CLIENT | GNUTLS_NONBLOCK)) < 0)
      return _error->Error("Internal error: could not allocate credentials: %s", gnutls_strerror(err));

   FdFd *fdfd = dynamic_cast<FdFd *>(Fd.get());
   if (fdfd != nullptr)
   {
      gnutls_transport_set_int(tlsFd->session, fdfd->fd);
   }
   else
   {
      gnutls_transport_set_ptr(tlsFd->session, Fd.get());
      gnutls_transport_set_pull_function(tlsFd->session,
					 [](gnutls_transport_ptr_t p, void *buf, size_t size) -> ssize_t {
					    return reinterpret_cast<MethodFd *>(p)->Read(buf, size);
					 });
      gnutls_transport_set_push_function(tlsFd->session,
					 [](gnutls_transport_ptr_t p, const void *buf, size_t size) -> ssize_t {
					    return reinterpret_cast<MethodFd *>(p)->Write((void *)buf, size);
					 });
   }

   if ((err = gnutls_certificate_allocate_credentials(&tlsFd->credentials)) < 0)
      return _error->Error("Internal error: could not allocate credentials: %s", gnutls_strerror(err));

   // Credential setup
   std::string fileinfo = Owner->ConfigFind("CaInfo", "");
   if (fileinfo.empty())
   {
      // No CaInfo specified, use system trust store.
      err = gnutls_certificate_set_x509_system_trust(tlsFd->credentials);
      if (err == 0)
	 Owner->Warning("No system certificates available. Try installing ca-certificates.");
      else if (err < 0)
	 return _error->Error("Could not load system TLS certificates: %s", gnutls_strerror(err));
   }
   else
   {
      // CA location has been set, use the specified one instead
      gnutls_certificate_set_verify_flags(tlsFd->credentials, GNUTLS_VERIFY_ALLOW_X509_V1_CA_CRT);
      err = gnutls_certificate_set_x509_trust_file(tlsFd->credentials, fileinfo.c_str(), GNUTLS_X509_FMT_PEM);
      if (err < 0)
	 return _error->Error("Could not load certificates from %s (CaInfo option): %s", fileinfo.c_str(), gnutls_strerror(err));
   }

   if (!Owner->ConfigFind("IssuerCert", "").empty())
      return _error->Error("The option '%s' is not supported anymore", "IssuerCert");
   if (!Owner->ConfigFind("SslForceVersion", "").empty())
      return _error->Error("The option '%s' is not supported anymore", "SslForceVersion");

   // For client authentication, certificate file ...
   std::string const cert = Owner->ConfigFind("SslCert", "");
   std::string const key = Owner->ConfigFind("SslKey", "");
   if (cert.empty() == false)
   {
      if ((err = gnutls_certificate_set_x509_key_file(
	       tlsFd->credentials,
	       cert.c_str(),
	       key.empty() ? cert.c_str() : key.c_str(),
	       GNUTLS_X509_FMT_PEM)) < 0)
      {
	 return _error->Error("Could not load client certificate (%s, SslCert option) or key (%s, SslKey option): %s", cert.c_str(), key.c_str(), gnutls_strerror(err));
      }
   }

   // CRL file
   std::string const crlfile = Owner->ConfigFind("CrlFile", "");
   if (crlfile.empty() == false)
   {
      if ((err = gnutls_certificate_set_x509_crl_file(tlsFd->credentials,
						      crlfile.c_str(),
						      GNUTLS_X509_FMT_PEM)) < 0)
	 return _error->Error("Could not load custom certificate revocation list %s (CrlFile option): %s", crlfile.c_str(), gnutls_strerror(err));
   }

   if ((err = gnutls_credentials_set(tlsFd->session, GNUTLS_CRD_CERTIFICATE, tlsFd->credentials)) < 0)
      return _error->Error("Internal error: Could not add certificates to session: %s", gnutls_strerror(err));

   if ((err = gnutls_set_default_priority(tlsFd->session)) < 0)
      return _error->Error("Internal error: Could not set algorithm preferences: %s", gnutls_strerror(err));

   if (Owner->ConfigFindB("Verify-Peer", true))
   {
      gnutls_session_set_verify_cert(tlsFd->session, Owner->ConfigFindB("Verify-Host", true) ? tlsFd->hostname.c_str() : nullptr, 0);
   }

   // set SNI only if the hostname is really a name and not an address
   {
      struct in_addr addr4;
      struct in6_addr addr6;

      if (inet_pton(AF_INET, tlsFd->hostname.c_str(), &addr4) == 1 ||
	  inet_pton(AF_INET6, tlsFd->hostname.c_str(), &addr6) == 1)
	 /* not a host name */;
      else if ((err = gnutls_server_name_set(tlsFd->session, GNUTLS_NAME_DNS, tlsFd->hostname.c_str(), tlsFd->hostname.length())) < 0)
	 return _error->Error("Could not set host name %s to indicate to server: %s", tlsFd->hostname.c_str(), gnutls_strerror(err));
   }

   // Set the FD now, so closing it works reliably.
   tlsFd->UnderlyingFd = std::move(Fd);
   Fd.reset(tlsFd);

   // Do the handshake. Our socket is non-blocking, so we need to call WaitFd()
   // accordingly.
   do
   {
      err = gnutls_handshake(tlsFd->session);
      if ((err == GNUTLS_E_INTERRUPTED || err == GNUTLS_E_AGAIN) &&
	  WaitFd(Fd->Fd(), gnutls_record_get_direction(tlsFd->session) == 1, Timeout) == false)
	 return _error->Errno("select", "Could not wait for server fd");
   } while (err < 0 && gnutls_error_is_fatal(err) == 0);

   if (err < 0)
   {
      // Print reason why validation failed.
      if (err == GNUTLS_E_CERTIFICATE_VERIFICATION_ERROR)
      {
	 gnutls_datum_t txt;
	 auto type = gnutls_certificate_type_get(tlsFd->session);
	 auto status = gnutls_session_get_verify_cert_status(tlsFd->session);
	 if (gnutls_certificate_verification_status_print(status,
							  type, &txt, 0) == 0)
	 {
	    _error->Error("Certificate verification failed: %s", txt.data);
	 }
	 gnutls_free(txt.data);
      }
      return _error->Error("Could not handshake: %s", gnutls_strerror(err));
   }

   return true;
}
									/*}}}*/
