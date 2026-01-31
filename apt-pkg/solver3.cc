/*
 * solver3.cc - The APT 3.0 solver
 *
 * Copyright (c) 2023 Julian Andres Klode
 * Copyright (c) 2023 Canonical Ltd
 *
 * SPDX-License-Identifier: GPL-2.0+
 *
 * This solver started from scratch but turns slowly into a variant of
 * MiniSat as documented in the paper
 *    "An extensible SAT-solver [extended version 1.2]."
 * by Niklas Eén, and Niklas Sörensson.
 *
 * It extends MiniSAT with support for optional clauses, and differs
 * in that it removes non-deterministic aspects like the activity based
 * ordering. Instead it uses a more nuanced static ordering that, to
 * some extend, preserves some greediness and sub-optimality of the
 * classic APT solver.
 */

#define APT_COMPILING_APT

#include <config.h>

#include <apt-pkg/algorithms.h>
#include <apt-pkg/aptconfiguration.h>
#include <apt-pkg/cachefilter.h>
#include <apt-pkg/cacheset.h>
#include <apt-pkg/error.h>
#include <apt-pkg/macros.h>
#include <apt-pkg/pkgsystem.h>
#include <apt-pkg/solver3.h>
#include <apt-pkg/version.h>

#include <cassert>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>

namespace APT::Solver
{

Solver::Solver(pkgCache &cache)
    : cache(cache),
      rootState(new State),
      pkgStates(cache),
      verStates(cache)
{
   // Ensure trivially
   static_assert(std::is_trivially_destructible_v<Work>);
   static_assert(std::is_trivially_destructible_v<Trail>);
   static_assert(sizeof(Var) == sizeof(map_pointer<pkgCache::Package>));
   static_assert(sizeof(Var) == sizeof(map_pointer<pkgCache::Version>));
   // Root state is "true".
   rootState->assignment = LiftedBool::True;
}

Solver::~Solver() = default;

// This function determines if a work item is less important than another.
bool Solver::Work::operator<(Solver::Work const &b) const
{
   if ((not clause->optional && size < 2) != (not b.clause->optional && b.size < 2))
      return not b.clause->optional && b.size < 2;
   if (clause->eager != b.clause->eager)
      return not clause->eager;
   if (clause->group != b.clause->group)
      return clause->group > b.clause->group;
   if ((size < 2) != (b.size < 2))
      return b.size < 2;
   if (size == 1 && b.size == 1) // Special case: 'shortcircuit' optional packages
      return clause->solutions.size() < b.clause->solutions.size();
   return false;
}

std::string APT::Solver::Clause::toString(pkgCache &cache, bool pretty, bool showMerged) const
{
   std::string out;
   if (showMerged)
      out.append(reason.toString(cache));
   if (dep && pretty)
   {
      out.append(" ").append(pkgCache::DepIterator(cache, dep).DepType()).append(" ");
      for (auto dep = pkgCache::DepIterator(cache, this->dep); not dep.end(); ++dep)
      {
	 out.append(dep.TargetPkg().FullName(true));
	 if (dep.TargetVer())
	    out.append(" (").append(dep.CompType()).append(" ").append(dep.TargetVer()).append(")");
	 if (!(dep->CompareOp & pkgCache::Dep::Or))
	    break;
	 out.append(" | ");
      }
   }
   else if (pretty && group == Group::SelectVersion && negative)
      out.append(" conflicts with other versions of itself");
   else if (pretty && group == Group::SelectVersion && reason.Pkg()) {
      out.append(solutions.size() > 1 ? " is available in versions " : " is available in version ");
      for (auto var : solutions) {
	 assert(var.Ver());
	 if (var != solutions.front())
	    out.append(", ");
	 out.append(var.Ver(cache).VerStr());
      }
   }
   else
   {
      out.append(" -> ");
      for (auto var : solutions)
	 out.append(" | ").append(var.toString(cache));
   }
   if (showMerged && not merged.empty())
   {
      for (auto &clause : merged)
      {
	 out.append(" and");
	 out.append(clause.toString(cache, pretty, false));
      }
   }
   return out;
}

std::string Solver::Work::toString(pkgCache &cache) const
{
   std::ostringstream out;
   if (clause->optional)
      out << "Optional ";
   out << "Item (" << ssize_t(size <= clause->solutions.size() ? size : -1) << "@" << level << ") ";
   out << clause->toString(cache);
   return out.str();
}

inline Var Solver::bestReason(Clause const *clause, Var var) const
{
   if (not clause)
      return Var{};
   if (clause->reason == var)
      for (auto choice : clause->solutions)
      {
	 if (clause->negative && value(choice) == LiftedBool::True)
	    return choice;
	 if (not clause->negative && value(choice) == LiftedBool::False)
	    return choice;
      }
   return clause->reason;
}

inline LiftedBool Solver::value(Lit lit) const
{
   return lit.sign() ? ~(*this)[lit.var()].assignment : (*this)[lit.var()].assignment;
}

// Prints an implication graph part of the form A -> B -> C, possibly with "not"
std::string Solver::WhyStr(Var reason) const
{
   std::vector<std::string> out;
   while (not reason.empty())
   {
      if (value(reason) == LiftedBool::False)
	 out.push_back(std::string("not ") + reason.toString(cache));
      else
	 out.push_back(reason.toString(cache));
      reason = bestReason((*this)[reason].reason, reason);
   }

   std::string outstr;
   for (auto I = out.rbegin(); I != out.rend(); ++I)
   {
      outstr += (outstr.size() == 0 ? "" : " -> ") + *I;
   }
   return outstr;
}

std::string Solver::LongWhyStr(Var var, bool assignment, const Clause *rclause, std::string prefix, std::unordered_set<Var> &seen) const
{
   std::ostringstream out;

   // Helper function to nicely print more details than just "install/do not install", such as "removal", "upgrade", "downgrade", "install"
   auto printSelection = [this](Var var, bool assignment)
   {
      std::string s;
      if (auto pkg = var.Pkg(cache); not assignment && pkg && pkg->CurrentVer)
	 strprintf(s, "%s is selected for removal", var.toString(cache).c_str());
      else if (auto ver = var.Ver(cache); assignment && ver && ver.ParentPkg().CurrentVer() && ver.ParentPkg().CurrentVer() != ver)
      {
	 if (cache.VS->CmpVersion(ver.ParentPkg().CurrentVer().VerStr(), ver.VerStr()) < 0)
	    strprintf(s, "%s is selected as an upgrade", var.toString(cache).c_str());
	 else
	    strprintf(s, "%s is selected as a downgrade", var.toString(cache).c_str());
      }
      else if (not assignment)
	 strprintf(s, "%s is not selected for install", var.toString(cache).c_str());
      else
	 strprintf(s, "%s is selected for install", var.toString(cache).c_str());
      return s;
   };

   // Helper: Recurse into all of the children of the clause and print the assignment for them.
   auto recurseChildren = [&](const Clause *clause, Var skip = Var())
   {
      if (clause->solutions.empty())
	 out << prefix << "[no choices]\n";
      for (auto choice : clause->solutions)
      {
	 if (choice == skip)
	    continue;

	 if (value(choice) == LiftedBool::Undefined)
	    out << prefix << "- " << choice.toString(cache) << " is undecided\n";
	 else
	    out << prefix << "- " << LongWhyStr(choice, value(choice) == LiftedBool::True, (*this)[choice].reason, prefix + "  ", seen).substr(prefix.size() + 2);
      }
   };

   // Inverse version selection clauses that select the package if the version is selected,
   // such as pkg=ver -> pkg, are irrelevant for the user, skip them
   if (var.Pkg() && assignment && rclause && rclause->group == Group::SelectVersion)
   {
      var = rclause->reason;
      rclause = (*this)[var].reason;
   }

   // No reason given, probably a user request or manually installed or essential or whatnot.
   if (not rclause)
   {
      out << prefix << printSelection(var, assignment) << "\n";
      return out.str();
   }

   // We could be called with a assignment we tried to make but failed due to a conflict;
   // this checks if it is the real assignment.
   if (value(var) != LiftedBool::Undefined && assignment == (value(var) == LiftedBool::True) && (*this)[var].reason == rclause)
   {
      // If we have seen the real assignment before; we dont't need to print it again.
      if (seen.find(var) != seen.end())
      {
	 out << prefix << printSelection(var, assignment) << " as above\n";
	 return out.str();
      }
      seen.insert(var);
   }

   // A package was decided "not install" due to a positive clause, so the clause is unsat.
   if (not assignment && rclause && not rclause->negative)
   {
      out << prefix << rclause->toString(cache, true) << "\n";
      out << prefix << "but none of the choices are installable:\n";
      recurseChildren(rclause);
      return out.str();
   }

   // Build the strongest path from a root to our assignment leaf
   std::vector<Var> path;
   for (auto reason = bestReason(rclause, var); not reason.empty(); reason = bestReason((*this)[reason].reason, reason))
      path.push_back(reason);

   // Render the strong reasoning path
   out << prefix << printSelection(var, assignment) << " because:\n";
   auto w = std::to_string(path.size() + 1).size();
   size_t i = 1;
   for (auto it = path.rbegin(); it != path.rend(); ++it, ++i)
   {
      auto const &state = (*this)[*it];
      // Don't print version selection clauses
      if (it->Pkg() && state.reason && state.reason->group == Group::SelectVersion)
      {
	 --i;
	 continue;
      }
      if (seen.find(*it) != seen.end())
      {
	 if ((it + 1) == path.rend() || seen.find(*(it + 1)) == seen.end())
	 {
	    out << prefix << (i == 1 ? "" : "1-") << i << ". " << printSelection(*it, state.assignment == LiftedBool::True) << " as above\n";
	 }
	 continue;
      }
      seen.insert(*it);
      if (state.reason)
      {
	 out << prefix << std::setw(w) << i << ". " << state.reason->toString(cache, true) << "\n";
	 if (state.reason->solutions.size() > 1)
	    out << prefix << std::setw(w) << " " << "  [selected " << it->toString(cache) << " for " << (state.assignment == LiftedBool::True ? "install" : "remove") << "]\n";
      }
      else
	 out << prefix << std::setw(w) << i << ". " << printSelection(*it, state.assignment == LiftedBool::True) << "\n";
   }

   // Print the leaf. We can't have the leaf in the path because we might be called for an attempted assignment
   // that conflicts with the actual assignment (to simplify: we marked X for not install, then we process Y depends X
   // and try to mark X and reach the conflict, we are called with "X" and the "Y depends X" clause).
   out << prefix << std::setw(w) << i << ". " << rclause->toString(cache, true) << "\n";
   if (rclause->solutions.size() > 1)
      out << prefix << std::setw(w) << " " << "  " << "[selected " << bestReason(rclause, var).toString(cache) << "]\n";

   bool firstContext = true;
   // Show alternative paths not taken. Consider you have Y depends X|Z; and you mark X
   // for it; we show above Y -> X as the path, but here we go show why Z was not considered in "Y depends X|Z".
   for (auto it = path.rbegin(); it != path.rend(); ++it)
   {
      auto const &state = (*this)[*it];
      if (not state.reason) // If we have no reason, we don't have alternatives
	 continue;
      if (state.reason->solutions.size() <= 1) // Nothing to print if we no alternatives
	 continue;
      if (state.reason->negative) // We only actually need one conflicting choice, ignore others
	 continue;

      if (firstContext)
      {
	 out << prefix << "For context, additional choices that could not be installed:" << "\n";
      }

      firstContext = false;
      out << prefix << "* In " << state.reason->toString(cache, true) << ":\n";
      prefix += "  ";
      recurseChildren(state.reason, *it);
      prefix.resize(prefix.size() - 2);
   }
   if (rclause->solutions.size() > 1 && not rclause->negative)
   {
      if (firstContext)
      {
	 out << prefix << "For context, additional choices that could not be installed:" << "\n";
      }
      firstContext = false;
      out << prefix << "* In " << rclause->toString(cache, true) << ":\n";
      prefix += "  ";
      recurseChildren(rclause, var);
      prefix.resize(prefix.size() - 2);
   }

   return out.str();
}

bool Solver::Assume(Lit lit, const Clause *reason)
{
   trailLim.push_back(trail.size());
   return Enqueue(lit, std::move(reason));
}

bool Solver::Enqueue(Lit lit, const Clause *reason)
{
   assert(not lit.empty());

   auto &state = (*this)[lit.var()];
   auto assignment = lit.sign() ? LiftedBool::False : LiftedBool::True;

   if (state.assignment != LiftedBool::Undefined)
   {
      if (state.assignment != assignment)
      {
	 std::ostringstream err;
	 err << "Unable to satisfy dependencies. Reached two conflicting assignments:" << "\n";
	 std::unordered_set<Var> seen;
	 err << "1. " << LongWhyStr(lit.var(), state.assignment == LiftedBool::True, state.reason, "   ", seen).substr(3) << "\n";
	 err << "2. " << LongWhyStr(lit.var(), not lit.sign(), reason, "   ", seen).substr(3);
	 return _error->Error("%s", err.str().c_str());
      }
      return true;
   }

   state.assignment = assignment;
   state.level = decisionLevel();
   state.reason = reason;

   // FIXME: Adjust call to bestReason to use lit
   if (unlikely(debug >= 1))
      std::cerr << "[" << decisionLevel() << "] " << (lit.sign() ? "Reject" : "Install") << ":" << lit.var().toString(cache) << " (" << WhyStr(bestReason(reason, lit.var())) << ")\n";

   trail.push_back(Trail{lit.var(), std::nullopt});
   propQ.push(lit.var());

   return true;
}

bool Solver::Propagate()
{
   while (!propQ.empty())
   {
      Var var = propQ.front();
      propQ.pop();

      // Stale propagation. These do not happen in MiniSat, because it clears the propQ on
      // conflict, however, we simply keep the item in here and skip it.
      if (value(var) == LiftedBool::Undefined)
	 continue;

      Lit lit = value(var) == LiftedBool::False ? ~var : var;
      if (not lit.sign())
	 Discover(lit.var());

      for (auto clause : watches(lit))
      {
	 if (Propagate(clause, lit))
	    continue;
	 return false;
      }
   }
   return true;
}

bool Solver::Propagate(const Clause *clause, Lit p)
{
   if (debug >= 3)
      std::cerr << "Propagate " << p.toString(cache) << " to " << clause->toString(cache) << std::endl;
   // Negative clauses are trivial
   if (clause->negative)
   {
      // One of the solutions was set, so reject the reason
      if (p != clause->reason)
	 return Enqueue(~clause->reason, clause);

      // Here we need to reject all conflicting solutions (reason -> none of solutions)
      for (auto sol : clause->solutions)
	 if (not Enqueue(~sol, clause))
	    return false;

      return true;
   }

   // Check if the clause is unit, conflict, or undecided
   auto not_false = [&](auto lit) { return value(lit) != LiftedBool::False; };
   auto head = std::ranges::find_if(clause->solutions, not_false);
   auto find_tail = [&]() { return std::ranges::find_last_if(clause->solutions, not_false); };
   if (head == clause->solutions.end())
   {
      // Conflict clause. If this clause is non-optional; reject its "reason".
      if (not clause->optional)
	 return Enqueue(~clause->reason, clause);
   }
   else if (value(clause->reason) != LiftedBool::True)
   {
      // Inactive clause, nothing to do
   }
   else if (not clause->optional && head == find_tail().begin())
   {
      // Unit clause. Enqueue the only possible solution
      return Enqueue(*head, clause);
   }
   else
   {
      // Undecided clause. If this is an activation, queue it for solving
      if (p == clause->reason)
	 return AddWork(Work{clause, decisionLevel()});
   }
   return true;
}

void Solver::UndoOne()
{
   auto trailItem = trail.back();

   if (unlikely(debug >= 4))
      std::cerr << "Undoing a single assignment\n";

   if (not trailItem.assigned.empty())
   {
      if (unlikely(debug >= 4))
	 std::cerr << "Unassign " << trailItem.assigned.toString(cache) << "\n";
      auto &state = (*this)[trailItem.assigned];
      state.assignment = LiftedBool::Undefined;
      state.reason = nullptr;
      state.reasonStr = nullptr;
      state.level = 0;
   }

   if (auto work = trailItem.work)
   {
      if (unlikely(debug >= 4))
	 std::cerr << "Adding work item " << work->toString(cache) << std::endl;

      must_succeed(AddWork(std::move(*work)));
   }

   trail.pop_back();

   // FIXME: Add the undo handling here once we have watchers.
}

bool Solver::Pop()
{
   if (decisionLevel() == 0)
      return false;

   time_t now = time(nullptr);
   if (startTime == 0)
      startTime = now;
   if (now - startTime >= Timeout)
      return _error->Error("Solver timed out.");

   if (unlikely(debug >= 2))
      for (std::string msg; _error->PopMessage(msg);)
	 std::cerr << "Branch failed: " << msg << std::endl;

   _error->Discard();

   // Assume() actually failed to enqueue anything, abort here
   if (trailLim.back() == trail.size())
   {
      trailLim.pop_back();
      return true;
   }

   assert(trailLim.back() < trail.size());
   int itemsToUndo = trail.size() - trailLim.back();
   auto choice = trail[trailLim.back()].assigned;

   for (; itemsToUndo; --itemsToUndo)
      UndoOne();

   // We need to remove any work that is at a higher level.
   trailLim.pop_back();
   work.erase(std::remove_if(work.begin(), work.end(), [this](Work &w) -> bool
			     { return w.level > decisionLevel(); }),
	      work.end());
   std::make_heap(work.begin(), work.end());

   if (unlikely(debug >= 2))
      std::cerr << "Backtracking to choice " << choice.toString(cache) << "\n";

   // FIXME: There should be a reason!
   if (not choice.empty() && not Enqueue(~choice, {}))
      return false;

   (*this)[choice].reasonStr = "backtracked";

   if (unlikely(debug >= 2))
      std::cerr << "Backtracked to choice " << choice.toString(cache) << "\n";

   return true;
}

bool Solver::AddWork(Work &&w)
{
   if (w.clause->negative)
   {
      for (auto var : w.clause->solutions)
	 if (not Enqueue(~var, w.clause))
	    return false;
   }
   else
   {
      if (unlikely(debug >= 3 && w.clause->optional))
	 std::cerr << "Enqueuing Recommends " << w.clause->toString(cache) << std::endl;
      if (w.clause->solutions.size() == 1 && not w.clause->optional)
	 return Enqueue(w.clause->solutions[0], w.clause);

      w.size = std::count_if(w.clause->solutions.begin(), w.clause->solutions.end(), [this](auto V)
			     { return value(V) != LiftedBool::False; });
      work.push_back(std::move(w));
      std::push_heap(work.begin(), work.end());
   }
   return true;
}

bool Solver::Solve()
{
   _error->PushToStack();
   DEFER([&]()
	 { _error->MergeWithStack(); });
   startTime = time(nullptr);
   while (true)
   {
      while (_error->PendingError() || not Propagate())
      {
	 if (not Pop())
	    return false;
      }

      if (work.empty())
	 break;

      auto item = work.front();
      std::pop_heap(work.begin(), work.end());
      work.pop_back();

      if (std::any_of(item.clause->solutions.begin(), item.clause->solutions.end(), [this](auto ver)
		      { return value(ver) == LiftedBool::True; }))
      {
	 if (unlikely(debug >= 2))
	    std::cerr << "ELIDED " << item.toString(cache) << std::endl;
      }
      else if (auto candidate = std::find_if(item.clause->solutions.begin(), item.clause->solutions.end(), [this](auto ver)
					     { return value(ver) == LiftedBool::Undefined; });
	       candidate != item.clause->solutions.end())
      {
	 if (unlikely(debug >= 3))
	    std::cerr << item.toString(cache) << "\n"
		      << "(try it: " << candidate->toString(cache) << ")\n";
	 must_succeed(Assume(*candidate, item.clause));
      }
      else
      {
	 assert(item.clause->optional);
	 if (unlikely(debug >= 1))
	    std::cerr << item.toString(cache) << "\n";
      }
      // Must push to trail after any Assume() above.
      trail.push_back(Trail{Var(), item});
   }

   return true;
}

// --------------------------------------------------------------------------------------------------------------------
// -------------------------------------------- Dependency solver -----------------------------------------------------
// --------------------------------------------------------------------------------------------------------------------
// FIXME: Helpers stolen from DepCache, please give them back.
struct CompareProviders3 /*{{{*/
{
   pkgCache &Cache;
   pkgDepCache::Policy &Policy;
   pkgCache::PkgIterator const Pkg;
   APT::Solver::DependencySolver &Solver;

   pkgCache::VerIterator bestVersion(pkgCache::PkgIterator pkg)
   {
      pkgCache::VerIterator res = pkg.VersionList();
      for (auto v = res; not v.end(); ++v)
	 res = std::max(res, v, *this);
      return res;
   }
   bool operator()(Var a, Var b)
   {
      pkgCache::VerIterator va = a.Ver(Cache);
      pkgCache::VerIterator vb = b.Ver(Cache);
      if (auto pa = a.Pkg(Cache))
	 va = bestVersion(pa);
      if (auto pb = b.Pkg(Cache))
	 vb = bestVersion(pb);

      assert(not va.end() && not vb.end());
      return (*this)(va, vb);
   }
   bool operator()(pkgCache::VerIterator const &AV, pkgCache::VerIterator const &BV)
   {
      assert(not AV.end() && not BV.end());
      pkgCache::PkgIterator const A = AV.ParentPkg();
      pkgCache::PkgIterator const B = BV.ParentPkg();
      // Compare versions for the same package. FIXME: Move this to the real implementation
      if (A == B)
      {
	 if (AV == BV)
	    return false;

	 // Candidate wins in upgrade scenario
	 if (Solver.IsUpgrade)
	 {
	    auto Cand = Solver.GetCandidateVer(A);
	    if (AV == Cand || BV == Cand)
	       return (AV == Cand);
	 }

	 // Installed version wins otherwise
	 if (A.CurrentVer() == AV || B.CurrentVer() == BV)
	    return (A.CurrentVer() == AV);

	 // Rest is ordered list, first by priority
	 if (auto pinA = Solver.GetPriority(AV), pinB = Solver.GetPriority(BV); pinA != pinB)
	    return pinA > pinB;

	 // Then by version
	 return _system->VS->CmpVersion(AV.VerStr(), BV.VerStr()) > 0;
      }
      // Try obsolete choices only after exhausting non-obsolete choices such that we install
      // packages replacing them and don't keep back upgrades depending on the replacement to
      // keep the obsolete package installed.
      if (Solver.IsUpgrade)
	 if (auto obsoleteA = Solver.Obsolete(A), obsoleteB = Solver.Obsolete(B); obsoleteA != obsoleteB)
	    return obsoleteB;
      // Prefer MA:same packages if other architectures for it are installed
      if ((AV->MultiArch & pkgCache::Version::Same) == pkgCache::Version::Same ||
	  (BV->MultiArch & pkgCache::Version::Same) == pkgCache::Version::Same)
      {
	 bool instA = false;
	 if ((AV->MultiArch & pkgCache::Version::Same) == pkgCache::Version::Same)
	 {
	    pkgCache::GrpIterator Grp = A.Group();
	    for (pkgCache::PkgIterator P = Grp.PackageList(); P.end() == false; P = Grp.NextPkg(P))
	       if (P->CurrentVer != 0)
	       {
		  instA = true;
		  break;
	       }
	 }
	 bool instB = false;
	 if ((BV->MultiArch & pkgCache::Version::Same) == pkgCache::Version::Same)
	 {
	    pkgCache::GrpIterator Grp = B.Group();
	    for (pkgCache::PkgIterator P = Grp.PackageList(); P.end() == false; P = Grp.NextPkg(P))
	    {
	       if (P->CurrentVer != 0)
	       {
		  instB = true;
		  break;
	       }
	    }
	 }
	 if (instA != instB)
	    return instA;
      }
      if ((A->CurrentVer == 0 || B->CurrentVer == 0) && A->CurrentVer != B->CurrentVer)
	 return A->CurrentVer != 0;
      // Prefer packages in the same group as the target; e.g. foo:i386, foo:amd64
      if (A->Group != B->Group && not Pkg.end())
      {
	 if (A->Group == Pkg->Group && B->Group != Pkg->Group)
	    return true;
	 else if (B->Group == Pkg->Group && A->Group != Pkg->Group)
	    return false;
      }
      // we like essentials
      if ((A->Flags & pkgCache::Flag::Essential) != (B->Flags & pkgCache::Flag::Essential))
      {
	 if ((A->Flags & pkgCache::Flag::Essential) == pkgCache::Flag::Essential)
	    return true;
	 else if ((B->Flags & pkgCache::Flag::Essential) == pkgCache::Flag::Essential)
	    return false;
      }
      if ((A->Flags & pkgCache::Flag::Important) != (B->Flags & pkgCache::Flag::Important))
      {
	 if ((A->Flags & pkgCache::Flag::Important) == pkgCache::Flag::Important)
	    return true;
	 else if ((B->Flags & pkgCache::Flag::Important) == pkgCache::Flag::Important)
	    return false;
      }
      // prefer native architecture
      if (strcmp(A.Arch(), B.Arch()) != 0)
      {
	 if (strcmp(A.Arch(), A.Cache()->NativeArch()) == 0)
	    return true;
	 else if (strcmp(B.Arch(), B.Cache()->NativeArch()) == 0)
	    return false;
	 std::vector<std::string> archs = APT::Configuration::getArchitectures();
	 for (std::vector<std::string>::const_iterator a = archs.begin(); a != archs.end(); ++a)
	    if (*a == A.Arch())
	       return true;
	    else if (*a == B.Arch())
	       return false;
      }
      // higher priority seems like a good idea
      if (AV->Priority != BV->Priority)
	 return AV->Priority < BV->Priority;
      if (auto NameCmp = strcmp(A.Name(), B.Name()))
	 return NameCmp < 0;
      // unable to decide…
      return A->ID > B->ID;
   }
};

/** \brief Returns \b true for packages matching a regular
 *  expression in APT::NeverAutoRemove.
 */
class DefaultRootSetFunc2 : public pkgDepCache::DefaultRootSetFunc
{
   std::unique_ptr<APT::CacheFilter::Matcher> Kernels;

   public:
   DefaultRootSetFunc2(pkgCache *cache) : Kernels(APT::KernelAutoRemoveHelper::GetProtectedKernelsFilter(cache)) {};
   ~DefaultRootSetFunc2() override = default;

   bool InRootSet(const pkgCache::PkgIterator &pkg) override { return pkg.end() == false && ((*Kernels)(pkg) || DefaultRootSetFunc::InRootSet(pkg)); };
}; // FIXME: DEDUP with pkgDepCache.
/*}}}*/

DependencySolver::DependencySolver(pkgCache &cache, pkgDepCache::Policy &policy, EDSP::Request::Flags requestFlags)
    : Solver(cache),
      policy(policy),
      requestFlags(requestFlags),
      pkgObsolete(cache),
      priorities(cache),
      candidates(cache)
{
}

DependencySolver::~DependencySolver() = default;

static bool SameOrGroup(pkgCache::DepIterator a, pkgCache::DepIterator b)
{
   while (1)
   {
      if (a->DependencyData != b->DependencyData)
	 return false;

      // At least one has reached the end, break
      if (not(a->CompareOp & pkgCache::Dep::Or) || not(b->CompareOp & pkgCache::Dep::Or))
	 break;

      ++a, ++b;
   }
   // Fully iterated over a and b
   return not(a->CompareOp & pkgCache::Dep::Or) && not(b->CompareOp & pkgCache::Dep::Or);
}

const Clause *DependencySolver::RegisterClause(Clause &&clause)
{
   auto &clauses = (*this)[clause.reason].clauses;
   pkgCache::DepIterator dep(cache, clause.dep);

   // Merge dependencies on the same name into a single one, and restrict their solution space.
   // For example, given dependencies on
   //	 bar Depends: pkg (<< 3), pkg (>> 2)
   //	 foo Provides: pkg (= 1)
   // The solution must always be pkg (= 2) and not say pkg (= 3), foo.
   // FIXME: This would be nice to merge across or groups too, but we can't do that yet.
   if (not clause.negative && not dep.end() && not(dep->CompareOp & pkgCache::Dep::Or))
   {
      bool merged = false;
      for (auto const &earlierClause : clauses)
      {
	 if (earlierClause->negative)
	    continue;
	 // Skip dependencies with or groups or dependencies on different names
	 if (pkgCache::DepIterator earlierDep(cache, earlierClause->dep);
	     earlierDep.end() || (earlierDep->CompareOp & pkgCache::Dep::Or) ||
	     earlierDep.TargetPkg() != dep.TargetPkg())
	    continue;
	 if (std::none_of(earlierClause->solutions.begin(), earlierClause->solutions.end(), [&clause](auto earlierSol)
			  { return std::ranges::contains(clause.solutions,
							 earlierSol); }))
	    continue;

	 if (earlierClause->optional == clause.optional)
	 {
	    std::erase_if(earlierClause->solutions, [&clause, this](auto earlierSol)
			  { return not std::ranges::contains(clause.solutions,
							     earlierSol); });

	    earlierClause->merged.push_front(clause);
	    merged = true;
	 }
	 else if (clause.optional)
	 {
	    // If say a Depends has fewer solution than a Recommends, remove the Recommend's extranous ones.
	    std::erase_if(clause.solutions, [&earlierClause, this](auto sol)
			  { return not std::ranges::contains(earlierClause->solutions,
							     sol); });

	    // Remove recursion here, such that we display correctly (if we ever display anywhere...)
	    auto earlierClauseCopy = *earlierClause;
	    clause.merged = std::move(earlierClauseCopy.merged);
	    clause.merged.push_front(earlierClauseCopy);
	 }
      }

      if (merged)
	 return nullptr;
   }

   clauses.push_back(std::make_unique<Clause>(std::move(clause)));
   auto const &inserted = clauses.back();
   // Insert all our watches
   if (not inserted->reason.empty())
      watches(inserted->reason).push_back(inserted.get());
   for (auto sol : inserted->solutions)
      watches(inserted->negative ? sol : ~sol).push_back(inserted.get());
   return inserted.get();
}

// This is essentially asking whether any other binary in the source package has a higher candidate
// version. This pretends that each package is installed at the same source version as the package
// under consideration.
bool DependencySolver::ObsoletedByNewerSourceVersion(pkgCache::VerIterator cand) const
{
   const auto pkg = cand.ParentPkg();
   const int candPriority = GetPriority(cand);

   for (auto ver = cand.Cache()->FindGrp(cand.SourcePkgName()).VersionsInSource(); not ver.end(); ver = ver.NextInSource())
   {
      // We are only interested in other packages in the same source package; built for the same architecture.
      if (ver->ParentPkg == cand->ParentPkg || ver.ParentPkg()->Arch != cand.ParentPkg()->Arch ||
	  (ver->MultiArch & pkgCache::Version::All) != (cand->MultiArch & pkgCache::Version::All) ||
	  cache.VS->CmpVersion(ver.SourceVerStr(), cand.SourceVerStr()) <= 0)
	 continue;

      // We also take equal priority here, given that we have a higher version
      const int priority = GetPriority(ver);
      if (priority == 0 || priority < candPriority)
	 continue;

      pkgObsolete[pkg] = LiftedBool::True;
      if (debug >= 3)
	 std::cerr << "Obsolete: " << cand.ParentPkg().FullName() << "=" << cand.VerStr() << " due to " << ver.ParentPkg().FullName() << "=" << ver.VerStr() << "\n";
      return true;
   }

   return false;
}

bool DependencySolver::Obsolete(pkgCache::PkgIterator pkg, bool AllowManual) const
{
   if ((*this)[pkg].flags.manual && not AllowManual)
      return false;
   if (pkgObsolete[pkg] != LiftedBool::Undefined)
      return pkgObsolete[pkg] == LiftedBool::True;

   auto ver = GetCandidateVer(pkg);

   if (ver.end() && not StrictPinning)
      ver = pkg.VersionList();
   if (ver.end())
   {
      if (debug >= 3)
	 std::cerr << "Obsolete: " << pkg.FullName() << " - not installable\n";
      pkgObsolete[pkg] = LiftedBool::True;
      return true;
   }

   if (ObsoletedByNewerSourceVersion(ver))
      return true;

   // Any version downloadable is good enough for us tbh
   for (auto ver = pkg.VersionList(); not ver.end(); ++ver)
   {
      if (ver.Downloadable())
      {
	 pkgObsolete[pkg] = LiftedBool::False;
	 return false;
      }
   }

   if (debug >= 3)
      std::cerr << "Obsolete: " << ver.ParentPkg().FullName() << "=" << ver.VerStr() << " - not installable\n";
   pkgObsolete[pkg] = LiftedBool::True;
   return true;
}
void DependencySolver::Discover(Var var)
{
   assert(discoverQ.empty());
   discoverQ.push(var);

   while (not discoverQ.empty())
   {
      var = discoverQ.front();
      discoverQ.pop();

      // Package needs to be discovered before the version to be able to dedup shared dependencies
      if (auto Ver = var.Ver(cache); not Ver.end() && not(*this)[Ver.ParentPkg()].flags.discovered)
	 var = Var(Ver.ParentPkg());

      auto &state = (*this)[var];

      if (state.flags.discovered)
	 continue;

      state.flags.discovered = true;

      if (auto Pkg = var.Pkg(cache); not Pkg.end())
      {
	 Clause clause{Var(Pkg), Group::SelectVersion};
	 for (auto ver = Pkg.VersionList(); not ver.end(); ver++)
	    clause.solutions.push_back(Var(ver));

	 std::stable_sort(clause.solutions.begin(), clause.solutions.end(), CompareProviders3{cache, policy, Pkg, *this});
	 RegisterClause(std::move(clause));

	 RegisterCommonDependencies(Pkg);
      }
      else if (auto Ver = var.Ver(cache); not Ver.end())
      {
	 Clause clause{Var(Ver), Group::SelectVersion};
	 clause.solutions = {Var(Ver.ParentPkg())};
	 RegisterClause(std::move(clause));

	 for (auto OV = Ver.ParentPkg().VersionList(); not OV.end(); ++OV)
	 {
	    if (OV == Ver)
	       continue;

	    Clause clause{Var(Ver), Group::SelectVersion, false, true /* negative */};
	    clause.solutions = {Var(OV)};
	    RegisterClause(std::move(clause));
	 }

	 for (auto dep = Ver.DependsList(); not dep.end();)
	 {
	    // Compute a single dependency element (glob or)
	    pkgCache::DepIterator start;
	    pkgCache::DepIterator end;
	    dep.GlobOr(start, end); // advances dep

	    // This dependency is shared across all versions, skip it.
	    if (auto &pkgClauses = (*this)[Ver.ParentPkg()].clauses;
		std::any_of(pkgClauses.begin(), pkgClauses.end(), [this, start](auto &c)
			    { return c->dep && SameOrGroup(start, pkgCache::DepIterator(cache, c->dep)); }))
	       continue;

	    auto clause = TranslateOrGroup(start, end, Var(Ver));

	    RegisterClause(std::move(clause));
	 }
      }

      // Recursively discover everything else that is not already FALSE by fact (False at level 0)
      for (auto const &clause : state.clauses)
	 for (auto const &var : clause->solutions)
	    if (value(var) != LiftedBool::False || (*this)[var].level > 0)
	       discoverQ.push(var);
   }
}

void DependencySolver::RegisterCommonDependencies(pkgCache::PkgIterator Pkg)
{
   for (auto dep = Pkg.VersionList().DependsList(); not dep.end();)
   {
      pkgCache::DepIterator start, end;
      dep.GlobOr(start, end); // advances dep

      bool allHaveDep = true;
      for (auto ver = Pkg.VersionList()++; allHaveDep && not ver.end(); ver++)
      {
	 bool haveDep = false;
	 for (auto otherDep = ver.DependsList(); not haveDep && not otherDep.end();)
	 {
	    pkgCache::DepIterator otherStart, otherEnd;
	    otherDep.GlobOr(otherStart, otherEnd); // advances other dep
	    haveDep = SameOrGroup(start, otherStart);
	 }
	 if (not haveDep)
	    allHaveDep = false;
      }
      if (not allHaveDep)
	 continue;
      auto clause = TranslateOrGroup(start, end, Var(Pkg));
      RegisterClause(std::move(clause));
   }
}

Clause DependencySolver::TranslateOrGroup(pkgCache::DepIterator start, pkgCache::DepIterator end, Var reason)
{
   // Non-important dependencies can only be installed if they are currently satisfied, see the check further
   // below once we have calculated all possible solutions.
   if (start.ParentPkg()->CurrentVer == 0 && not policy.IsImportantDep(start))
      return Clause{reason, Group::Satisfy, true};
   // Replaces and Enhances are not a real dependency.
   if (start->Type == pkgCache::Dep::Replaces || start->Type == pkgCache::Dep::Enhances)
      return Clause{reason, Group::Satisfy, true};
   if (unlikely(debug >= 3))
      std::cerr << "Found dependency critical " << reason.toString(cache) << " -> " << start.TargetPkg().FullName() << "\n";

   Clause clause{reason, Group::Satisfy, not start.IsCritical() /* optional */, start.IsNegative()};

   clause.dep = start;

   do
   {
      auto begin = clause.solutions.size();

      if (DeferVersionSelection && not start.IsNegative() && start.TargetPkg().ProvidesList().end() && start.IsSatisfied(start.TargetPkg()))
      {
	 clause.solutions.push_back(Var(start.TargetPkg()));
      }
      else
      {
	 auto all = start.AllTargets();

	 for (auto tgt = all; *tgt; ++tgt)
	 {
	    pkgCache::VerIterator tgti(cache, *tgt);

	    if (unlikely(debug >= 3))
	       std::cerr << "Adding work to  item " << reason.toString(cache) << " -> " << tgti.ParentPkg().FullName() << "=" << tgti.VerStr() << (clause.negative ? " (negative)" : "") << "\n";
	    clause.solutions.push_back(Var(pkgCache::VerIterator(cache, *tgt)));
	 }
	 delete[] all;
	 std::stable_sort(clause.solutions.begin() + begin, clause.solutions.end(), CompareProviders3{cache, policy, start.TargetPkg(), *this});
      }
      if (start == end)
	 break;
      ++start;
   } while (1);

   // Move obsolete packages to the end, and (non-obsolete) installed packages to the front
   if (not FixPolicyBroken)
      std::stable_sort(clause.solutions.begin(), clause.solutions.end(), [this](Var a, Var b)
		       {
	    if (IsUpgrade)
	       if (auto obsoleteA = Obsolete(a.CastPkg(cache)), obsoleteB = Obsolete(b.CastPkg(cache)); obsoleteA != obsoleteB)
		  return obsoleteB;
	    if ((a.CastPkg(cache)->CurrentVer == 0 || b.CastPkg(cache)->CurrentVer == 0) && a.CastPkg(cache)->CurrentVer != b.CastPkg(cache)->CurrentVer)
	       return a.CastPkg(cache)->CurrentVer != 0;
	    return false; });

   if (std::all_of(clause.solutions.begin(), clause.solutions.end(), [this](auto var) -> auto
		   { return var.CastPkg(cache)->CurrentVer == 0; }))
      clause.group = Group::SatisfyNew;
   if (std::any_of(clause.solutions.begin(), clause.solutions.end(), [this](auto var) -> auto
		   { return Obsolete(var.CastPkg(cache), true); }))
      clause.group = Group::SatisfyObsolete;
   // Try to perserve satisfied Recommends. FIXME: We should check if the Recommends was there in the installed version?
   if (clause.optional && start.ParentPkg()->CurrentVer)
   {
      bool important = policy.IsImportantDep(start);
      auto importantToKeep = [this](pkgCache::DepIterator d)
      {
	 return policy.IsImportantDep(d) || (KeepRecommends && d->Type == pkgCache::Dep::Recommends) || (KeepSuggests && d->Type == pkgCache::Dep::Suggests);
      };
      bool satisfied = std::any_of(clause.solutions.begin(), clause.solutions.end(), [this](auto var)
				   { return var.Pkg(cache) ? var.Pkg(cache)->CurrentVer != nullptr : Var(var.CastPkg(cache).CurrentVer()) == var; });

      // Find the existing dependency
      pkgCache::DepIterator existing;
      for (auto D = start.ParentPkg().CurrentVer().DependsList(); not D.end(); D++)
	 if (not D.IsCritical() && importantToKeep(D) && D.TargetPkg() == start.TargetPkg())
	 {
	    existing = D;
	    break;
	 }

      if (not existing.end() && not important && importantToKeep(start) && satisfied)
      {
	 if (unlikely(debug >= 3))
	    std::cerr << "Try to keep satisfied: " << clause.toString(cache, true) << std::endl;
	 clause.group = Group::SatisfySuggests;
	 // Erase the non-installed solutions. We will process this last and try to keep the previously installed
	 // "best" solution installed.
	 clause.solutions.erase(std::remove_if(clause.solutions.begin(), clause.solutions.end(), [this](auto var)
					       { return var.CastPkg(cache)->CurrentVer == nullptr; }),
				clause.solutions.end());
      }
      else if (not important)
      {
	 if (unlikely(debug >= 3))
	    std::cerr << "Ignore unimportant clause: " << clause.toString(cache, true) << std::endl;
	 return Clause{reason, Group::Satisfy, true};
      }
      else if (not existing.end() && policy.IsImportantDep(existing) && not satisfied)
      {
	 if (unlikely(debug >= 3))
	    std::cerr << "Ignoring unsatisfied clause: " << clause.toString(cache, true) << std::endl;
	 return Clause{reason, Group::Satisfy, true};
      }
      else if (IsUpgrade && not existing.end() && satisfied)
      {
	 if (unlikely(debug >= 3))
	    std::cerr << "Promoting previously satisfied clause to hard dependency: " << clause.toString(cache, true) << std::endl;
	 clause.optional = false;
	 clause.eager = true;
      }
      else if (
	 IsUpgrade && not(AllowRemove && AllowInstall)				    // promote Recommends to Depends in upgrade, not in dist-upgrade.
	 && reason.Ver() && reason.Ver(cache) != reason.CastPkg(cache).CurrentVer() // and if this an upgrade to an installed package
	 && (existing.end() || not policy.IsImportantDep(existing))		    // new Recommends, or upgraded from Suggests
      )
      {
	 if (unlikely(debug >= 3))
	    std::cerr << "Promoting new clause to hard dependency: " << clause.toString(cache) << std::endl;
	 clause.optional = false;
	 clause.eager = true;
      }
      else if (not existing.end() && importantToKeep(start) && satisfied)
      {
	 if (unlikely(debug >= 3))
	    std::cerr << "Restricting existing Recommends to installed packages: " << clause.toString(cache, true) << std::endl;
	 // Erase the non-installed solutions. We will process this last and try to keep the previously installed
	 // "best" solution installed.
	 clause.solutions.erase(std::remove_if(clause.solutions.begin(), clause.solutions.end(), [this](auto var)
					       { return var.CastPkg(cache)->CurrentVer == nullptr; }),
				clause.solutions.end());
	 clause.eager = true;
      }
   }

   return clause;
}

// \brief Apply the selections from the dep cache to the solver
bool DependencySolver::FromDepCache(pkgDepCache &depcache)
{
   DefaultRootSetFunc2 rootSet(&cache);
   std::vector<Var> manualPackages;

   // Enforce strict pinning rules by rejecting all forbidden versions.
   if (StrictPinning)
   {
      for (auto P = cache.PkgBegin(); not P.end(); P++)
      {
	 bool isForced = depcache[P].Protect() && depcache[P].Install();
	 bool isPhasing = IsUpgrade && depcache.PhasingApplied(P) && not isForced;
	 for (auto V = P.VersionList(); not V.end(); ++V)
	    if (P.CurrentVer() != V && (depcache.GetCandidateVersion(P) != V || isPhasing))
	       if (not Enqueue(~Var(V), {}))
		  return false;
      }
   }

   // Clause discovery depends on the manual flag, so we need to set the manual flag first before we discover any packages
   for (auto P = cache.PkgBegin(); not P.end(); P++)
      if (P->CurrentVer && not(depcache[P].Flags & pkgCache::Flag::Auto) && (depcache[P].Keep() || depcache[P].Install()))
	 (*this)[P].flags.manual = true;

   for (auto P = cache.PkgBegin(); not P.end(); P++)
   {
      if (P->VersionList == nullptr)
	 continue;

      auto state = depcache[P];
      if (P->SelectedState == pkgCache::State::Hold && not state.Protect())
      {
	 if (unlikely(debug >= 1))
	    std::cerr << "Hold " << P.FullName() << "\n";
	 if (P->CurrentVer ? not Enqueue(Var(P.CurrentVer())) : not Enqueue(~Var(P)))
	    return false;
      }
      else if (state.Delete()						  // Normal delete request.
	       || (not P->CurrentVer && state.Keep() && state.Protect())  // Delete request of not installed package.
	       || (not P->CurrentVer && state.Keep() && not AllowInstall) // New package installs not allowed.
      )
      {
	 if (unlikely(debug >= 1))
	    std::cerr << "Delete " << P.FullName() << "\n";
	 if (not Enqueue(~Var(P)))
	    return false;
      }
      else if (state.Install() || (state.Keep() && P->CurrentVer))
      {
	 auto isEssential = P->Flags & (pkgCache::Flag::Essential | pkgCache::Flag::Important);
	 auto isAuto = (depcache[P].Flags & pkgCache::Flag::Auto);
	 auto isOptional = ((isAuto && AllowRemove) || AllowRemoveManual) && not isEssential && not depcache[P].Protect();
	 auto Root = rootSet.InRootSet(P);
	 auto Upgrade = depcache.GetCandidateVersion(P) != P.CurrentVer();
	 auto Group = isAuto ? (Upgrade ? Group::UpgradeAuto : Group::KeepAuto)
			     : (Upgrade ? Group::UpgradeManual : Group::InstallManual);

	 if (isAuto && not depcache[P].Protect() && not isEssential && not KeepAuto && not rootSet.InRootSet(P))
	 {
	    if (unlikely(debug >= 1))
	       std::cerr << "Ignore automatic install " << P.FullName() << " (" << (isEssential ? "E" : "") << (isAuto ? "M" : "") << (Root ? "R" : "") << ")"
			 << "\n";
	    continue;
	 }
	 if (unlikely(debug >= 1))
	    std::cerr << "Install " << P.FullName() << " (" << (isEssential ? "E" : "") << (isAuto ? "M" : "") << (Root ? "R" : "") << ")"
		      << "\n";
	 if (not isOptional)
	 {
	    // Pre-empt the non-optional requests, as we don't want to queue them, we can just "unit propagate" here.
	    if (depcache[P].Keep() ? not Enqueue(Var(P)) : not Enqueue(Var(depcache.GetCandidateVersion(P))))
	       return false;
	 }
	 else
	 {
	    Clause w{Var(), Group, isOptional};
	    w.solutions.push_back(Var(P));
	    auto insertedW = RegisterClause(std::move(w));
	    if (insertedW && not AddWork(Work{insertedW, decisionLevel()}))
	       return false;

	    if (not isAuto)
	       manualPackages.push_back(Var(P));

	    // Given A->A2|A1, B->B1|B2; Bn->An, if we select `not A1`, we
	    // should try to install A2 before trying B so we end up with
	    // A2, B2, instead of removing A1 to keep B1 installed. This
	    // requires some special casing in Work::operator< above.
	    // Compare test-bug-712116-dpkg-pre-install-pkgs-hook-multiarch
	    Clause shortcircuit{Var(), Group, isOptional};
	    for (auto V = P.VersionList(); not V.end(); ++V)
	       shortcircuit.solutions.push_back(Var(V));
	    std::stable_sort(shortcircuit.solutions.begin(), shortcircuit.solutions.end(), CompareProviders3{cache, policy, P, *this});
	    auto insertedShort = RegisterClause(std::move(shortcircuit));
	    if (insertedShort && not AddWork(Work{insertedShort, decisionLevel()}))
	       return false;

	    // Discovery here is needed so the shortcircuit clause can actually become unit.
	    if (P.VersionList() && P.VersionList()->NextVer)
	       Discover(Var(P));
	 }
      }
      else if (IsUpgrade && AllowRemove && AllowInstall && (P->Flags & pkgCache::Flag::Essential))
      {
	 Clause w{Var(), Group::InstallManual, false};
	 auto G = P.Group();
	 for (auto P = G.PackageList(); not P.end(); P = G.NextPkg(P))
	    if (P->Flags & pkgCache::Flag::Essential)
	       w.solutions.push_back(Var(P));
	 std::stable_sort(w.solutions.begin(), w.solutions.end(), CompareProviders3{cache, policy, P, *this});
	 if (unlikely(debug >= 1))
	    std::cerr << "Install essential package " << P << std::endl;
	 auto inserted = RegisterClause(std::move(w));
	 if (inserted && not AddWork(Work{inserted, decisionLevel()}))
	    return false;
      }
   }

   if (not Propagate())
      return false;

   std::stable_sort(manualPackages.begin(), manualPackages.end(), CompareProviders3{cache, policy, {}, *this});
   for (auto assumption : manualPackages)
   {
      if (not Assume(assumption, {}) || not Propagate())
	 must_succeed(Pop());
   }

   return true;
}

bool DependencySolver::ToDepCache(pkgDepCache &depcache) const
{
   FastContiguousCacheMap<pkgCache::Package, bool> movedManual(cache);
   pkgDepCache::ActionGroup group(depcache);
   for (auto P = cache.PkgBegin(); not P.end(); P++)
   {
      depcache[P].Marked = 0;
      depcache[P].Garbage = 0;
      if (value(Var(P)) == LiftedBool::True)
      {
	 pkgCache::VerIterator cand;
	 for (auto V = P.VersionList(); cand.end() && not V.end(); V++)
	    if (value(Var(V)) == LiftedBool::True)
	       cand = V;

	 auto reasonClause = (*this)[cand].reason;
	 auto reason = reasonClause ? reasonClause->reason : Var();
	 if (auto RP = reason.Pkg(); RP == P.MapPointer())
	    reason = (*this)[P].reason ? (*this)[P].reason->reason : Var();

	 if (cand != P.CurrentVer())
	 {
	    bool automatic = (not reason.empty() || (depcache[P].Flags & pkgCache::Flag::Auto)) && not movedManual[P];
	    depcache.SetCandidateVersion(cand);
	    depcache.MarkInstall(P, false, 0, not automatic);

	    // Set the automatic bit for new packages or move it on upgrades to oldlibs
	    if (not P->CurrentVer)
	       depcache.MarkAuto(P, automatic);
	    else if (not(depcache[P].Flags & pkgCache::Flag::Auto) && P.CurrentVer()->Section && cand->Section && not _config->SectionInSubTree("APT::Move-Autobit-Sections", P.CurrentVer().Section()) && _config->SectionInSubTree("APT::Move-Autobit-Sections", cand.Section()))
	    {
	       bool moved = false;
	       for (auto const &clause : (*this)[cand].clauses)
		  for (auto sol : clause->solutions)
		  {
		     // New installs move the auto-bit. TODO: Should we look at whether clause is the reason for installing it?
		     if (sol.CastPkg(cache) == P || sol.CastPkg(cache)->CurrentVer)
			continue;
		     std::cerr << "Move  manual bit from " << P.FullName() << " to " << sol.CastPkg(cache).Name() << std::endl;
		     movedManual[sol.CastPkg(cache)] = true;
		     depcache.MarkAuto(sol.CastPkg(cache), false);
		     moved = true;
		  }
	       if (moved)
		  depcache.MarkAuto(P, true);
	    }

	 }
	 else
	    depcache.MarkKeep(P, false, reason.empty() && not(depcache[P].Flags & pkgCache::Flag::Auto));

	 depcache[P].Marked = 1;
	 depcache[P].Garbage = 0;
      }
      else if (P->CurrentVer || depcache[P].Install())
      {
	 bool automatic = (not (*this)[P].reason) && (not (*this)[P].reasonStr);
	 depcache.MarkDelete(P, false, 0, automatic);
	 depcache[P].Marked = 0;
	 depcache[P].Garbage = 1;
      }
   }
   return true;
}

// Command-line
std::string DependencySolver::InternalCliWhy(pkgDepCache &cache, pkgCache::PkgIterator pkg, bool assignment)
{
   DependencySolver solver(cache.GetCache(), cache.GetPolicy(), EDSP::Request::Flags(0));
   std::string buf;

   auto doOne = [&](Var var) -> std::string
   {
      solver.Discover(var);
      if (not solver.FromDepCache(cache) || not solver.Solve())
	 return "";
      std::unordered_set<Var> seen;
      if (solver[var].assignment == LiftedBool::Undefined)
	 return strprintf(buf, "%s is undecided\n", var.toString(cache).c_str()), buf;
      if (assignment && solver[var].assignment != LiftedBool::True)
	 return strprintf(buf, "%s is not actually marked for install\n", var.toString(cache).c_str()), buf;
      if (not assignment && solver[var].assignment == LiftedBool::True)
	 return strprintf(buf, "%s is actually marked for install\n", var.toString(cache).c_str()), buf;
      return solver.LongWhyStr(var, assignment, solver[var].reason, "", seen);
   };

   if (pkg.VersionList().end())
   {
      if (pkg.ProvidesList().end())
	 return strprintf(buf, "%s is a virtual package without a provider\n", pkg.FullName().c_str()), buf;

      std::ostringstream out;
      ioprintf(out, "%s is a virtual package, printing all providers\n", pkg.FullName().c_str());
      for (auto prv = pkg.ProvidesList(); not prv.end(); ++prv)
	 out << doOne(Var(prv.OwnerVer()));
      return out.str();
   }
   return doOne(Var(pkg));
}
} // namespace APT::Solver
