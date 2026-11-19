------------------------------- MODULE restart -------------------------------
(* One alert and one channel while the service crashes and starts again. The
   store keeps the events and the delivery rows; memory keeps only the send in
   flight, and a crash loses it. *)
EXTENDS Naturals, Sequences

\* The values live here, so the configuration file holds names only.
MaxEvents == 3
\* Without a bound on crashes no delivery can be promised.
MaxCrashes == 2
Ev == 1..MaxEvents

VARIABLES world, up, events, rows, posts, lost, inflight, crashes
vars == <<world, up, events, rows, posts, lost, inflight, crashes>>

TypeOK ==
    /\ world \in {"ok", "bad"}
    /\ up \in BOOLEAN
    /\ events \in Seq({"open", "resolve"})
    /\ Len(events) <= MaxEvents
    /\ rows \in [Ev -> {"none", "pending", "sent"}]
    /\ posts \in [Ev -> 0..(1 + MaxCrashes)]
    /\ lost \in [Ev -> 0..MaxCrashes]
    /\ inflight \in 0..MaxEvents
    /\ crashes \in 0..MaxCrashes

\* Memory is empty after a restart, so only the store can say what is open.
OpenInStore == Len(events) > 0 /\ events[Len(events)] = "open"

Init ==
    /\ world = "ok"
    /\ up = TRUE
    /\ events = <<>>
    /\ rows = [k \in Ev |-> "none"]
    /\ posts = [k \in Ev |-> 0]
    /\ lost = [k \in Ev |-> 0]
    /\ inflight = 0
    /\ crashes = 0

\* Always enabled, so the deadlock check stays meaningful.
Env ==
    /\ world' = IF world = "ok" THEN "bad" ELSE "ok"
    /\ UNCHANGED <<up, events, rows, posts, lost, inflight, crashes>>

\* One observation. The event and its delivery row are written in one
\* transaction, so no crash can fall between them.
Check ==
    /\ up
    /\ Len(events) < MaxEvents
    /\ \/ world = "bad" /\ ~OpenInStore
       \/ world = "ok" /\ OpenInStore
    /\ events' = Append(events, IF world = "bad" THEN "open" ELSE "resolve")
    /\ rows' = [rows EXCEPT ![Len(events) + 1] = "pending"]
    /\ UNCHANGED <<world, up, posts, lost, inflight, crashes>>

\* From here on the receiver may have the message, whatever happens to the
\* answer; so it counts as received.
Post(i) ==
    /\ up
    /\ inflight = 0
    /\ rows[i] = "pending"
    /\ posts' = [posts EXCEPT ![i] = @ + 1]
    /\ inflight' = i
    /\ UNCHANGED <<world, up, events, rows, lost, crashes>>

Record ==
    /\ up
    /\ inflight # 0
    /\ rows' = [rows EXCEPT ![inflight] = "sent"]
    /\ inflight' = 0
    /\ UNCHANGED <<world, up, events, posts, lost, crashes>>

\* A kill: the store stays as the last transaction left it.
Crash ==
    /\ up
    /\ crashes < MaxCrashes
    /\ up' = FALSE
    /\ inflight' = 0
    /\ lost' = IF inflight # 0 THEN [lost EXCEPT ![inflight] = @ + 1] ELSE lost
    /\ crashes' = crashes + 1
    /\ UNCHANGED <<world, events, rows, posts>>

Start ==
    /\ ~up
    /\ up' = TRUE
    /\ UNCHANGED <<world, events, rows, posts, lost, inflight, crashes>>

Next ==
    \/ Env
    \/ Check
    \/ \E i \in Ev : Post(i)
    \/ Record
    \/ Crash
    \/ Start

Spec ==
    /\ Init
    /\ [][Next]_vars
    /\ WF_vars(Record)
    /\ WF_vars(Start)
    /\ \A i \in Ev : WF_vars(Post(i))

-----------------------------------------------------------------------------

\* A difference that stands across a crash is not opened a second time.
Alternate == \A k \in 1..Len(events) : events[k] = IF k % 2 = 1 THEN "open" ELSE "resolve"

\* An event without its row is a notice that never goes out.
RowPerEvent == \A k \in Ev : (rows[k] # "none") <=> k <= Len(events)

\* The one duplicate that cannot be avoided: the receiver got the message and
\* the service died before the store knew it.
DuplicateOnlyAfterCrash == \A k \in Ev : posts[k] <= 1 + lost[k]

\* A row marked sent before its request goes is lost by a crash in between.
SentWasPosted == \A k \in Ev : rows[k] = "sent" => posts[k] >= 1

\* A restart must trust the store's word that a row went out.
SentStaysSent ==
    [][\A k \in Ev : rows[k] = "sent" => rows'[k] = "sent" /\ posts'[k] = posts[k]]_vars

\* A restart that closes a standing alert would open it again at the next check.
EventFollowsWorld ==
    [][Len(events') > Len(events) =>
        events'[Len(events')] = IF world = "bad" THEN "open" ELSE "resolve"]_vars

\* A crash may repeat a notice, never lose it.
EveryRowSent == \A k \in Ev : [](rows[k] = "pending" => <>(rows[k] = "sent"))

=============================================================================
