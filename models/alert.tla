-------------------------------- MODULE alert --------------------------------
(* The alert states of one domain: what the checks find now, the open alerts,
   and the event and delivery rows that one check writes. *)
EXTENDS Naturals, FiniteSets

\* The values live here, so the configuration file holds names only.
Ids == {"i1", "i2"}
Vals == {"v1", "v2"}
Sevs == {1, 2}
Channels == {"c1", "c2"}
MinSev == [c \in Channels |-> IF c = "c1" THEN 1 ELSE 2]
Diff == [val: Vals, sev: Sevs]
Kinds == {"open", "update", "escalate", "reminder", "resolve"}
Alerts == [id: Ids, val: Vals, sev: Sevs, peak: Sevs]
Events == [id: Ids, kind: Kinds, val: Vals, sev: Sevs, peak: Sevs]

\* Each sentinel has the fields of the values it stands beside, with values out
\* of range: TLC stops when it compares a record with a string.
Ok == [val |-> "none", sev |-> 0]
NoAlert == [id |-> "none", val |-> "none", sev |-> 0, peak |-> 0]
NoEvent == [id |-> "none", kind |-> "none", val |-> "none", sev |-> 0, peak |-> 0]

VARIABLES world, open, due, heard, remind, emitted, rows, checked
vars == <<world, open, due, heard, remind, emitted, rows, checked>>

TypeOK ==
    /\ world \in [Ids -> Diff \cup {Ok}]
    /\ open \subseteq Alerts
    /\ due \in [Ids -> BOOLEAN]
    /\ heard \in [Ids -> SUBSET Channels]
    /\ remind \in BOOLEAN
    /\ emitted \in Events \cup {NoEvent}
    /\ rows \subseteq Channels
    /\ checked \in Ids \cup {"none"}

OpenIn(S, i) == IF \E a \in S : a.id = i THEN CHOOSE a \in S : a.id = i ELSE NoAlert
Same(a, d) == a.val = d.val /\ a.sev = d.sev
Max(x, y) == IF x > y THEN x ELSE y

Init ==
    /\ world = [i \in Ids |-> Ok]
    /\ open = {}
    /\ due = [i \in Ids |-> FALSE]
    /\ heard = [i \in Ids |-> {}]
    /\ remind \in BOOLEAN
    /\ emitted = NoEvent
    /\ rows = {}
    /\ checked = "none"

\* Always enabled, so the deadlock check stays meaningful.
Env(i, d) ==
    /\ d # world[i]
    /\ world' = [world EXCEPT ![i] = d]
    /\ emitted' = NoEvent
    /\ rows' = {}
    /\ checked' = "none"
    /\ UNCHANGED <<open, due, heard, remind>>

\* The reminder interval passes for every open alert at once.
Tick ==
    /\ \E a \in open : ~due[a.id]
    /\ due' = [i \in Ids |-> due[i] \/ OpenIn(open, i) # NoAlert]
    /\ emitted' = NoEvent
    /\ rows' = {}
    /\ checked' = "none"
    /\ UNCHANGED <<world, open, heard, remind>>

\* One observation of identity i. The alert, its event and its delivery rows
\* change in one transaction, so they change together here.
Check(i) ==
    LET a == OpenIn(open, i)
        w == world[i]
        New(p) == [id |-> i, val |-> w.val, sev |-> w.sev, peak |-> p]
        \* rows' is set before heard' reads it.
        Emit(k, b, S) ==
            /\ open' = S
            /\ emitted' = [id |-> i, kind |-> k, val |-> b.val, sev |-> b.sev, peak |-> b.peak]
            /\ rows' = {c \in Channels : MinSev[c] <= b.peak}
            /\ due' = [due EXCEPT ![i] = FALSE]
            /\ heard' = [heard EXCEPT ![i] = IF k = "resolve" THEN {} ELSE @ \cup rows']
        Quiet ==
            /\ emitted' = NoEvent
            /\ rows' = {}
            /\ UNCHANGED <<open, due, heard>>
    IN  /\ checked' = i
        /\ UNCHANGED <<world, remind>>
        /\ \/ /\ a = NoAlert /\ w = Ok
              /\ Quiet
           \/ /\ a = NoAlert /\ w # Ok
              /\ Emit("open", New(w.sev), open \cup {New(w.sev)})
           \/ /\ a # NoAlert /\ w = Ok
              /\ Emit("resolve", a, open \ {a})
           \/ /\ a # NoAlert /\ w # Ok /\ ~Same(a, w)
              /\ LET b == New(Max(a.peak, w.sev))
                 IN  Emit(IF w.sev > a.sev THEN "escalate" ELSE "update", b, (open \ {a}) \cup {b})
           \/ /\ a # NoAlert /\ w # Ok /\ Same(a, w) /\ remind /\ due[i]
              /\ Emit("reminder", a, open)
           \/ /\ a # NoAlert /\ w # Ok /\ Same(a, w) /\ ~(remind /\ due[i])
              /\ Quiet

Next ==
    \/ \E i \in Ids, d \in Diff \cup {Ok} : Env(i, d)
    \/ Tick
    \/ \E i \in Ids : Check(i)

Spec == Init /\ [][Next]_vars /\ \A i \in Ids : WF_vars(Check(i))

-----------------------------------------------------------------------------

\* The store's unique index on open alerts refuses a second one.
OneOpen == \A i \in Ids : Cardinality({a \in open : a.id = i}) <= 1

\* The state, the event and the rows are written together.
EventMatchesState ==
    emitted # NoEvent =>
        IF emitted.kind = "resolve"
        THEN OpenIn(open, emitted.id) = NoAlert
        ELSE OpenIn(open, emitted.id) =
                [id |-> emitted.id, val |-> emitted.val, sev |-> emitted.sev, peak |-> emitted.peak]

RowsMatchEvent ==
    rows = IF emitted = NoEvent THEN {} ELSE {c \in Channels : MinSev[c] <= emitted.peak}

ReminderOnlyWhenOn == ~remind => emitted.kind # "reminder"

\* A standing difference gives one notice, not one per observation.
OnceWhileSame ==
    [][\A i \in Ids :
        LET A == OpenIn(open, i) IN
        /\ checked' = i
        /\ A # NoAlert /\ world[i] # Ok /\ Same(A, world[i])
        /\ ~(remind /\ due[i])
        => emitted' = NoEvent]_vars

UpdateOnChange ==
    [][\A i \in Ids :
        LET A == OpenIn(open, i) IN
        /\ checked' = i
        /\ A # NoAlert /\ world[i] # Ok /\ ~Same(A, world[i])
        => /\ emitted'.kind \in {"update", "escalate"}
           /\ Same(OpenIn(open', i), world[i])]_vars

EscalateWhenRaised ==
    [][\A i \in Ids :
        LET A == OpenIn(open, i) IN
        /\ checked' = i
        /\ A # NoAlert /\ world[i] # Ok /\ world[i].sev > A.sev
        => emitted'.kind = "escalate"]_vars

ResolveWhenGone ==
    [][\A i \in Ids :
        LET A == OpenIn(open, i) IN
        /\ checked' = i
        /\ A # NoAlert /\ world[i] = Ok
        => /\ emitted'.kind = "resolve"
           /\ OpenIn(open', i) = NoAlert]_vars

\* A channel that heard of an alert also hears of its end.
ResolveReachesEveryone ==
    [][emitted' # NoEvent /\ emitted'.kind = "resolve" => heard[emitted'.id] \subseteq rows']_vars

\* The first notice of an alert must say that it is new.
OpenWhenNew ==
    [][\A i \in Ids :
        /\ checked' = i
        /\ OpenIn(open, i) = NoAlert /\ world[i] # Ok
        => emitted'.kind = "open"]_vars

\* A headline that says "raised" must follow a real raise.
EscalateOnlyWhenRaised ==
    [][\A i \in Ids :
        /\ checked' = i
        /\ emitted'.kind = "escalate"
        => world[i].sev > OpenIn(open, i).sev]_vars

\* With reminders on, an open alert that is due is reminded, not forgotten.
ReminderWhenDue ==
    [][\A i \in Ids :
        LET A == OpenIn(open, i) IN
        /\ checked' = i
        /\ A # NoAlert /\ world[i] # Ok /\ Same(A, world[i])
        /\ remind /\ due[i]
        => emitted'.kind = "reminder"]_vars

\* The reminder interval counts from the last notice; else a reminder goes out at every check.
NoticeResetsDue == [][emitted' # NoEvent => ~due'[emitted'.id]]_vars

\* Whatever the checks keep finding, the open alerts come to match it.
Follows ==
    \A i \in Ids, w \in Diff \cup {Ok} :
        [](world[i] = w =>
            <>(\/ world[i] # w
               \/ IF w = Ok
                  THEN OpenIn(open, i) = NoAlert
                  ELSE OpenIn(open, i) # NoAlert /\ Same(OpenIn(open, i), w)))

=============================================================================
