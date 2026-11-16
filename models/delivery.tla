------------------------------- MODULE delivery -------------------------------
(* The delivery rows of one store: attempts, waits between them, giving up,
   and receivers that come and go. *)
EXTENDS Naturals

\* The values live here, so the configuration file holds names only.
Rows == {<<"e1", "c1">>, <<"e2", "c1">>, <<"e1", "c2">>}
Channels == {"c1", "c2"}
\* The receiver refuses this row; it shares its channel with a good row.
Bad == {<<"e2", "c1">>}
MaxTries == 3
Cap == 2
Delay(n) == IF n = 1 THEN 1 ELSE 2
\* The real delays grow and then stop at a cap; these reach it in fewer tries.
ASSUME Delay(1) < Delay(2) /\ \A n \in 1..(MaxTries - 1) : Delay(n) <= Cap

VARIABLES row, got, up
vars == <<row, got, up>>

TypeOK ==
    /\ row \in [Rows -> [state: {"pending", "sent", "gaveup"}, tries: 0..MaxTries, wait: 0..Cap]]
    /\ got \subseteq Rows
    /\ up \in [Channels -> BOOLEAN]

Init ==
    /\ row = [r \in Rows |-> [state |-> "pending", tries |-> 0, wait |-> 0]]
    /\ got = {}
    /\ up \in [Channels -> BOOLEAN]

\* A Retry-After can only lengthen the wait, never past the cap.
Failed(r) ==
    LET n == row[r].tries + 1 IN
    IF n = MaxTries
    THEN row' = [row EXCEPT ![r] = [state |-> "gaveup", tries |-> n, wait |-> 0]]
    ELSE \E w \in Delay(n)..Cap :
            row' = [row EXCEPT ![r] = [state |-> "pending", tries |-> n, wait |-> w]]

Attempt(r) ==
    /\ row[r].state = "pending"
    /\ row[r].wait = 0
    /\ UNCHANGED up
    /\ \/ /\ ~up[r[2]]
          /\ Failed(r)
          /\ UNCHANGED got
       \* A refusal: retrying cannot help.
       \/ /\ up[r[2]] /\ r \in Bad
          /\ row' = [row EXCEPT ![r] = [state |-> "gaveup", tries |-> @.tries + 1, wait |-> 0]]
          /\ UNCHANGED got
       \* The receiver got it, but its answer may be lost on the way back.
       \/ /\ up[r[2]] /\ r \notin Bad
          /\ got' = got \cup {r}
          /\ \/ row' = [row EXCEPT ![r] = [state |-> "sent", tries |-> @.tries + 1, wait |-> 0]]
             \/ Failed(r)

Tick ==
    /\ \E r \in Rows : row[r].state = "pending" /\ row[r].wait > 0
    /\ row' = [r \in Rows |->
                IF row[r].state = "pending" /\ row[r].wait > 0
                THEN [row[r] EXCEPT !.wait = @ - 1]
                ELSE row[r]]
    /\ UNCHANGED <<got, up>>

\* Always enabled, so the deadlock check stays meaningful.
Flip(c) ==
    /\ up' = [up EXCEPT ![c] = ~@]
    /\ UNCHANGED <<row, got>>

Next ==
    \/ \E r \in Rows : Attempt(r)
    \/ Tick
    \/ \E c \in Channels : Flip(c)

Spec == Init /\ [][Next]_vars /\ \A r \in Rows : WF_vars(Attempt(r)) /\ WF_vars(Tick)

-----------------------------------------------------------------------------

SentWasReceived == \A r \in Rows : row[r].state = "sent" => r \in got

GiveUpOnlyWhenHopeless ==
    \A r \in Rows : row[r].state = "gaveup" => r \in Bad \/ row[r].tries = MaxTries

\* A row that waits for another row only slows down, so no liveness property sees it.
NoRowWaitsForAnother ==
    \A r \in Rows : row[r].state = "pending" /\ row[r].wait = 0 => ENABLED Attempt(r)

GrowingDelay ==
    [][\A r \in Rows :
        row'[r].state = "pending" /\ row'[r].tries = row[r].tries + 1
        => row'[r].wait >= Delay(row'[r].tries)]_vars

EndsStay == [][\A r \in Rows : row[r].state # "pending" => row'[r] = row[r]]_vars

\* Retrying a refused URL or payload cannot help.
RefusalEndsAtOnce ==
    [][\A r \in Bad :
        up[r[2]] /\ row'[r].tries = row[r].tries + 1 => row'[r].state = "gaveup"]_vars

\* An attempt before its wait ends would ignore the backoff and the Retry-After.
AttemptOnlyWhenDue ==
    [][\A r \in Rows : row'[r].tries = row[r].tries + 1 => row[r].wait = 0]_vars

EveryRowEnds == \A r \in Rows : <>(row[r].state \in {"sent", "gaveup"})

\* It names no other row and no other channel: a refused row or a dead channel
\* may delay a good row, but cannot stop its delivery.
HealthyChannelDelivers == \A r \in Rows \ Bad : []up[r[2]] => <>(r \in got)

=============================================================================
