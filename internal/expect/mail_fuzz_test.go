package expect

import (
	"slices"
	"strings"
	"testing"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

// emlFuzzSet cuts data at NUL octets into records, and each record into TXT
// strings of cut%40+1 octets (at most 255).
func emlFuzzSet(data []byte, cut uint8) []dnswire.RData {
	var set []dnswire.RData
	size := int(cut%40) + 1
	for _, rec := range strings.Split(string(data), "\x00") {
		var pieces []string
		for len(rec) > size {
			pieces = append(pieces, rec[:size])
			rec = rec[size:]
		}
		set = append(set, dnswire.TXT{Strings: append(pieces, rec)})
	}
	return set
}

// emlFuzzWeaker holds the points that every reader must keep on any bytes.
func emlFuzzWeaker(t *testing.T, k MailKind, owner string, was, now []byte, cut uint8) {
	t.Helper()
	o := expName(t, owner)
	w, n := emlFuzzSet(was, cut), emlFuzzSet(now, cut)
	if got := Weaker(k, o, n, n); got != nil {
		t.Fatalf("Weaker(x, x) = %q for %s", got, emlShow(n))
	}
	got := Weaker(k, o, w, n)
	emlCheckWords(t, got)
	if again := Weaker(k, o, w, n); !emlSameWords(got, again) {
		t.Fatalf("Weaker is not deterministic: %q then %q", got, again)
	}
	if merged := MergeWords(got, got); len(merged) != len(got) || (len(got) > 0 && !slices.Equal(merged, got)) {
		t.Fatalf("MergeWords(w, w) = %q; want %q", merged, got)
	}
	Weaker(MailKind(0), o, w, n)
	Weaker(MailKind(200), o, w, n)
}

func emlSameWords(a, b []string) bool {
	if (a == nil) != (b == nil) || len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func emlFuzzSeeds(f *testing.F, texts ...string) {
	for _, a := range texts {
		for _, b := range texts {
			f.Add([]byte(a), []byte(b), uint8(254))
		}
	}
	f.Add([]byte(texts[0]), []byte(texts[0]+"\x00"+texts[0]), uint8(3))
	f.Add([]byte(texts[0]), []byte(emlPad(texts[0]+" x=", 4097)), uint8(39))
	f.Add([]byte(texts[0]), []byte(emlPad(texts[0]+" x=", 4096)), uint8(39))
}

func FuzzSPF(f *testing.F) {
	emlFuzzSeeds(f, "v=spf1 mx -all", "v=spf1 ip4:192.0.2.0/24 include:a.test redirect=r.test", "v=spf1 a/24//64 ?all exp=x.test",
		"v=spf1 include:%{d}.x.test -all", "V=SPF1 ptr exists:%{i}.x.test ~all foo=bar", "v=spf1 ip6:2001:db8::/32 -all\x00v=spf1 +all",
		"v=spf1 a:Corp.Test. mx:m.test/24 \tx")
	owner := expName(f, emlSPFOwner)
	f.Fuzz(func(t *testing.T, was, now []byte, cut uint8) {
		emlFuzzWeaker(t, MailSPF, emlSPFOwner, was, now, cut)
		set := emlFuzzSet(now, cut)
		has := HasSPF(set)
		if want := emlOracleHasSPF(emlJoined(set)); has != want {
			t.Fatalf("HasSPF = %v; want %v for %s", has, want, emlShow(set))
		}
		targets := SPFTargets(owner, set)
		if !has && targets != nil {
			t.Fatalf("SPFTargets = %q without an SPF record", emlNames(targets))
		}
		if len(targets) > 128 {
			t.Fatalf("%d targets; want at most 128", len(targets))
		}
		for _, n := range emlNames(targets) {
			if strings.Contains(n, "%") {
				t.Fatalf("target %q holds a macro", n)
			}
			for i := 0; i < len(n); i++ {
				if n[i] < 0x21 || n[i] > 0x7E {
					t.Fatalf("target %q holds octet 0x%02X", n, n[i])
				}
			}
		}
		if again := emlNames(SPFTargets(owner, set)); !emlSameWords(emlNames(targets), again) {
			t.Fatalf("SPFTargets is not deterministic: %q then %q", emlNames(targets), again)
		}
		for _, text := range emlJoined(set) {
			if len(text) > 4096 && len(set) == 1 && targets != nil {
				t.Fatalf("SPFTargets = %q for a record of %d octets", emlNames(targets), len(text))
			}
		}
	})
}

func FuzzDMARC(f *testing.F) {
	emlFuzzSeeds(f, "v=DMARC1; p=reject", "v=DMARC1; p=none; rua=mailto:a@corp.test!10m,mailto:x@evil.test; ruf=mailto:b@corp.test",
		"v = DMARC1 ; P = Reject ; pct=50; sp=quarantine; np=none; t=y; adkim=s; aspf=s; psd=y", "v=DMARC1; rua=mailto:a@corp.test",
		"v=DMARC1; p=bogus", "v=DMARC1; p=reject\x00v=DMARC1; p=none", "p=reject; v=DMARC1; ;;=; x")
	f.Fuzz(func(t *testing.T, was, now []byte, cut uint8) {
		emlFuzzWeaker(t, MailDMARC, emlDMARCOwner, was, now, cut)
	})
}

func FuzzDKIM(f *testing.F) {
	emlFuzzSeeds(f, emlKeyQ, emlKeyR, "v=DKIM1; k=ed25519; t=y:s; p=QUJD RA==", "p=QUJDRA==; s=email", "v=DKIM1; p=", "v=DKIM1; k=rsa; p=QUJDRA==\x00"+emlKeyR,
		"v=DKIM1; s=other; p=RUZHSA==; x=1;; ;", "v=DKIM1; p=QUJDRA==; p=RUZHSA==")
	f.Fuzz(func(t *testing.T, was, now []byte, cut uint8) {
		emlFuzzWeaker(t, MailDKIM, emlDKIMOwner, was, now, cut)
		// A CNAME beside the records is a signer too.
		o := expName(t, emlDKIMOwner)
		n := append(emlFuzzSet(now, cut), emlCNAME("s1.dkim.evil.test."))
		if got := Weaker(MailDKIM, o, n, n); got != nil {
			t.Fatalf("Weaker(x, x) = %q with a CNAME", got)
		}
		emlCheckWords(t, Weaker(MailDKIM, o, emlFuzzSet(was, cut), n))
	})
}

func FuzzMTASTSRecord(f *testing.F) {
	emlFuzzSeeds(f, "v=STSv1; id=20261117", "v=STSv1;id=1;", "v=STSv1 ; id=abc!", "v=STSv1; ; id=1", "v=stsv1; id=1", "v=STSv1; id=1; foo=bar; x_y=1\x00v=STSv1; id=2")
	f.Fuzz(func(t *testing.T, was, now []byte, cut uint8) {
		emlFuzzWeaker(t, MailMTASTS, emlSTSOwner, was, now, cut)
	})
}
