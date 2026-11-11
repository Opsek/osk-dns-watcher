package dnswire

import "encoding/binary"

// AppendRData appends the wire form of d, with names uncompressed. The types
// of NSEC and NSEC3 are written sorted and without duplicates.
func AppendRData(b []byte, d RData) []byte { return d.appendData(b) }

// AppendRecord appends the wire form of r, with names uncompressed.
func AppendRecord(b []byte, r Record) []byte {
	b = r.Name.AppendWire(b)
	b = binary.BigEndian.AppendUint16(b, uint16(r.Type()))
	b = binary.BigEndian.AppendUint16(b, uint16(r.Class))
	b = binary.BigEndian.AppendUint32(b, r.TTL)
	at := len(b)
	b = AppendRData(append(b, 0, 0), r.Data)
	binary.BigEndian.PutUint16(b[at:], uint16(len(b)-at-2))
	return b
}

// Canonical gives r in the canonical form of RFC 4034 section 6.2, items 2
// and 3, as RFC 6840 section 5.1 corrects them: the owner and the names in
// the data of NS, CNAME, SOA, MX, DNAME, PTR and the RRSIG signer in lower
// case, and so the names inside the Unknown data of SRV, NAPTR, RP, AFSDB,
// KX, PX, RT, MINFO, MB, MG, MR, MD and MF. Such data that does not fit its
// type, a name with a pointer for one, stays as it is. The next name of
// NSEC keeps its case.
func Canonical(r Record) Record {
	r.Name = r.Name.Lower()
	switch d := r.Data.(type) {
	case Unknown:
		if layout, ok := unknownNames[d.TypeCode]; ok {
			if data, err := expandNames(d.Data, 0, layout, false, true); err == nil {
				r.Data = Unknown{TypeCode: d.TypeCode, Data: data}
			}
		}
	case NS:
		d.Host = d.Host.Lower()
		r.Data = d
	case CNAME:
		d.Target = d.Target.Lower()
		r.Data = d
	case DNAME:
		d.Target = d.Target.Lower()
		r.Data = d
	case PTR:
		d.Target = d.Target.Lower()
		r.Data = d
	case SOA:
		d.MName, d.RName = d.MName.Lower(), d.RName.Lower()
		r.Data = d
	case MX:
		d.Exchange = d.Exchange.Lower()
		r.Data = d
	case RRSIG:
		d.SignerName = d.SignerName.Lower()
		r.Data = d
	}
	return r
}
