package pqaccum

// Clone returns a deep copy of the accumulator (its leaf list), so a caller can
// snapshot PQ state for reorg rollback without aliasing. The classical
// accumulator has an equivalent Clone used by the chain's reorg machinery.
func (a *Accumulator) Clone() *Accumulator {
	if a.streaming {
		cp := &Accumulator{streaming: true, count: a.count, peaks: make([]peak, len(a.peaks))}
		for i, p := range a.peaks {
			cp.peaks[i] = peak{hash: append([]byte(nil), p.hash...), size: p.size}
		}
		return cp
	}
	cp := &Accumulator{leaves: make([][]byte, len(a.leaves))}
	for i, l := range a.leaves {
		cp.leaves[i] = append([]byte(nil), l...)
	}
	return cp
}
