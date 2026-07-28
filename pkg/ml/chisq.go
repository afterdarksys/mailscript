package ml

import "math"

// ChiSquareP returns the upper-tail probability of the chi-square
// distribution: P(X > x) for X with the given degrees of freedom.
//
// Only even degrees of freedom are supported, which is all Fisher's method
// needs: combining n token probabilities always yields 2n. For even df the
// survival function has a closed form and reduces to summing the terms of a
// Poisson series, so no numerical integration or gamma function is required.
//
//	P(X > x) = exp(-m) * sum_{i=0}^{df/2-1} m^i / i!    where m = x/2
//
// The series is accumulated iteratively (each term is the previous one times
// m/i) so the factorial never has to be computed and cannot overflow.
func ChiSquareP(x float64, df int) float64 {
	if df <= 0 || df%2 != 0 {
		// Fisher's method never produces odd or zero degrees of freedom.
		// Returning 1 keeps a caller that hits this from reading it as
		// evidence in either direction.
		return 1.0
	}
	if x <= 0 {
		return 1.0
	}
	// exp(-m) underflows to zero past roughly m = 745, at which point the
	// upper tail is indistinguishable from zero anyway.
	m := x / 2
	if m > 745 {
		return 0.0
	}

	term := math.Exp(-m)
	sum := term
	for i := 1; i < df/2; i++ {
		term *= m / float64(i)
		sum += term
	}

	// Floating-point error can push the sum a hair above 1.
	if sum > 1.0 {
		return 1.0
	}
	if sum < 0 {
		return 0.0
	}
	return sum
}

// safeLog returns the natural log of p, clamped away from zero so that a
// token probability of exactly 0 or 1 cannot produce an infinite score.
//
// Robinson's f(w) is already smoothed away from the endpoints, but a caller
// supplying raw probabilities would otherwise poison the whole sum with a
// single infinity.
func safeLog(p float64) float64 {
	const epsilon = 1e-12
	if p < epsilon {
		p = epsilon
	}
	if p > 1-epsilon {
		p = 1 - epsilon
	}
	return math.Log(p)
}
