package lib

// AnyError returns whether any of the given error is not nil
func AnyError(errs ...error) bool {
	for _, e := range errs {
		if e != nil {
			return true
		}
	}
	return false
}

// FirstError returns the first non-nil error in the given arguments, and
// otherwise retuens nil
func FirstError(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
