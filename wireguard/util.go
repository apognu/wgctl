package wireguard

func anyError(errs ...error) bool {
	for _, e := range errs {
		if e != nil {
			return true
		}
	}
	return false
}

func firstError(errs ...error) error {
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
