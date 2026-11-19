package dnswire

// Exchange stands for the function that sends a query and reads the answer.
func Exchange(q []byte) ([]byte, error) {
	return q, nil
}
