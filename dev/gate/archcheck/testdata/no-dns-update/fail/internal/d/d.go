package d

import (
	_ "log/syslog"
	"net/smtp"
	tp "net/textproto"
)

// Mail reaches the network through packages that dial on their own.
func Mail() error {
	if _, err := tp.Dial("tcp", "192.0.2.25:25"); err != nil {
		return err
	}
	return smtp.SendMail("192.0.2.25:25", nil, "a@example.test", nil, nil)
}
