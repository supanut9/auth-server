package port

import "context"

type MailMessage struct {
	To      string
	Subject string
	Text    string
}

type MailSender interface {
	Send(ctx context.Context, message MailMessage) error
}
