package port

import "context"

type MailMessage struct {
	To      string
	Subject string
	Text    string
	// HTML is the optional HTML body. When set, the message is sent as
	// multipart/alternative with both plain text and HTML parts. When empty,
	// only the plain text part is sent.
	HTML string
}

type MailSender interface {
	Send(ctx context.Context, message MailMessage) error
}
