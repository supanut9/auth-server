package mail

import (
	"context"

	"github.com/supanut9/auth-server/internal/port"
)

type Message = port.MailMessage

type Sender interface {
	Send(ctx context.Context, message Message) error
}
