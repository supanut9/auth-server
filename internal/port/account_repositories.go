package port

import (
	"context"

	"github.com/supanut9/auth-server/internal/domain"
)

type AccountRepository interface {
	Create(ctx context.Context, account domain.Account) (domain.Account, error)
	FindByID(ctx context.Context, id string) (domain.Account, error)
	FindByPrimaryVerifiedEmail(ctx context.Context, email string) (domain.Account, error)
	Update(ctx context.Context, account domain.Account) (domain.Account, error)
}

type AccountProviderRepository interface {
	Create(ctx context.Context, provider domain.AccountProvider) (domain.AccountProvider, error)
	FindByProviderAccountID(ctx context.Context, provider string, providerAccountID string) (domain.AccountProvider, error)
	FindByAccountIDAndProvider(ctx context.Context, accountID string, provider string) (domain.AccountProvider, error)
}
