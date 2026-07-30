package security

import "context"

type URLScanner interface {
	CheckURL(ctx context.Context, targetURL string) (bool, error)
}
