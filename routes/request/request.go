// Package request holds the trust-anchor API request DTOs.
package request

import "azugo.io/azugo"

// ApproveBootstrap confirms which staged OJ bootstrap update is being
// activated. The reference must match the staged update so an operator can
// never approve a set other than the one they reviewed.
type ApproveBootstrap struct {
	OJReference string `json:"ojReference" validate:"required,min=1,max=64"`
}

// Validate implements azugo.Validator.
func (r *ApproveBootstrap) Validate(ctx *azugo.Context) error {
	return ctx.Validate().Struct(r)
}
