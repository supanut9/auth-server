package port

type OTPCodeGenerator interface {
	NewCode() (string, error)
}
