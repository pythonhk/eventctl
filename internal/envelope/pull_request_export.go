package envelope

// ValidatePullRequestAddress exposes the strict v1 fork/PR/head-seal validator
// for trusted internal protocol packages such as isolated scoring.
func ValidatePullRequestAddress(value PullRequest) error {
	return validatePullRequest(value)
}
