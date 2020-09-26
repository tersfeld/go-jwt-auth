package auth

// Type representing the required level (need to be admin, user, service account) to access a resource
type Type uint64

const (
	// AuthTypeUser means that a user account is required to access a resource
	AuthTypeUser Type = 1 << iota

	// AuthTypeAdmin means that an admin account is required to access a resource
	AuthTypeAdmin Type = 2

	// AuthTypeServiceAccount means that a service account is required to access a resource
	AuthTypeServiceAccount Type = 4

	// AuthTypeAll means that any account type can access the ressource (anonymous not allowed)
	AuthTypeAll Type = 8
)

// HasFlag is useful to check if the current route got the specific user flag
// We can protect a route like AuthTypeAdmin | AuthTypeServiceAccount, it should then allow only those two types
func (t Type) HasFlag(flag Type) bool {
	return t|flag == t
}
