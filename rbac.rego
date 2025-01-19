package app.rbac
# By default, deny requests
default allow = false
# Allow admins to do anything
allow if {
    user_is_admin
}
# Allow bob to do anything
allow if {
    input.user == "bob"
}
# Allow the action if the user is granted permission to perform the action.
allow if {
    # Find permissions for the user.
    some permission
    user_is_granted[permission]
    # Check if the permission permits the action.
    input.action == permission.action
    input.type == permission.type
    # Unless the user location is outside the US
    country := data.users[input.user].location.country
    country == "US"
}
# user_is_admin is true if the user has the admin role
user_is_admin if {
    some i
    data.users[input.user].roles[i] == "admin"
}
# user_is_viewer is true if the user has the viewer role
user_is_viewer if {
    some i
    data.users[input.user].roles[i] == "viewer"
}
# user_is_guest is true if the user has the guest role
user_is_guest if {
    some i
    data.users[input.user].roles[i] == "guest"
}
# user_is_granted is a set of permissions for the user identified in the request
user_is_granted[permission] if {
    some i, j
    # `role` is an element of the user's roles
    role := data.users[input.user].roles[i]
    # `permission` is a single permission for the role
    permission := data.role_permissions[role][j]
}
