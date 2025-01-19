package utils
hasPermission(grants, roles) if {
	some i
	grants[i] == roles[i]
}
