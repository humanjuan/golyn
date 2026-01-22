package hierarchy

import "strings"

const (
	RoleSuperAdmin = "superadmin"
	RoleAdmin      = "admin"
	RoleUser       = "user"
)

var roleWeights = map[string]int{
	RoleSuperAdmin: 3,
	RoleAdmin:      2,
	RoleUser:       1,
}

func GetRoleWeight(role string) int {
	if weight, ok := roleWeights[strings.ToLower(role)]; ok {
		return weight
	}
	return 0
}

func CanManage(actorRole, targetRole string) bool {
	actorWeight := GetRoleWeight(actorRole)
	targetWeight := GetRoleWeight(targetRole)
	if actorRole == RoleSuperAdmin && targetRole == RoleSuperAdmin {
		return true
	}
	return actorWeight > targetWeight
}

func CanCreate(actorRole, targetRole string) bool {
	actorWeight := GetRoleWeight(actorRole)
	targetWeight := GetRoleWeight(targetRole)
	if actorRole == RoleSuperAdmin && targetRole == RoleSuperAdmin {
		return true
	}
	return actorWeight > targetWeight
}
