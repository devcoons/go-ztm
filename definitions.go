package go_ztm

import (
	aJWT "github.com/devcoons/go-auth-jwt"
	"github.com/go-redis/redis/v8"
	"gorm.io/gorm"
)

type SJWTClaims struct {
	Auth    bool   `json:"auth"`
	UserId  int    `json:"userid"`
	Role    int    `json:"role"`
	Service string `json:"service"`
	Hop     int    `json:"hop"`
	SysAdm  bool   `json:"sysadm"`
}

type UJWTClaims struct {
	Auth   bool   `json:"a"`
	UserId int    `json:"u"`
	Role   int    `json:"r"`
	SysAdm bool   `json:"s"`
	Nonce  string `json:"n"`
}

type UJWTClaimsMinimal struct {
	A bool   `json:"a"`
	U int    `json:"u"`
	R int    `json:"r"`
	S bool   `json:"s"`
	N string `json:"n"`
}

type ErrorMsg struct {
	ErrorCode string `json:"code"`
	Message   string `json:"message"`
}

type ServicesStatus struct {
	Name     string
	IsAlive  bool
	Services []map[string]any
}

type imsConfiguration struct {
	Title       string
	Abbeviation string
	RootPath    string
}

type serviceConfigurationJWT struct {
	Name     string
	Secret   string
	Duration int
	AuthType string
}

type serviceConfigurationDatabase struct {
	Host     string
	Port     int
	Username string
	Password string
	DbName   string
}

type serviceConfigurationService struct {
	Name string
	Host string
	Port int
	URL  string
}

type serviceConfigurationGateway struct {
	Host string
	Port int
}

type serviceConfigurationRedisDB struct {
	Host     string
	Port     int
	Username string
	Password string
	DB       int
}

type serviceConfigurationAuth struct {
	Host string
	Port int
	URL  string
}

type serviceConfigurationAdmin struct {
	Host string
	Port int
	URL  string
}

type serviceConfigurationRegister struct {
	Host string
	Port int
	URL  string
}

type serviceConfigurationNonce struct {
	Host string
	Port int
	URL  string
}

type ServiceConfiguration struct {
	Ims          imsConfiguration
	Secrets      []serviceConfigurationJWT
	Database     serviceConfigurationDatabase
	RedisDB      serviceConfigurationRedisDB
	Gateways     []serviceConfigurationGateway
	PathAuth     serviceConfigurationAuth
	PathRegister serviceConfigurationRegister
	PathNonce    serviceConfigurationNonce
	PathAdmin    serviceConfigurationAdmin
	Services     []serviceConfigurationService
}

type Service struct {
	UJwt        *aJWT.AuthJWT
	SJwt        *aJWT.AuthJWT
	Config      *ServiceConfiguration
	Database    *gorm.DB
	Rdb         *redis.Client
	ServicesSts []ServicesStatus
	cfgFilepath string
}
