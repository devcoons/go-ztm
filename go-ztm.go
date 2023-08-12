package go_ztm

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	aJWT "github.com/devcoons/go-auth-jwt"
	c "github.com/devcoons/go-fmt-colors"
	"github.com/gin-gonic/gin"
	"github.com/go-redis/redis/v8"
	"github.com/logrusorgru/aurora"
	"github.com/mitchellh/mapstructure"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
)

func (u *Service) Initialize(cfgpath string) bool {
	var err error

	u.Config = &ServiceConfiguration{}
	r := u.Config.Load(cfgpath)
	fmt.Println(c.FmtFgBgWhiteLBlue+"[ IMS ]"+c.FmtReset, c.FmtFgBgWhiteBlue+" INFO "+c.FmtReset, c.FmtFgBgWhiteBlack+" Loading service configuration for: "+u.Config.Ims.Title+"."+c.FmtReset)

	if !r {
		return false
	}

	u.cfgFilepath = cfgpath

	if u.Config.RedisDB.Host != "" {
		fmt.Println(c.FmtFgBgWhiteLBlue+"[ IMS ]"+c.FmtReset, c.FmtFgBgWhiteBlue+" INFO "+c.FmtReset, c.FmtFgBgWhiteBlack+"Redis Instance will be available"+c.FmtReset)

		u.Rdb = redis.NewClient(&redis.Options{
			Addr:     u.Config.RedisDB.Host + ":" + strconv.Itoa(u.Config.RedisDB.Port),
			Username: u.Config.RedisDB.Username,
			Password: u.Config.RedisDB.Password,
			DB:       u.Config.RedisDB.DB,
		})
		var ctx = context.Background()
		u.Rdb.FlushDB(ctx)

	} else {
		fmt.Println(aurora.BgBrightYellow("[ IMS ] Redis Instance will NOT be available.."))
	}

	if u.Config.Secrets != nil {
		for _, s := range u.Config.Secrets {
			if strings.ToLower(s.Name) == "sjwt" {
				fmt.Println(c.FmtFgBgWhiteLBlue+"[ IMS ]"+c.FmtReset, c.FmtFgBgWhiteBlue+" INFO "+c.FmtReset, c.FmtFgBgWhiteBlack+"SJWT Token will be available"+c.FmtReset)
				u.SJwt = &aJWT.AuthJWT{}
				u.SJwt.SecretKey = s.Secret
				u.SJwt.TokenDuration = time.Duration(s.Duration) * time.Second
				u.SJwt.AuthType = s.AuthType
			}
			if strings.ToLower(s.Name) == "ujwt" {
				fmt.Println(c.FmtFgBgWhiteLBlue+"[ IMS ]"+c.FmtReset, c.FmtFgBgWhiteBlue+" INFO "+c.FmtReset, c.FmtFgBgWhiteBlack+"UJWT Token will be available"+c.FmtReset)
				u.UJwt = &aJWT.AuthJWT{}
				u.UJwt.SecretKey = s.Secret
				u.UJwt.TokenDuration = time.Duration(s.Duration) * time.Second
				u.UJwt.AuthType = s.AuthType
			}
		}
	} else {
		fmt.Println(aurora.BgRed("[ IMS ] Microservice cannot work without Secrets"))
		return false
	}

	if u.Config.Database.Host != "" {
		u.Database = &gorm.DB{}

		dsn := u.Config.Database.Username + ":" + u.Config.Database.Password + "@tcp("
		dsn += u.Config.Database.Host + ":" + strconv.Itoa(u.Config.Database.Port) + ")/"
		dsn += u.Config.Database.DbName + "?parseTime=true"

		for i := 1; i <= 5; i++ {
			fmt.Println(c.FmtFgBgWhiteLBlue+"[ IMS ]"+c.FmtReset, c.FmtFgBgWhiteBlue+" INFO "+c.FmtReset, c.FmtFgBgWhiteBlack+"Connecting SQL database: "+u.Config.Database.Host+":"+strconv.Itoa(u.Config.Database.Port)+c.FmtReset)

			u.Database, err = gorm.Open(mysql.Open(dsn), &gorm.Config{})
			if err != nil {
				fmt.Println(aurora.BgBrightYellow("[ IMS ] Connection failed. Retring in 7 seconds.."))
				time.Sleep(7 * time.Second)
			} else {
				fmt.Println(c.FmtFgBgWhiteLBlue+"[ IMS ]"+c.FmtReset, c.FmtFgBgWhiteBlue+" INFO "+c.FmtReset, c.FmtFgBgWhiteBlack+"Connection succesfully completed"+c.FmtReset)
				break
			}
		}
	} else {
		fmt.Println(aurora.BgBrightYellow("[ IMS ] Sql Database will NOT be available.."))
	}

	return err == nil
}

func (u *ServiceConfiguration) Load(dbconfig string) bool {

	fmt.Println(c.FmtFgBgWhiteLBlue+"[ IMS ]"+c.FmtReset, c.FmtFgBgWhiteBlue+" INFO "+c.FmtReset, c.FmtFgBgWhiteBlack+"Loading configuration file ("+dbconfig+")"+c.FmtReset)

	jsonFile, err := os.Open(dbconfig)
	if err != nil {
		fmt.Println(c.FmtFgBgWhiteLBlue+"[ IMS ]"+c.FmtReset, c.FmtFgBgWhiteRed+" ERRN "+c.FmtReset, c.FmtFgBgWhiteBlack+"Cannot open the configuration file"+c.FmtReset)
		return false
	}
	byteValue, err := io.ReadAll(jsonFile)
	if err != nil {
		fmt.Println(c.FmtFgBgWhiteLBlue+"[ IMS ]"+c.FmtReset, c.FmtFgBgWhiteRed+" ERRN "+c.FmtReset, c.FmtFgBgWhiteBlack+"Cannot read the configuration file"+c.FmtReset)
		return false
	}
	err = json.Unmarshal(byteValue, u)

	if err != nil {
		fmt.Println(c.FmtFgBgWhiteLBlue+"[ IMS ]"+c.FmtReset, c.FmtFgBgWhiteRed+" ERRN "+c.FmtReset, c.FmtFgBgWhiteBlack+"Cannot parse the configuration file"+c.FmtReset)
		return false
	}

	fmt.Println(c.FmtFgBgWhiteLBlue+"[ IMS ]"+c.FmtReset, c.FmtFgBgWhiteBlue+" INFO "+c.FmtReset, c.FmtFgBgWhiteBlack+"Loading configuration file ("+dbconfig+")"+c.FmtReset)

	return true
}

func (u *ServiceConfiguration) AddService(name string, host string, port int, url string) {
	var exists bool = false

	for _, srv := range u.Services {

		if srv.Name == name {
			exists = true
		}
	}
	if !exists {
		u.Services = append(u.Services, serviceConfigurationService{name, host, port, url})
	}
}

func (u *ServiceConfiguration) RemoveService(name string) {

	var t []serviceConfigurationService
	for _, srv := range u.Services {

		if srv.Name != name {
			t = append(t, srv)
		}
	}
	u.Services = t
}

func (u *Service) SaveConfiguration() bool {

	file, er2 := os.Create(u.cfgFilepath)
	if er2 != nil {
		return false
	}

	r, er3 := json.Marshal(u.Config)
	if er3 != nil {
		return false
	}

	_, er4 := file.Write(r)
	if er4 != nil {
		return false
	}

	er5 := file.Close()
	return er5 == nil
}

func AddUSEService(u *Service) gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Set("service", u)
		c.Next()
	}
}

func (u *Service) IssueNewUserJWT(claims UJWTClaims) (string, bool) {

	var ctx = context.Background()
	if u.Rdb == nil {
		return "", false
	}
	_, err := u.Rdb.Get(ctx, strconv.Itoa(claims.UserId)).Result()
	if err == nil {
		_, _ = u.Rdb.Del(ctx, strconv.Itoa(claims.UserId)).Result()
	}
	u.Rdb.Set(ctx, strconv.Itoa(claims.UserId), claims.Nonce, 0)
	token := u.UJwt.GenerateJWT(claims)

	return token, true
}

func (u *Service) ValidateUserJWT(r *http.Request) *UJWTClaims {

	if u.Rdb == nil {
		return nil
	}

	iclaims, ok := u.UJwt.IsAuthorized(r)
	if !ok {
		return nil
	}

	var claims UJWTClaims
	var claimsmin UJWTClaimsMinimal
	err := mapstructure.Decode(iclaims, &claimsmin)

	if err != nil {
		return nil
	}
	claims.Auth = claimsmin.A
	claims.Nonce = claimsmin.N
	claims.Role = claimsmin.R
	claims.UserId = claimsmin.U
	claims.SysAdm = claimsmin.S

	res := u.CompareUserNonce(claims.UserId, claims.Nonce)

	if res {
		return &claims
	}
	return nil
}

func (u *Service) ValidateServiceJWT(r *http.Request) *SJWTClaims {

	if u.Rdb == nil {
		return nil
	}

	iclaims, ok := u.SJwt.IsAuthorized(r)

	if !ok {
		return nil
	}

	var claims SJWTClaims
	err := mapstructure.Decode(iclaims, &claims)

	if err != nil {
		return nil
	}

	return &claims
}

func (u *Service) UpdateUserNonce(userId int, userNonce string) bool {

	var ctx = context.Background()
	if u.Rdb == nil {
		return false
	}

	_, err := u.Rdb.Get(ctx, strconv.Itoa(userId)).Result()
	if err == nil {
		_, _ = u.Rdb.Del(ctx, strconv.Itoa(userId)).Result()
	}
	u.Rdb.Set(ctx, strconv.Itoa(userId), userNonce, 0)

	for _, gw := range u.Config.Gateways {

		var sclaims SJWTClaims
		sclaims.Auth = true
		sclaims.UserId = userId
		sclaims.Role = 0
		sclaims.Service = u.Config.Ims.Abbeviation
		sclaims.SysAdm = false

		token := u.SJwt.GenerateJWT(sclaims)

		client := &http.Client{}
		req, _ := http.NewRequest("GET", gw.Host+":"+strconv.Itoa(gw.Port)+"/syncunc", nil)
		req.Header.Del("Authorization")
		req.Header.Add("Authorization", "X-Fowarder "+token)
		req.Body = nil
		client.Do(req)
	}
	return true
}

func (u *Service) ReloadUserNonceFromDB(userId int, userNonce string) bool {

	var ctx = context.Background()
	if u.Rdb == nil {
		return false
	}

	_, err := u.Rdb.Get(ctx, strconv.Itoa(userId)).Result()
	if err == nil {
		_, _ = u.Rdb.Del(ctx, strconv.Itoa(userId)).Result()
	}
	u.Rdb.Set(ctx, strconv.Itoa(userId), userNonce, 0)

	return true
}

func (u *Service) CompareUserNonce(userId int, nonce string) bool {

	var ctx = context.Background()
	if u.Rdb == nil {
		return false
	}

	rdb_nonce, err := u.Rdb.Get(ctx, strconv.Itoa(userId)).Result()
	if err == nil && rdb_nonce == nonce {
		return true
	}

	var sclaims SJWTClaims
	sclaims.Auth = true
	sclaims.Role = 0
	sclaims.UserId = userId
	sclaims.Service = u.Config.Ims.Abbeviation
	sclaims.SysAdm = false
	sclaims.Hop = 2
	token := u.SJwt.GenerateJWT(sclaims)
	client := &http.Client{}
	req, _ := http.NewRequest("GET", u.Config.PathNonce.Host+":"+strconv.Itoa(u.Config.PathNonce.Port)+u.Config.PathNonce.URL, nil)
	req.Header.Del("Authorization")
	req.Header.Add("Authorization", u.SJwt.AuthType+" "+token)
	req.Body = nil
	res, errn := client.Do(req)

	values := UnmashalBody(res.Body)

	if errn != nil || values == nil {
		return false
	}

	db_nonce := values["nonce"].(string)
	if db_nonce != nonce {
		return false
	}

	u.Rdb.Set(ctx, strconv.Itoa(userId), db_nonce, 0)
	return true
}

func (u *Service) DeleteUserNonceFromDB(userId int) bool {

	var ctx = context.Background()
	if u.Rdb == nil {
		return false
	}
	_, err := u.Rdb.Get(ctx, strconv.Itoa(userId)).Result()
	if err == nil {
		_, _ = u.Rdb.Del(ctx, strconv.Itoa(userId)).Result()
	} else {
	}

	return true
}

func UnmashalBody(body io.ReadCloser) map[string]interface{} {
	var values map[string]interface{}

	bbody, err := io.ReadAll(body)

	if err != nil {
		return nil
	}

	json.Unmarshal([]byte(bbody), &values)
	return values
}

func (u *Service) ClearUserNonceFromAll(userId int) bool {

	u.DeleteUserNonceFromDB(userId)

	errns := 0
	var sclaims SJWTClaims
	sclaims.Auth = true
	sclaims.Hop = 2
	sclaims.Role = 9
	sclaims.Service = u.Config.Ims.Abbeviation
	sclaims.SysAdm = false
	sclaims.UserId = userId

	token := u.SJwt.GenerateJWT(sclaims)

	for _, gateway := range u.Config.Gateways {
		gclient := &http.Client{}
		req1, _ := http.NewRequest("DELETE", gateway.Host+":"+strconv.Itoa(gateway.Port)+"/nonce", nil)
		req1.Header.Del("Authorization")
		req1.Header.Add("Authorization", u.SJwt.AuthType+" "+token)
		req1.Body = nil
		_, errn := gclient.Do(req1)
		if errn != nil {
			errns = errns + 1
		}
	}
	return errns == 0
}

func (u *Service) RefreshUserNonceFromAll(userId int) bool {

	var sclaims SJWTClaims
	sclaims.Auth = true
	sclaims.Hop = 2
	sclaims.Role = 9
	sclaims.Service = u.Config.Ims.Abbeviation
	sclaims.SysAdm = false
	sclaims.UserId = userId

	token := u.SJwt.GenerateJWT(sclaims)
	client := &http.Client{}
	req, _ := http.NewRequest("PATCH", u.Config.PathNonce.Host+":"+strconv.Itoa(u.Config.PathNonce.Port)+u.Config.PathNonce.URL, nil)
	req.Header.Del("Authorization")
	req.Header.Add("Authorization", u.SJwt.AuthType+" "+token)
	req.Body = nil
	client.Do(req)
	return u.ClearUserNonceFromAll(userId)
}

func (u *Service) IsUserAdmin(claims *UJWTClaims) bool {

	if claims == nil || claims.UserId == -1 || !claims.Auth {
		return false
	}

	var sclaims SJWTClaims
	sclaims.Auth = claims.Auth
	sclaims.Role = claims.Role
	sclaims.UserId = claims.UserId
	sclaims.Service = u.Config.Ims.Abbeviation
	sclaims.SysAdm = claims.SysAdm
	sclaims.Hop = 5

	token := u.SJwt.GenerateJWT(sclaims)
	client := &http.Client{}
	req, _ := http.NewRequest("GET", u.Config.PathAdmin.Host+":"+strconv.Itoa(u.Config.PathAdmin.Port)+u.Config.PathAdmin.URL, nil)
	req.Header.Del("Authorization")
	req.Header.Add("Authorization", u.SJwt.AuthType+" "+token)
	res, errn := client.Do(req)
	if errn == nil {

		var values = UnmashalBody(res.Body)
		if values["admin"] == nil || values["enabled"] == nil || values["username"] == nil || values["id"] == nil {
			return false
		}
		if values["admin"].(bool) {
			return true
		}
	}
	return false
}

func (u *Service) RequestWithClaims(path string, method string, header http.Header, body io.ReadCloser, claims SJWTClaims) (*http.Response, error) {

	if path == "" || method == "" {
		return nil, errors.New("Failed")
	}

	token := u.SJwt.GenerateJWT(claims)
	client := &http.Client{}
	req, e := http.NewRequest(method, path, body)

	if e != nil {
		return nil, errors.New("Request issue")
	}

	if header != nil {
		req.Header = header
	}
	req.Header.Set("Authorization", u.SJwt.AuthType+" "+token)
	res, errn := client.Do(req)
	if errn != nil || res.StatusCode != 200 {
		return nil, errors.New("Failed")
	}

	return res, nil
}

func (u *Service) Request(path string, method string, header http.Header, body io.ReadCloser) (*http.Response, error) {

	if path == "" || method == "" {
		return nil, errors.New("Failed")
	}

	client := &http.Client{}
	req, e := http.NewRequest(method, path, body)

	if e != nil {
		return nil, errors.New("Request issue")
	}

	if header != nil {
		req.Header = header
	}

	res, errn := client.Do(req)
	if errn != nil || res.StatusCode != 200 {
		return nil, errors.New("Failed")
	}

	return res, nil
}

func (u *Service) GWRequest(url string, method string, header http.Header, body io.ReadCloser, claims SJWTClaims) (*http.Response, error) {

	if url == "" || method == "" {
		return nil, errors.New("Failed")
	}
	url = u.Config.Gateways[len(u.Config.Gateways)-1].Host + ":" + strconv.Itoa(u.Config.Gateways[len(u.Config.Gateways)-1].Port) + url
	claims.Service = u.Config.Ims.Abbeviation
	token := u.SJwt.GenerateJWT(claims)
	client := &http.Client{}

	req, _ := http.NewRequest(method, url, body)

	if header != nil {
		req.Header = header
	}
	req.Header.Set("Authorization", u.SJwt.AuthType+" "+token)

	res, errn := client.Do(req)

	if errn != nil || res.StatusCode != 200 {
		return nil, errors.New("Failed")
	}
	return res, nil
}

func (u *Service) SRVRequest(path string, method string, header http.Header, body io.ReadCloser, claims SJWTClaims) (*http.Response, error) {

	if path == "" || method == "" {
		return nil, errors.New("Failed")
	}
	var node serviceConfigurationService
	var requestedPath = strings.TrimRight(path, "/")

	for _, nodeDetails := range u.Config.Services {
		m, _ := regexp.MatchString(nodeDetails.URL, requestedPath)
		if m {

			node = nodeDetails
			url := node.Host + ":" + strconv.Itoa(node.Port) + path
			claims.Service = u.Config.Ims.Abbeviation
			token := u.SJwt.GenerateJWT(claims)
			client := &http.Client{}

			req, _ := http.NewRequest(method, url, body)

			if header != nil {
				req.Header = header
			}
			req.Header.Set("Authorization", u.SJwt.AuthType+" "+token)

			res, errn := client.Do(req)

			if errn != nil || res.StatusCode != 200 {
				return nil, errors.New("Failed")
			}

			return res, nil
		}
	}
	return nil, nil
}

func (u *Service) RequestForwarder(c *gin.Context) {

	var requestedPath = strings.TrimRight(c.Request.URL.Path, "/")
	var requestedUrlQuery = c.Request.URL.RawQuery

	for _, nodeDetails := range u.Config.Services {

		m, _ := regexp.MatchString(nodeDetails.URL, requestedPath)

		if m {

			var sclaims SJWTClaims

			claims := u.ValidateUserJWT(c.Request)
			if claims == nil {

				dclaims := u.ValidateServiceJWT(c.Request)
				if dclaims == nil {
					sclaims.Auth = false
					sclaims.Role = 0
					sclaims.UserId = -1
					sclaims.Service = u.Config.Ims.Abbeviation
					sclaims.Hop = 5
					sclaims.SysAdm = false
				} else {
					sclaims = *dclaims
					sclaims.Hop = sclaims.Hop - 1
				}
			} else {
				sclaims.Auth = claims.Auth
				sclaims.Role = claims.Role
				sclaims.UserId = claims.UserId
				sclaims.Service = u.Config.Ims.Abbeviation
				sclaims.SysAdm = claims.SysAdm
				sclaims.Hop = 5
			}

			token := u.SJwt.GenerateJWT(sclaims)
			client := &http.Client{}
			req, _ := http.NewRequest(c.Request.Method, nodeDetails.Host+":"+strconv.Itoa(nodeDetails.Port)+requestedPath+"?"+requestedUrlQuery, c.Request.Body)
			req.Header = c.Request.Header
			req.Header.Set("Authorization", u.SJwt.AuthType+" "+token)
			res, errn := client.Do(req)
			if errn == nil {
				body, _ := io.ReadAll(res.Body)
				c.Data(res.StatusCode, res.Header.Get("Content-Type"), body)
			} else {
				c.Data(503, "application/json", nil)
			}
			return
		}
	}
}

func (u *Service) servicesHealthCheck() {
	var tServicesSts []ServicesStatus

	for _, nodeDetails := range u.Config.Services {
		var sclaims SJWTClaims
		sclaims.Auth = false
		sclaims.Role = 0
		sclaims.UserId = -1
		sclaims.Service = u.Config.Ims.Abbeviation
		sclaims.SysAdm = false
		sclaims.Hop = 1
		tServicesSts = append(tServicesSts, ServicesStatus{Name: nodeDetails.Name, IsAlive: false})
	}
	u.ServicesSts = tServicesSts

	for {
		var tServicesSts []ServicesStatus
		for _, nodeDetails := range u.Config.Services {
			var sclaims SJWTClaims
			sclaims.Auth = false
			sclaims.Role = 0
			sclaims.UserId = -1
			sclaims.Service = u.Config.Ims.Abbeviation
			sclaims.SysAdm = false
			sclaims.Hop = 1
			token := u.SJwt.GenerateJWT(sclaims)
			res, data := u.serviceHealthPing(nodeDetails.Host+":"+strconv.Itoa(nodeDetails.Port)+nodeDetails.URL+"/ztm-framework/services/status", token)
			tServicesSts = append(tServicesSts, ServicesStatus{Name: nodeDetails.Name, IsAlive: res, Services: data})
		}
		u.ServicesSts = tServicesSts
		time.Sleep(7 * time.Second)
	}
}

func (u *Service) serviceHealthPing(url string, token string) (bool, []map[string]any) {
	client := &http.Client{Timeout: 5 * time.Second}
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Del("Authorization")
	req.Header.Add("Authorization", u.SJwt.AuthType+" "+token)
	req.Body = nil
	r, errn := client.Do(req)
	var result []map[string]any

	if errn == nil {
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &result)
	}

	return errn == nil, result
}

func (u *Service) Start(router *gin.Engine) {

	router.GET(strings.ReplaceAll(u.Config.Ims.RootPath+"/ztm-framework/services/status", "//", "/"), func(c *gin.Context) {
		c.IndentedJSON(200, u.ServicesSts)
	})

	router.GET(strings.ReplaceAll(u.Config.Ims.RootPath+"/ztm-framework/gateways", "//", "/"), func(c *gin.Context) {
		c.IndentedJSON(200, u.Config.Gateways)
	})

	router.GET(strings.ReplaceAll(u.Config.Ims.RootPath+"/ztm-framework/configuration", "//", "/"), func(c *gin.Context) {
		claims := u.ValidateUserJWT(c.Request)
		if !u.IsUserAdmin(claims) {
			c.IndentedJSON(http.StatusForbidden, ErrorMsg{ErrorCode: "GW-S-0001", Message: "Admin only operation."})
			return
		}
		c.IndentedJSON(http.StatusOK, u.Config)
	})

	router.POST(strings.ReplaceAll(u.Config.Ims.RootPath+"/ztm-framework/services", "//", "/"), func(c *gin.Context) {
		claims := u.ValidateUserJWT(c.Request)
		if !u.IsUserAdmin(claims) {
			c.IndentedJSON(http.StatusForbidden, ErrorMsg{ErrorCode: "GW-S-0002", Message: "Admin only operation."})
			return
		}
		values := UnmashalBody(c.Request.Body)
		if values == nil {
			c.IndentedJSON(http.StatusPreconditionFailed, ErrorMsg{ErrorCode: "GW-S-0010", Message: "Missing values."})
			return
		}
		if len(values["name"].(string)) < 3 || len(values["host"].(string)) < 3 || values["port"] == nil || len(values["url"].(string)) < 3 {
			c.IndentedJSON(http.StatusBadRequest, ErrorMsg{ErrorCode: "GW-S-0010", Message: "Missing values or wrong lengths"})
			return
		}
		port := ConvertToInt(values["port"], 0)
		if port == 0 {
			c.IndentedJSON(http.StatusNotAcceptable, ErrorMsg{ErrorCode: "GW-S-0020", Message: "Parameter 'port' has invalid data"})
			return
		}
		u.Config.AddService(values["name"].(string), values["host"].(string), port, values["url"].(string))
		c.Data(200, "application/json", nil)
	})

	router.PUT(strings.ReplaceAll(u.Config.Ims.RootPath+"/ztm-framework/configuration", "//", "/"), func(c *gin.Context) {
		claims := u.ValidateUserJWT(c.Request)
		if !u.IsUserAdmin(claims) {
			c.IndentedJSON(http.StatusForbidden, ErrorMsg{ErrorCode: "GW-S-0003", Message: "Admin only operation."})
			return
		}
		if u.SaveConfiguration() {
			c.Data(200, "application/json", nil)
			return
		}
		c.IndentedJSON(http.StatusForbidden, ErrorMsg{ErrorCode: "GW-S-0013", Message: "Configuration could not be saved."})
	})

	router.DELETE(strings.ReplaceAll(u.Config.Ims.RootPath+"/ztm-framework/services", "//", "/"), func(c *gin.Context) {
		claims := u.ValidateUserJWT(c.Request)
		if !u.IsUserAdmin(claims) {
			c.IndentedJSON(http.StatusForbidden, ErrorMsg{ErrorCode: "GW-S-0004", Message: "Admin only operation."})
			return
		}
		values := UnmashalBody(c.Request.Body)
		if values == nil {
			c.IndentedJSON(http.StatusPreconditionFailed, ErrorMsg{ErrorCode: "GW-S-0050", Message: "Missing values."})
			return
		}
		if len(values["name"].(string)) < 3 {
			c.IndentedJSON(http.StatusNotAcceptable, ErrorMsg{ErrorCode: "GW-S-0020", Message: "Parameter 'name' has invalid data"})
			return
		}
		u.Config.RemoveService(values["name"].(string))
		c.Data(200, "application/json", nil)
	})

	router.NoRoute(u.RequestForwarder)
	go u.servicesHealthCheck()
}
