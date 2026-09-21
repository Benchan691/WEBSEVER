# auth-service


**简介**:auth-service


**HOST**:https://test-accounthub.cloudtimes.net.cn/accounthub-api-gateway/auth


**联系人**:


**Version**:


**接口路径**:/auth/v3/api-docs


[TOC]






# SSO 登录-退出

## 账号密码登录（建立 SSO 全局会话）


**接口地址**:`/auth/user/oauth/login`


**请求方式**:`POST`


**请求数据类型**:`application/x-www-form-urlencoded,application/json`


**响应数据类型**:`application/json`


**接口描述**:<p>登录成功后：</p>
<ol>
<li>颁发用户服务中心 access/refresh token；</li>
<li>创建 SSO 全局会话并通过 Set-Cookie 下发 SESSIONID（HttpOnly），后续 /oauth2/authorize 等端点依赖该 Cookie 识别登录态；</li>
<li>登录方式由用户 loginType 或全局配置决定（本地密码 / RADIUS）。
连续失败达到阈值后需携带 captchaVerification（滑块验证码）；IP / 账号名失败次数超限会被临时锁定。</li>
</ol>



**请求参数**:


| 参数名称 | 参数说明 | 请求类型    | 是否必须 | 数据类型 | schema |
| -------- | -------- | ----- | -------- | -------- | ------ |
|password|密码（Base64 编码）|query|true|string||
|username|用户名（op 号）|query|true|string||
|captchaVerification|滑块验证码凭证，连续失败达到阈值后必填|query|false|string||


**响应状态**:


| 状态码 | 说明 | schema |
| -------- | -------- | ----- | 
|200|登录成功，Set-Cookie SESSIONID，data 为 token|object|
|401|用户名/密码错误、账号锁定/停用或验证码错误|object|


**响应状态码-200**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code|响应码，200 成功|integer||
|message|提示信息|string||
|data|用户服务中心 token|object||


**响应示例**:
```javascript
{
	"code": 0,
	"message": "",
	"data": {}
}
```


**响应状态码-401**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code|响应码，200 成功|integer||
|message|提示信息|string||


**响应示例**:
```javascript
{
	"code": 0,
	"message": ""
}
```


## SSO 全局退出


**接口地址**:`/auth/user/oauth/logout`


**请求方式**:`POST`


**请求数据类型**:`application/x-www-form-urlencoded`


**响应数据类型**:`application/json`


**接口描述**:<p>需携带 SESSIONID Cookie。销毁 SSO 全局会话、清理服务中心 token，并吊销该会话签发的 OAuth2 授权（access/refresh token），成功后 302 跳转登录页。单点退出所有接入子系统。</p>



**请求参数**:


暂无


**响应状态**:


| 状态码 | 说明 | schema |
| -------- | -------- | ----- | 
|200|退出成功（默认 302 跳转登录页）|object|
|302|跳转登录页||


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code|响应码，200 成功|integer||
|message|提示信息|string||


**响应示例**:
```javascript
{
	"code": 0,
	"message": ""
}
```

# 会话验证API


## active


**接口地址**:`/auth/open-api/v1/session/active`


**请求方式**:`POST`


**请求数据类型**:`application/x-www-form-urlencoded,application/json`


**响应数据类型**:`application/json,*/*`


**接口描述**:


**请求参数**:


暂无


**响应状态**:


| 状态码 | 说明 | schema |
| -------- | -------- | ----- | 
|200|OK|ResponseResultMapStringObject|
|404|Not Found|ResponseResultObject|


**响应状态码-200**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code||integer(int32)|integer(int32)|
|message||string||
|data||object||


**响应示例**:
```javascript
{
	"code": 0,
	"message": "",
	"data": {}
}
```


**响应状态码-404**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code||integer(int32)|integer(int32)|
|message||string||
|data||object||


**响应示例**:
```javascript
{
	"code": 0,
	"message": "",
	"data": {}
}
```


## get captcha code


**接口地址**:`/auth/open-api/v1/code/captcha/get`


**请求方式**:`POST`


**请求数据类型**:`application/x-www-form-urlencoded,application/json`


**响应数据类型**:`*/*`


**接口描述**:


**请求示例**:


```javascript
{
  "captchaId": "",
  "projectCode": "",
  "captchaType": "",
  "captchaOriginalPath": "",
  "captchaFontType": "",
  "captchaFontSize": 0,
  "secretKey": "",
  "originalImageBase64": "",
  "point": {
    "secretKey": "",
    "x": 0,
    "y": 0
  },
  "jigsawImageBase64": "",
  "wordList": [],
  "pointList": [
    {
      "x": 0,
      "y": 0
    }
  ],
  "pointJson": "",
  "token": "",
  "result": true,
  "captchaVerification": "",
  "clientUid": "",
  "ts": 0,
  "browserInfo": ""
}
```


**请求参数**:


| 参数名称 | 参数说明 | 请求类型    | 是否必须 | 数据类型 | schema |
| -------- | -------- | ----- | -------- | -------- | ------ |
|captchaVO|CaptchaVO|body|true|CaptchaVO|CaptchaVO|
|&emsp;&emsp;captchaId|||false|string||
|&emsp;&emsp;projectCode|||false|string||
|&emsp;&emsp;captchaType|||false|string||
|&emsp;&emsp;captchaOriginalPath|||false|string||
|&emsp;&emsp;captchaFontType|||false|string||
|&emsp;&emsp;captchaFontSize|||false|integer(int32)||
|&emsp;&emsp;secretKey|||false|string||
|&emsp;&emsp;originalImageBase64|||false|string||
|&emsp;&emsp;point|||false|PointVO|PointVO|
|&emsp;&emsp;&emsp;&emsp;secretKey|||false|string||
|&emsp;&emsp;&emsp;&emsp;x|||false|integer(int32)||
|&emsp;&emsp;&emsp;&emsp;y|||false|integer(int32)||
|&emsp;&emsp;jigsawImageBase64|||false|string||
|&emsp;&emsp;wordList|||false|array|string|
|&emsp;&emsp;pointList|||false|array|object|
|&emsp;&emsp;pointJson|||false|string||
|&emsp;&emsp;token|||false|string||
|&emsp;&emsp;result|||false|boolean||
|&emsp;&emsp;captchaVerification|||false|string||
|&emsp;&emsp;clientUid|||false|string||
|&emsp;&emsp;ts|||false|integer(int64)||
|&emsp;&emsp;browserInfo|||false|string||


**响应状态**:


| 状态码 | 说明 | schema |
| -------- | -------- | ----- | 
|200|OK|ResponseResultResponseModel|
|404|Not Found|ResponseResultObject|


**响应状态码-200**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code||integer(int32)|integer(int32)|
|message||string||
|data||ResponseModel|ResponseModel|
|&emsp;&emsp;repCode||string||
|&emsp;&emsp;repMsg||string||
|&emsp;&emsp;repData||object||
|&emsp;&emsp;success||boolean||
|&emsp;&emsp;repCodeEnum|可用值:SUCCESS,ERROR,EXCEPTION,BLANK_ERROR,NULL_ERROR,NOT_NULL_ERROR,NOT_EXIST_ERROR,EXIST_ERROR,PARAM_TYPE_ERROR,PARAM_FORMAT_ERROR,API_CAPTCHA_INVALID,API_CAPTCHA_COORDINATE_ERROR,API_CAPTCHA_ERROR,API_CAPTCHA_BASEMAP_NULL,API_REQ_LIMIT_GET_ERROR,API_REQ_INVALID,API_REQ_LOCK_GET_ERROR,API_REQ_LIMIT_CHECK_ERROR,API_REQ_LIMIT_VERIFY_ERROR|string||


**响应示例**:
```javascript
{
	"code": 0,
	"message": "",
	"data": {
		"repCode": "",
		"repMsg": "",
		"repData": {},
		"success": true,
		"repCodeEnum": ""
	}
}
```


**响应状态码-404**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code||integer(int32)|integer(int32)|
|message||string||
|data||object||


**响应示例**:
```javascript
{
	"code": 0,
	"message": "",
	"data": {}
}
```


## check captcha code


**接口地址**:`/auth/open-api/v1/code/captcha/check`


**请求方式**:`POST`


**请求数据类型**:`application/x-www-form-urlencoded,application/json`


**响应数据类型**:`*/*`


**接口描述**:


**请求示例**:


```javascript
{
  "captchaId": "",
  "projectCode": "",
  "captchaType": "",
  "captchaOriginalPath": "",
  "captchaFontType": "",
  "captchaFontSize": 0,
  "secretKey": "",
  "originalImageBase64": "",
  "point": {
    "secretKey": "",
    "x": 0,
    "y": 0
  },
  "jigsawImageBase64": "",
  "wordList": [],
  "pointList": [
    {
      "x": 0,
      "y": 0
    }
  ],
  "pointJson": "",
  "token": "",
  "result": true,
  "captchaVerification": "",
  "clientUid": "",
  "ts": 0,
  "browserInfo": ""
}
```


**请求参数**:


| 参数名称 | 参数说明 | 请求类型    | 是否必须 | 数据类型 | schema |
| -------- | -------- | ----- | -------- | -------- | ------ |
|captchaVO|CaptchaVO|body|true|CaptchaVO|CaptchaVO|
|&emsp;&emsp;captchaId|||false|string||
|&emsp;&emsp;projectCode|||false|string||
|&emsp;&emsp;captchaType|||false|string||
|&emsp;&emsp;captchaOriginalPath|||false|string||
|&emsp;&emsp;captchaFontType|||false|string||
|&emsp;&emsp;captchaFontSize|||false|integer(int32)||
|&emsp;&emsp;secretKey|||false|string||
|&emsp;&emsp;originalImageBase64|||false|string||
|&emsp;&emsp;point|||false|PointVO|PointVO|
|&emsp;&emsp;&emsp;&emsp;secretKey|||false|string||
|&emsp;&emsp;&emsp;&emsp;x|||false|integer(int32)||
|&emsp;&emsp;&emsp;&emsp;y|||false|integer(int32)||
|&emsp;&emsp;jigsawImageBase64|||false|string||
|&emsp;&emsp;wordList|||false|array|string|
|&emsp;&emsp;pointList|||false|array|object|
|&emsp;&emsp;pointJson|||false|string||
|&emsp;&emsp;token|||false|string||
|&emsp;&emsp;result|||false|boolean||
|&emsp;&emsp;captchaVerification|||false|string||
|&emsp;&emsp;clientUid|||false|string||
|&emsp;&emsp;ts|||false|integer(int64)||
|&emsp;&emsp;browserInfo|||false|string||


**响应状态**:


| 状态码 | 说明 | schema |
| -------- | -------- | ----- | 
|200|OK|ResponseResultResponseModel|
|404|Not Found|ResponseResultObject|


**响应状态码-200**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code||integer(int32)|integer(int32)|
|message||string||
|data||ResponseModel|ResponseModel|
|&emsp;&emsp;repCode||string||
|&emsp;&emsp;repMsg||string||
|&emsp;&emsp;repData||object||
|&emsp;&emsp;success||boolean||
|&emsp;&emsp;repCodeEnum|可用值:SUCCESS,ERROR,EXCEPTION,BLANK_ERROR,NULL_ERROR,NOT_NULL_ERROR,NOT_EXIST_ERROR,EXIST_ERROR,PARAM_TYPE_ERROR,PARAM_FORMAT_ERROR,API_CAPTCHA_INVALID,API_CAPTCHA_COORDINATE_ERROR,API_CAPTCHA_ERROR,API_CAPTCHA_BASEMAP_NULL,API_REQ_LIMIT_GET_ERROR,API_REQ_INVALID,API_REQ_LOCK_GET_ERROR,API_REQ_LIMIT_CHECK_ERROR,API_REQ_LIMIT_VERIFY_ERROR|string||


**响应示例**:
```javascript
{
	"code": 0,
	"message": "",
	"data": {
		"repCode": "",
		"repMsg": "",
		"repData": {},
		"success": true,
		"repCodeEnum": ""
	}
}
```


**响应状态码-404**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code||integer(int32)|integer(int32)|
|message||string||
|data||object||


**响应示例**:
```javascript
{
	"code": 0,
	"message": "",
	"data": {}
}
```


## 令牌校验


**接口地址**:`/auth/open-api/v1/token/check`


**请求方式**:`GET`


**请求数据类型**:`application/x-www-form-urlencoded`


**响应数据类型**:`*/*`


**接口描述**:<p>校验访问令牌有效性并返回用户信息。优先按 accessToken 查询授权信息，无效时回退校验 refreshToken：refreshToken 有效而 accessToken 无效视为 accessToken 已过期，两者均无效视为令牌非法。有效时返回 Redis 中的用户信息及令牌过期时间（expireTime，毫秒时间戳）。校验通过时 data 为用户信息（UserInfoVO，结构见响应 schema）</p>



**请求参数**:


| 参数名称 | 参数说明 | 请求类型    | 是否必须 | 数据类型 | schema |
| -------- | -------- | ----- | -------- | -------- | ------ |
|accessToken|访问令牌（access_token）|query|true|string||
|refreshToken|刷新令牌（refresh_token），accessToken 失效时用于回退校验|query|true|string||


**响应状态**:


| 状态码 | 说明 | schema |
| -------- | -------- | ----- | 
|200|OK|ResponseResultObject|
|404|Not Found|ResponseResultObject|
|500|令牌非法或已过期（业务码见 message）|ResponseResultUserInfoVO|


**响应状态码-200**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code||integer(int32)|integer(int32)|
|message||string||
|data||object||


**响应示例**:
```javascript
{
	"code": 0,
	"message": "",
	"data": {}
}
```


**响应状态码-404**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code||integer(int32)|integer(int32)|
|message||string||
|data||object||


**响应示例**:
```javascript
{
	"code": 0,
	"message": "",
	"data": {}
}
```


**响应状态码-500**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code||integer(int32)|integer(int32)|
|message||string||
|data||UserInfoVO|UserInfoVO|
|&emsp;&emsp;uid||integer(int64)||
|&emsp;&emsp;username||string||
|&emsp;&emsp;authorities||array|GrantedAuthority|
|&emsp;&emsp;&emsp;&emsp;authority||string||
|&emsp;&emsp;email||string||
|&emsp;&emsp;phone||string||
|&emsp;&emsp;position||string||
|&emsp;&emsp;organizationId||integer(int64)||
|&emsp;&emsp;sex||integer(int32)||
|&emsp;&emsp;name||string||
|&emsp;&emsp;loginType||integer(int32)||
|&emsp;&emsp;roles||array|AuthRole|
|&emsp;&emsp;&emsp;&emsp;roleName||string||
|&emsp;&emsp;&emsp;&emsp;permissions||array|AuthPermission|
|&emsp;&emsp;&emsp;&emsp;&emsp;&emsp;permissionName||string||
|&emsp;&emsp;accountNonExpired||boolean||
|&emsp;&emsp;credentialsNonExpired||boolean||
|&emsp;&emsp;accountNonLocked||boolean||
|&emsp;&emsp;enabled||boolean||
|&emsp;&emsp;accessTokenId||string||
|&emsp;&emsp;token||string||
|&emsp;&emsp;anonymousFlag||boolean||
|&emsp;&emsp;expireTime||integer(int64)||


**响应示例**:
```javascript
{
	"code": 0,
	"message": "",
	"data": {
		"uid": 0,
		"username": "",
		"authorities": [
			{
				"authority": ""
			}
		],
		"email": "",
		"phone": "",
		"position": "",
		"organizationId": 0,
		"sex": 0,
		"name": "",
		"loginType": 0,
		"roles": [
			{
				"roleName": "",
				"permissions": [
					{
						"permissionName": ""
					}
				]
			}
		],
		"accountNonExpired": true,
		"credentialsNonExpired": true,
		"accountNonLocked": true,
		"enabled": true,
		"accessTokenId": "",
		"token": "",
		"anonymousFlag": true,
		"expireTime": 0
	}
}
```


# device-code-endpoint


## deviceAuthorization


**接口地址**:`/auth/custom_oauth2/oauth2/device_authorization`


**请求方式**:`POST`


**请求数据类型**:`application/x-www-form-urlencoded`


**响应数据类型**:`*/*`


**接口描述**:


**请求参数**:


| 参数名称 | 参数说明 | 请求类型    | 是否必须 | 数据类型 | schema |
| -------- | -------- | ----- | -------- | -------- | ------ |
|client_id||query|true|string||
|scope||query|false|string||


**响应状态**:


| 状态码 | 说明 | schema |
| -------- | -------- | ----- | 
|200|OK|ResponseResultDeviceAuthorizationResponse|
|404|Not Found|ResponseResultObject|


**响应状态码-200**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code||integer(int32)|integer(int32)|
|message||string||
|data||DeviceAuthorizationResponse|DeviceAuthorizationResponse|
|&emsp;&emsp;deviceCode||string||
|&emsp;&emsp;userCode||string||
|&emsp;&emsp;verificationUri||string||
|&emsp;&emsp;verificationUriComplete||string||
|&emsp;&emsp;expiresIn||integer(int32)||
|&emsp;&emsp;interval||integer(int32)||


**响应示例**:
```javascript
{
	"code": 0,
	"message": "",
	"data": {
		"deviceCode": "",
		"userCode": "",
		"verificationUri": "",
		"verificationUriComplete": "",
		"expiresIn": 0,
		"interval": 0
	}
}
```


**响应状态码-404**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code||integer(int32)|integer(int32)|
|message||string||
|data||object||


**响应示例**:
```javascript
{
	"code": 0,
	"message": "",
	"data": {}
}
```


## verify


**接口地址**:`/auth/custom_oauth2/device/verify`


**请求方式**:`POST`


**请求数据类型**:`application/x-www-form-urlencoded`


**响应数据类型**:`*/*`


**接口描述**:


**请求参数**:


| 参数名称 | 参数说明 | 请求类型    | 是否必须 | 数据类型 | schema |
| -------- | -------- | ----- | -------- | -------- | ------ |
|user_code||query|true|string||


**响应状态**:


| 状态码 | 说明 | schema |
| -------- | -------- | ----- | 
|200|OK|ResponseResultBoolean|
|404|Not Found|ResponseResultObject|


**响应状态码-200**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code||integer(int32)|integer(int32)|
|message||string||
|data||boolean||


**响应示例**:
```javascript
{
	"code": 0,
	"message": "",
	"data": true
}
```


**响应状态码-404**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code||integer(int32)|integer(int32)|
|message||string||
|data||object||


**响应示例**:
```javascript
{
	"code": 0,
	"message": "",
	"data": {}
}
```


## verifyPage


**接口地址**:`/auth/custom_oauth2/device`


**请求方式**:`GET`


**请求数据类型**:`application/x-www-form-urlencoded`


**响应数据类型**:`*/*`


**接口描述**:


**请求参数**:


| 参数名称 | 参数说明 | 请求类型    | 是否必须 | 数据类型 | schema |
| -------- | -------- | ----- | -------- | -------- | ------ |
|user_code||query|false|string||


**响应状态**:


| 状态码 | 说明 | schema |
| -------- | -------- | ----- | 
|200|OK||
|404|Not Found|ResponseResultObject|


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code||integer(int32)|integer(int32)|
|message||string||
|data||object||


**响应示例**:
```javascript
{
	"code": 0,
	"message": "",
	"data": {}
}
```

# OAuth2 授权


## OAuth2 授权端点（authorization code）


**接口地址**:`/auth/oauth2/authorize`


**请求方式**:`GET`


**请求数据类型**:`application/x-www-form-urlencoded`


**响应数据类型**:`application/json`


**接口描述**:<p>需携带 SESSIONID Cookie（SSO 全局会话）。</p>
<ul>
<li>未登录：302 跳转登录页并携带 return_to，登录后自动回到本端点；</li>
<li>默认（浏览器导航）：302 重定向到 redirect_uri?code=xxx&amp;state=xxx；</li>
<li>response=url（自定义扩展，SPA/AJAX 场景）：返回 200 JSON，data.url 为回调地址，由前端自行跳转。</li>
</ul>



**请求参数**:


| 参数名称 | 参数说明 | 请求类型    | 是否必须 | 数据类型 | schema |
| -------- | -------- | ----- | -------- | -------- | ------ |
|response_type|固定值 code|query|true|string||
|client_id|客户端 ID|query|true|string||
|redirect_uri|回调地址，须与客户端注册的一致|query|true|string||
|scope|申请范围，如 read-only（OIDC 客户端含 openid）|query|false|string||
|state|防 CSRF 随机串，响应时原样回传|query|false|string||
|response|传 url 时返回 JSON 而非 302（自定义扩展）|query|false|string||


**响应状态**:


| 状态码 | 说明 | schema |
| -------- | -------- | ----- | 
|200|response=url 时返回，data.url 为授权回调地址|object|
|302|重定向到 redirect_uri?code=xxx&state=xxx；未登录时重定向登录页||
|401|client_id 未注册或用户无该系统访问权限|object|


**响应状态码-200**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code|响应码，200 成功|integer||
|message|提示信息|string||
|data|授权回调地址（response=url 时返回）|object||


**响应示例**:
```javascript
{
	"code": 0,
	"message": "",
	"data": {}
}
```


**响应状态码-401**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code|响应码，200 成功|integer||
|message|提示信息|string||


**响应示例**:
```javascript
{
	"code": 0,
	"message": ""
}
```


## OAuth2 令牌端点


**接口地址**:`/auth/oauth2/token`


**请求方式**:`POST`


**请求数据类型**:`application/x-www-form-urlencoded`


**响应数据类型**:`application/json`


**接口描述**:<p>Content-Type: application/x-www-form-urlencoded，支持的 grant_type：</p>
<ul>
<li>authorization_code：code + redirect_uri 兑换令牌；</li>
<li>refresh_token：刷新令牌续期（须携带 SESSIONID Cookie，全局会话失效时拒绝续期并返回 AUTH_ERR；会话有效时同步滑动续期全局会话与 refresh token）；</li>
<li>token-exchange / device_code：令牌交换与设备码模式。
响应格式取决于客户端配置（native_oauth2 标志）：</li>
<li>常规客户端：{ code, message, data: { accessToken, refreshToken, type, scope, expires, idToken } }；</li>
<li>原生客户端（native_oauth2=1，如 Trino/Gravitino）：OAuth2 标准响应体。</li>
</ul>



**请求参数**:


| 参数名称 | 参数说明 | 请求类型    | 是否必须 | 数据类型 | schema |
| -------- | -------- | ----- | -------- | -------- | ------ |
|client_id|客户端 ID|query|true|string||
|grant_type|授权类型：authorization_code / refresh_token / urn:ietf:params:oauth:grant-type:token-exchange / urn:ietf:params:oauth:grant-type:device_code|query|true|string||
|redirect_uri|回调地址（authorization_code 时必填）|query|false|string||
|client_secret|客户端密钥（机密客户端必填）|query|false|string||
|code|授权码（authorization_code 时必填）|query|false|string||
|refresh_token|刷新令牌（refresh_token 时必填）|query|false|string||


**响应状态**:


| 状态码 | 说明 | schema |
| -------- | -------- | ----- | 
|200|令牌颁发成功（格式见描述）|object|
|401|客户端认证失败 / 授权码无效 / 全局会话失效（native 客户端返回 OAuth2 标准错误体）|object|


**响应状态码-200**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code|响应码，200 成功|integer||
|message|提示信息|string||
|data|令牌信息（常规客户端）|object||


**响应示例**:
```javascript
{
	"code": 0,
	"message": "",
	"data": {}
}
```


**响应状态码-401**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code|响应码，200 成功|integer||
|message|提示信息|string||
|data|OAuth2 标准响应（native_oauth2 客户端）|object||


**响应示例**:
```javascript
{
	"code": 0,
	"message": "",
	"data": {}
}
```


# OIDC


## OIDC UserInfo


**接口地址**:`/auth/userinfo`


**请求方式**:`GET`


**请求数据类型**:`application/x-www-form-urlencoded`


**响应数据类型**:`application/json`


**接口描述**:<p>需携带 Authorization: Bearer {access_token}，且授权时 scope 包含 openid。返回与该用户 ID Token 同源的 Claims。</p>



**请求参数**:


| 参数名称 | 参数说明 | 请求类型    | 是否必须 | 数据类型 | schema |
| -------- | -------- | ----- | -------- | -------- | ------ |
|Authorization|Bearer {access_token}|header|true|string||


**响应状态**:


| 状态码 | 说明 | schema |
| -------- | -------- | ----- | 
|200|用户 Claims|object|
|401|令牌无效、过期或 scope 不含 openid|object|


**响应状态码-200**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code|响应码，200 成功|integer||
|message|提示信息|string||
|data|用户 Claims（与 ID Token 同源）|object||


**响应示例**:
```javascript
{
	"code": 0,
	"message": "",
	"data": {}
}
```


**响应状态码-401**:


**响应参数**:


| 参数名称 | 参数说明 | 类型 | schema |
| -------- | -------- | ----- |----- | 
|code|响应码，200 成功|integer||
|message|提示信息|string||


**响应示例**:
```javascript
{
	"code": 0,
	"message": ""
}
```