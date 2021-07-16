# oAuth demo

## About

oAuth demo authorization and resource server with client using signed JWT for client authentication.

## 1. Requirements

### 1.1 Setup keycloak

#### 1.1.1 Run keycloak

**Docker:**


```shell
docker run --add-host=host.docker.internal:host-gateway -p 8082:8080 -e KEYCLOAK_USER=admin -e KEYCLOAK_PASSWORD=admin quay.io/keycloak/keycloak:13.0.0
```
* Notice: Docker container is stateless so after restart all config is lost. To preserve config use docker compose with postgres db below

**Docker compose:**

```shell
#start 
docker-compose -f etc/docker-compose/keycloak-postgres.yml up -d

#kill
docker-compose -f etc/docker-compose/keycloak-postgres.yml down

# or use make
make run-containers
make kill-container
```

#### 1.1.2 Create realm

1. Go to `Add realm`
2. Insert name `test` of realm and `Create`

#### 1.1.3 Register client for realm

1. `Clients` -> `Create`
2. Set:
    * `Client-Id` - `demo`
    * `Name` - `Demo`
    * `Client-Protocol` - `OpenId`
    * `AccessType` - `Confidential`
    * `Valid redirect uri` - `http://localhost:8080/*`
3. `Save`
4. After save go to credentials and select:
    * `Client authenticator` - Signed jwt
    * `Signature algorithm` - RS512
    * `Use JWKS Url` - set to ON
    * `JWKS URL` - `http://host.docker.internal:8080/api/jwks`

#### 1.1.4 Add Identity provider

##### 1.1.4.1 Create Identity provider

1. `Identity Providers` -> `Add provider`
2. Set:
   * `Alias` - `demo-authorization-server`
   * `Display name` - `DEMO Authorization Server`
   * `Enabled` - `ON`
   * `Sync mode` - `import`
   * `Authorization url` - `http://localhost:8081/oauth2/authorize`
   * `Token url` - `http://host.docker.internal:8081/oauth2/token`
   * `Client authentication` - choose Client secret sent as basic auth
   * `Client Id` -  `keycloak-client`
   * `Client Secret` -  `secret`
   
3. `Save`

##### 1.1.4.2 Set identity provider as default

This setup that this provider is called imediately without keycloak login page and identity choose.

1. `Authentication`
2. `Identitu provider Redirector` -> `Actions` -> `Config`
3. Set:
   * `Alias` - alias for config
   * `Default identity provider` - alias of identity provider

#### 1.1.4 Add user

1. `Users` -> `Add user`
2. Fill data:
   * `username` : `demo`
   * `First name` and `Last name`: `Demo`
   * `Save`
   * Go to `Credentials`
   * Fill password: `password`
   * Set `Temporary` to `OFF`

###  1.2 Generate key pair for client:

```shell
openssl genrsa -des3 -out client.rsa.pem 2048
openssl rsa -in client.private.pem -outform PEM -pubout -out client.public.pem
openssl pkcs8 -in client.rsa.pem -out client.private.pem -nocrypt -topk8
```

## 2. Resource server application

### 2.1 Testing

Application serves public and secured page:

 * `http://localhost:8080/` - public page not requires authentication
 * `http://localhost:8080/secured` - secured page which requires authentication through oAuth

### 2.2 Exposing public keys

JWK set is exposed through api: `http://localhost:8080/api/jwks`


## 3. Authorization server application

Authorization server application acts as Identity provider for keycloak.



## Appendix

### Refs

   * https://www.baeldung.com/spring-security-oauth-jwt
   * https://www.baeldung.com/rest-api-spring-oauth2-angular
   * https://www.baeldung.com/spring-security-oauth2-jws-jwk
   * https://docs.spring.io/spring-security/site/docs/5.5.0/reference/html5/#authenticate-using-private_key_jwt
   * https://docs.spring.io/spring-security/site/docs/5.1.7.RELEASE/reference/html/jc.html
   * https://www.baeldung.com/spring-security-custom-oauth-requests
   * https://auth0.com/docs/scopes/openid-connect-scopes

