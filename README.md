# JWT Demo (Spring Boot 3 + jjwt 0.12)

## Run
    mvn spring-boot:run
Java 17+ chahiye. Default users: `admin/admin123` (ROLE_ADMIN), `user/user123`.

## Endpoints
| Method | URL | Auth | Kaam |
|---|---|---|---|
| POST | /api/auth/register | - | Naya user + tokens |
| POST | /api/auth/login | - | Access + refresh token |
| POST | /api/auth/refresh | - | Token rotation |
| POST | /api/auth/validate | - | Token valid hai ya nahi + claims |
| POST | /api/auth/logout | Bearer | Access (+refresh) revoke |
| GET | /api/me | Bearer | Current user |
| GET | /api/admin/hello | Bearer (ADMIN) | Role-based access |

## Test
    curl -s -X POST localhost:8080/api/auth/login -H 'Content-Type: application/json' \
      -d '{"username":"admin","password":"admin123"}'

    curl -s localhost:8080/api/me -H "Authorization: Bearer <accessToken>"

    curl -s -X POST localhost:8080/api/auth/validate -H 'Content-Type: application/json' \
      -d '{"token":"<accessToken>"}'

    curl -s -X POST localhost:8080/api/auth/refresh -H 'Content-Type: application/json' \
      -d '{"refreshToken":"<refreshToken>"}'

    curl -s -X POST localhost:8080/api/auth/logout -H "Authorization: Bearer <accessToken>" \
      -H 'Content-Type: application/json' -d '{"refreshToken":"<refreshToken>"}'

## Production notes
- `JWT_SECRET` env variable me Base64 secret (min 32 bytes) do: `openssl rand -base64 48`
- `UserService` (in-memory) ko JPA/DB se replace karo
- `TokenBlacklist` ko Redis (TTL = token expiry) se replace karo agar multiple instances hain
- HTTPS zaroor use karo
