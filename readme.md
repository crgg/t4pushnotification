## Endpoints

### General

#### Endpoint base


```http
GET /
```

**Response:**
```json
{
  "service": "iOS Push Notification Server",
  "version": "1.0.0",
  "status": "running",
  "endpoints": {
    "auth": "/auth/login",
    "health": "/health",
    "send": "/send",
    "keys": {
      "list": "/keys/list",
      "upload": "/upload/key",
      "activate": "/keys/activate",
      "assign": "/keys/assign"
    },
    "company": "/company/new",
    "project": {
      "new": "/project/new",
      "assign": "/project/assign"
    }
  }
}
```

---

#### Health Check

```http
GET /health
```

**Response:**
```json
{
  "status": "healthy",
  "service": "iOS Push Notification Server",
  "timestamp": "2026-01-08T12:00:00.000000Z",
  "apns_configured": true,
  "environment": "production",
  "bundle_id": "com.example.app"
}
```

**Status Codes:**
- `200` - Service is healthy and configured
- `503` - Service is misconfigured (no active APNs key)

---

### Authentication Endpoints

#### Login
Auth con passphare y devuelve un JWT token.

```http
POST /auth/login
```

**Headers:**
```
Content-Type: application/json
```

**Request:**
```json
{
  "passphrase": "PASSPHRASE"
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| passphrase | string | Si | Authentication passphrase |

**Response:**
```json
{
  "status": true,
  "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "expires_in": 3600
}
```



### Notifications

#### Enviar una notificacion
Notificacion a un Device Token

```http
POST /send
```

**Headers:**
```
Authorization: Bearer JWT_TOKEN
Content-Type: application/json
```

**Request Body:**
```json
{
  "device_token": "abc123...",
  "title": "Notification Title",
  "message": "Notification message body",
  "badge": 1,
  "sound": "default",
  "category": "MESSAGE",
  "thread_id": "thread-123",
  "data": {
    "custom_key": "custom_value"
  },
  "priority": "high",
  "collapse_id": "group-1",
  "expiration": 3600,
  "pushtype": "alert"
}
```

**Parameters:**

| Field | Type | Required | Default | Description |
|-------|------|----------|---------|-------------|
| device_token | string | Si | - | Device token (hex string, 64 chars) |
| title | string | Si | - | Notification title (max 500 chars) |
| message | string | Si | - | Notification body (max 4096 chars) |
| badge | integer | No | - | Badge number to display on app icon |
| sound | string | No | "default" | Sound to play ("default" or custom sound name) |
| category | string | No | - | Notification category for actions |
| thread_id | string | No | - | Thread ID for grouping notifications |
| data | object | No | - | Custom data payload |
| priority | string | No | "high" | Priority ("high" or "low") |
| collapse_id | string | No | - | ID for collapsing similar notifications |
| expiration | integer | No | - | Expiration time in seconds |
| pushtype | string | No | "alert" | Push type (alert, background, voip, etc.) |

**Response (Success):**
```json
{
  "success": true,
  "apns_id": "A1B2C3D4-E5F6-7890-ABCD-EF1234567890",
  "status_code": 200
}
```

**Response (Error):**
```json
{
  "success": false,
  "error": "Invalid device token",
  "status_code": 400
}
```

---

### Keys

#### List Keys
Lista de todas las keys.

```http
GET /keys/list
```

**Headers:**
```
Authorization: Bearer JWT_TOKEN
```

**Response:**
```json
{
  "success": true,
  "data": [
    {
      "id": 1,
      "key_id": "ABC1234567",
      "team_id": "DEF8901234",
      "bundle_id": "com.example.app",
      "company_id": 1,
      "environment": "production",
      "is_active": true,
      "created_at": "2026-01-08T10:00:00"
    }
  ]
}
```

---

#### Upload Key
Upload and encrypt a new APNs .p8 key file.

```http
POST /upload/key
```

**Headers:**
```
Authorization: Bearer JWT_TOKEN
Content-Type: multipart/form-data
```

**Form Data:**

| Field | Type | Required | Format | Description |
|-------|------|----------|--------|-------------|
| key_id | string | Si | 10 chars (A-Z0-9) | APNs Key ID from Apple Developer |
| team_id | string | Si | 10 chars (A-Z0-9) | Team ID from Apple Developer |
| bundle_id | string | Si | Reverse domain notation | iOS app bundle identifier |
| company_id | string | Si | Integer | Company ID |
| environment | string | No | "sandbox" or "production" | APNs environment (default: sandbox) |
| file | file | Si | .p8 file | APNs authentication key file |

**Response:**
```json
{
  "success": true,
  "message": "APNs key uploaded, encrypted, and configuration saved",
  "data": {
    "key_id": "ABC1234567",
    "team_id": "DEF8901234",
    "bundle_id": "com.example.app",
    "environment": "production",
    "p8_filename": "AuthKey_ABC1234567_20260108120000.p8",
    "enc_filename": "AuthKey_ABC1234567_20260108120000.p8.enc",
    "key_version": 1
  }
}
```


---

#### Marcar Key como activa

```http
POST /keys/activate
```

**Headers:**
```
Authorization: Bearer JWT_TOKEN
Content-Type: application/json
```

**Request Body:**
```json
{
  "bundle_id": "com.example.app",
  "environment": "production"
}
```

**Parameters:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| bundle_id | string | Si | Bundle ID to activate |

**Response:**
```json
{
  "success": true,
  "message": "Active APNs configuration updated",
  "active": {
    "bundle_id": "com.example.app"
  }
}
```


---

#### Assign Key to Company
Assign an APNs key to a company.

```http
POST /keys/assign
```

**Headers:**
```
Authorization: Bearer JWT_TOKEN
Content-Type: multipart/form-data
```

**Form Data:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| company_id | string | Si | Company ID |
| key_id | string | Si | Key ID to assign |

**Response:**
```json
{
  "success": true,
  "message": "Key assigned to company successfully"
}
```



---

### Company 

#### Crear Company

```http
POST /company/new
```

**Headers:**
```
Authorization: Bearer JWT_TOKEN
Content-Type: multipart/form-data
```

**Form Data:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Si | Company name |
| address | string | Si | Company address |
| email | string | No | Company email (must be valid format) |
| phone | string | No | Company phone number |
| url | string | No | Company website URL |

**Response:**
```json
{
  "success": true,
  "message": "Company created successfully",
  "data": {
    "name": "Example Corp",
    "address": "123 Main St",
    "email": "info@example.com",
    "phone": "+1234567890",
    "url": "https://example.com"
  }
}
```


---

### Project Management

#### Create Project
Create a new project.

```http
POST /project/new
```

**Headers:**
```
Authorization: Bearer JWT_TOKEN
Content-Type: multipart/form-data
```

**Form Data:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| name | string | Si | Project name |
| url | string | Si | Project URL |

**Response:**
```json
{
  "success": true,
  "message": "Project created successfully"
}
```


---

#### Assign Project to Key
Assign a project to an APNs key.

```http
POST /project/assign
```

**Headers:**
```
Authorization: Bearer JWT_TOKEN
Content-Type: multipart/form-data
```

**Form Data:**

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| project_id | string | Si | Project ID |
| key_id | string | Si | Key ID to assign |

**Response:**
```json
{
  "success": true,
  "message": "Project assigned to key successfully"
}
```

