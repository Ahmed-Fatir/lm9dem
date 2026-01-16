# lm9dem - ABG Migration Dashboard

A FastAPI-based web dashboard for managing the Alpha-Beta-Gamma migration system.

## Features

- **Real-time System Monitoring**: Live view of ALPHA, BETA, GAMMA deployment status
- **Database Management**: View and manage database version assignments
- **Migration Controls**: Reset databases, unlock migrations
- **Interactive UI**: Bootstrap + htmx for responsive, real-time updates

## Quick Start

### 1. Build and Deploy
```bash
cd lm9dem
./deploy.sh
```

### 2. Access Dashboard
```bash
# Port forward to access locally
kubectl port-forward -n system-experio service/lm9dem 8080:8080

# Visit in browser
open http://localhost:8080
```

### 3. Add to Ingress (Optional)
Add this to your existing `system-ingress.yaml`:
```yaml
- path: /dashboard
  pathType: Prefix
  backend:
    service:
      name: lm9dem
      port:
        number: 8080
```

## API Endpoints

- `GET /` - Dashboard UI
- `GET /api/system/status` - System deployment status
- `GET /api/databases` - List all databases with versions
- `PUT /api/databases/{db}` - Set database version
- `POST /api/databases/reset` - Reset all databases to alpha
- `POST /api/databases/unlock` - Remove migration lock
- `GET /health` - Health check

## Environment Variables

- `REDIS_HOST` - Redis hostname (default: redis)
- `REDIS_PORT` - Redis port (default: 6379)
- `REDIS_DB` - Redis database number (default: 2)
- `NAMESPACE` - Kubernetes namespace (default: system-experio)

## Development

### Local Development
```bash
# Install dependencies
pip install -r requirements.txt

# Run locally
uvicorn main:app --reload --host 0.0.0.0 --port 8080
```

### Custom Image Version
```bash
./deploy.sh v1.0.0
```

## Dashboard Features

### System Status
- Real-time deployment replica counts
- Current image versions
- Health status indicators

### Database Management
- Table view of all databases
- One-click version switching (α/β/γ)
- Last updated timestamps

### Migration Controls
- Reset all databases to alpha
- Unlock stuck migrations
- Operation feedback# lm9dem
