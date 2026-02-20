#!/usr/bin/env bash
# generate-otp-openshift-manifests.sh
# Patch + merge idempotent pour OpenShift (Vault in-namespace + bootstrap auth K8S + transit)
# Usage:
#   ./generate-otp-openshift-manifests.sh --project-dir . --namespace heritage-africa-otp
#   ./generate-otp-openshift-manifests.sh --project-dir /path/to/otp-auth-service --namespace heritage-africa-otp

set -euo pipefail

log(){ echo -e "[$(date +%H:%M:%S)] $*"; }
die(){ echo "ERROR: $*" >&2; exit 1; }

PROJECT_DIR="."
NAMESPACE="heritage-africa-otp"
APP_NAME="otp-auth-service"
APP_SA="otp-auth-service-sa"
VAULT_ROLE="otp-auth-service"
TRANSIT_KEY="otp-hmac"

while [[ $# -gt 0 ]]; do
  case "$1" in
    --project-dir) PROJECT_DIR="$2"; shift 2;;
    --namespace) NAMESPACE="$2"; shift 2;;
    --app-name) APP_NAME="$2"; shift 2;;
    --app-sa) APP_SA="$2"; shift 2;;
    --vault-role) VAULT_ROLE="$2"; shift 2;;
    --transit-key) TRANSIT_KEY="$2"; shift 2;;
    -h|--help)
      sed -n '1,120p' "$0"; exit 0;;
    *) die "Argument inconnu: $1";;
  esac
done

[[ -d "$PROJECT_DIR" ]] || die "project-dir introuvable: $PROJECT_DIR"
cd "$PROJECT_DIR"

OS_DIR="manifests/openshift"
KUSTOM="$OS_DIR/kustomization.yaml"
DEPLOY="$OS_DIR/deployment.yaml"

mkdir -p "$OS_DIR/vault" "$OS_DIR/vault-config"

# -------------------------------------------------------------------
# Helpers idempotents
# -------------------------------------------------------------------
ensure_line_after() {
  # ensure_line_after <file> <pattern> <line_to_insert>
  local file="$1" pat="$2" line="$3"
  grep -qxF "$line" "$file" 2>/dev/null && return 0
  awk -v pat="$pat" -v ins="$line" '
    { print }
    $0 ~ pat && !done { print ins; done=1 }
  ' "$file" > "$file.__tmp__" && mv "$file.__tmp__" "$file"
}

ensure_kustom_resource() {
  local res="$1"
  grep -qxF "  - $res" "$KUSTOM" 2>/dev/null || echo "  - $res" >> "$KUSTOM"
}

# -------------------------------------------------------------------
# 1) Générer manifests Vault (in-namespace)
# -------------------------------------------------------------------
cat > "$OS_DIR/vault/vault-deployment.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: vault
spec:
  replicas: 1
  selector:
    matchLabels:
      app: vault
  template:
    metadata:
      labels:
        app: vault
    spec:
      containers:
        - name: vault
          image: hashicorp/vault:1.16
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 8200
          env:
            - name: VAULT_DEV_LISTEN_ADDRESS
              value: "0.0.0.0:8200"
            - name: VAULT_DEV_ROOT_TOKEN_ID
              value: "root"
          readinessProbe:
            httpGet:
              path: /v1/sys/health
              port: 8200
            initialDelaySeconds: 5
            periodSeconds: 5
          livenessProbe:
            httpGet:
              path: /v1/sys/health
              port: 8200
            initialDelaySeconds: 10
            periodSeconds: 10
EOF

cat > "$OS_DIR/vault/vault-service.yaml" <<'EOF'
apiVersion: v1
kind: Service
metadata:
  name: vault
spec:
  selector:
    app: vault
  ports:
    - name: http
      port: 8200
      targetPort: 8200
EOF

# -------------------------------------------------------------------
# 2) Générer bootstrap Vault (auth k8s + transit key + policy + role)
# -------------------------------------------------------------------
cat > "$OS_DIR/vault-config/vault-bootstrap-sa.yaml" <<'EOF'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: vault-bootstrap-sa
EOF

cat > "$OS_DIR/vault-config/vault-bootstrap-rbac.yaml" <<'EOF'
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: vault-bootstrap-role
rules:
  - apiGroups: [""]
    resources: ["serviceaccounts/token"]
    verbs: ["create"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: vault-bootstrap-rb
subjects:
  - kind: ServiceAccount
    name: vault-bootstrap-sa
roleRef:
  kind: Role
  name: vault-bootstrap-role
  apiGroup: rbac.authorization.k8s.io
EOF

cat > "$OS_DIR/vault-config/vault-config-job.yaml" <<EOF
apiVersion: batch/v1
kind: Job
metadata:
  name: vault-config
spec:
  backoffLimit: 6
  template:
    spec:
      serviceAccountName: vault-bootstrap-sa
      restartPolicy: OnFailure
      containers:
        - name: vault-config
          image: hashicorp/vault:1.16
          imagePullPolicy: IfNotPresent
          env:
            - name: VAULT_ADDR
              value: "http://vault:8200"
            - name: VAULT_TOKEN
              value: "root"
            - name: OTP_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
            - name: OTP_SA_NAME
              value: "${APP_SA}"
            - name: VAULT_ROLE
              value: "${VAULT_ROLE}"
            - name: TRANSIT_KEY
              value: "${TRANSIT_KEY}"
          command: ["sh","-lc"]
          args:
            - |
              set -e

              echo "Waiting Vault..."
              for i in \$(seq 1 120); do
                curl -sSf "\$VAULT_ADDR/v1/sys/health" >/dev/null && break
                sleep 2
              done

              echo "Enable transit + create key (idempotent)..."
              vault secrets enable transit >/dev/null 2>&1 || true
              vault write -f "transit/keys/\${TRANSIT_KEY}" >/dev/null 2>&1 || true

              echo "Enable kubernetes auth (idempotent)..."
              vault auth enable kubernetes >/dev/null 2>&1 || true

              echo "Configure kubernetes auth..."
              K8S_HOST="https://\${KUBERNETES_SERVICE_HOST}:\${KUBERNETES_SERVICE_PORT}"
              SA_JWT="\$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"
              SA_CA="/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"

              vault write auth/kubernetes/config \
                kubernetes_host="\$K8S_HOST" \
                kubernetes_ca_cert=@"\$SA_CA" \
                token_reviewer_jwt="\$SA_JWT" >/dev/null

              echo "Write policy for transit hmac..."
              cat > /tmp/otp-policy.hcl <<POL
path "transit/hmac/\${TRANSIT_KEY}" {
  capabilities = ["update"]
}
path "transit/keys/\${TRANSIT_KEY}" {
  capabilities = ["read"]
}
POL
              vault policy write otp-auth-service /tmp/otp-policy.hcl >/dev/null

              echo "Create role \${VAULT_ROLE} bound to SA \${OTP_SA_NAME} in ns \${OTP_NAMESPACE}..."
              vault write "auth/kubernetes/role/\${VAULT_ROLE}" \
                bound_service_account_names="\${OTP_SA_NAME}" \
                bound_service_account_namespaces="\${OTP_NAMESPACE}" \
                policies="otp-auth-service" \
                ttl="1h" >/dev/null

              echo "Vault configured OK."
EOF

# -------------------------------------------------------------------
# 3) kustomization.yaml : créer si absent, puis append resources manquants
# -------------------------------------------------------------------
if [[ ! -f "$KUSTOM" ]]; then
  cat > "$KUSTOM" <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: ${NAMESPACE}
resources:
EOF
fi

# ensure namespace correct (patch simple si diff)
# remplace la première ligne "namespace:" si existe
awk -v ns="$NAMESPACE" '
  BEGIN{done=0}
  {
    if(!done && $0 ~ /^namespace:[[:space:]]*/) { print "namespace: " ns; done=1; next }
    print
  }
' "$KUSTOM" > "$KUSTOM.__tmp__" && mv "$KUSTOM.__tmp__" "$KUSTOM"

# Ajout ressources Vault
ensure_kustom_resource "vault/vault-deployment.yaml"
ensure_kustom_resource "vault/vault-service.yaml"
ensure_kustom_resource "vault-config/vault-bootstrap-sa.yaml"
ensure_kustom_resource "vault-config/vault-bootstrap-rbac.yaml"
ensure_kustom_resource "vault-config/vault-config-job.yaml"

# -------------------------------------------------------------------
# 4) deployment.yaml : patch idempotent
#    - VAULT_URI -> http://vault:8200 (si variable existe)
#    - initContainers wait-for-vault (si absent)
# -------------------------------------------------------------------
if [[ -f "$DEPLOY" ]]; then
  # (4a) patch VAULT_URI value
  awk '
    BEGIN{in=0}
    {
      if ($0 ~ /^[[:space:]]*- name:[[:space:]]*VAULT_URI[[:space:]]*$/) { print; in=1; next }
      if (in==1 && $0 ~ /^[[:space:]]*value:[[:space:]]*".*"[[:space:]]*$/) {
        sub(/value:.*$/, "              value: \"http://vault:8200\"")
        print
        in=0
        next
      }
      print
    }
  ' "$DEPLOY" > "$DEPLOY.__tmp__" && mv "$DEPLOY.__tmp__" "$DEPLOY"

  # (4b) insert initContainers before first "containers:" if not present
  if ! grep -qE '^[[:space:]]*initContainers:' "$DEPLOY"; then
    awk '
      function block() {
        print "      initContainers:"
        print "        - name: wait-for-vault"
        print "          image: curlimages/curl:8.6.0"
        print "          env:"
        print "            - name: VAULT_ADDR"
        print "              value: \"http://vault:8200\""
        print "          command: [\"sh\",\"-lc\"]"
        print "          args:"
        print "            - |"
        print "              echo \"Waiting for Vault...\""
        print "              for i in $(seq 1 120); do"
        print "                code=$(curl -s -o /dev/null -w \"%{http_code}\" \"$VAULT_ADDR/v1/sys/health\" || true)"
        print "                if [ \"$code\" = \"200\" ] || [ \"$code\" = \"429\" ] || [ \"$code\" = \"473\" ]; then"
        print "                  echo \"Vault OK (HTTP $code)\""
        print "                  exit 0"
        print "                fi"
        print "                sleep 2"
        print "              done"
        print "              echo \"Vault not ready\""
        print "              exit 1"
      }
      {
        if (!done && $0 ~ /^[[:space:]]*containers:[[:space:]]*$/) {
          block()
          done=1
        }
        print
      }
    ' "$DEPLOY" > "$DEPLOY.__tmp__" && mv "$DEPLOY.__tmp__" "$DEPLOY"
  fi
else
  log "⚠️ deployment.yaml absent: $DEPLOY (je n'écrase pas, juste Vault ajouté à kustomize)"
fi

log "✅ Patch OpenShift terminé."
log "Next:"
log "  oc new-project ${NAMESPACE} || true"
log "  oc apply -k manifests/openshift"

