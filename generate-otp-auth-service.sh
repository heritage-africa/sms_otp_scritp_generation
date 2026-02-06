#!/usr/bin/env bash
# generate-otp-auth-service.sh (V2 — profils + OpenShift + Vault Kubernetes Auth “propre prod”)
# Génère un microservice Spring Boot "OTP Auth" prod-ready (Redis OTP store, Vault Transit HMAC, SMSEAGLE BasicAuth, Email OTP),
# avec tests unitaires, Dockerfile, manifests OpenShift/K8s, et profils dev/test/docker/kubernetes/qualif/preprod/prod.
#
# Usage:
#   ./generate-otp-auth-service.sh --name otp-auth-service --groupId heritage.africa --artifactId otp-auth-service --package heritage.africa.otp \
#     --java 21 --boot 3.3.5 --cloud 2023.0.4 --out ./go-gainde-otp --ns heritage-africa-otp --image otp-auth-service:latest
#
set -euo pipefail

# -----------------------------
# Helpers
# -----------------------------
log() { echo -e "[$(date +%H:%M:%S)] $*"; }
die() { echo "ERROR: $*" >&2; exit 1; }
need() { command -v "$1" >/dev/null 2>&1 || die "Commande requise introuvable: $1"; }

# -----------------------------
# Defaults
# -----------------------------
NAME="otp-auth-service"
GROUP_ID="heritage.africa"
ARTIFACT_ID="otp-auth-service"
PKG="heritage.africa.otp"
JAVA_VER="21"
BOOT_VER="3.3.5"
CLOUD_VER="2023.0.4"
OUT_DIR="."
PORT="8080"

# OpenShift/K8s defaults
K8S_NS="heritage-africa-otp"
IMAGE="otp-auth-service:latest"
ROUTE_HOST=""   # si vide, OpenShift générera

# -----------------------------
# Args
# -----------------------------
while [[ $# -gt 0 ]]; do
  case "$1" in
    --name) NAME="$2"; shift 2;;
    --groupId) GROUP_ID="$2"; shift 2;;
    --artifactId) ARTIFACT_ID="$2"; shift 2;;
    --package) PKG="$2"; shift 2;;
    --java) JAVA_VER="$2"; shift 2;;
    --boot) BOOT_VER="$2"; shift 2;;
    --cloud) CLOUD_VER="$2"; shift 2;;
    --out) OUT_DIR="$2"; shift 2;;
    --port) PORT="$2"; shift 2;;
    --ns) K8S_NS="$2"; shift 2;;
    --image) IMAGE="$2"; shift 2;;
    --route-host) ROUTE_HOST="$2"; shift 2;;
    -h|--help)
      sed -n '1,120p' "$0"; exit 0;;
    *) die "Argument inconnu: $1";;
  esac
done

need mkdir
need cat
need sed
need tr
need chmod

BASE="${OUT_DIR%/}/${ARTIFACT_ID}"
SRC_MAIN="$BASE/src/main/java/$(echo "$PKG" | tr '.' '/')"
SRC_TEST="$BASE/src/test/java/$(echo "$PKG" | tr '.' '/')"
RES_MAIN="$BASE/src/main/resources"
RES_TEST="$BASE/src/test/resources"

if [[ -e "$BASE" ]]; then
  die "Le dossier existe déjà: $BASE (supprime-le ou change --artifactId/--out)"
fi

log "Création du projet: $BASE"
mkdir -p "$SRC_MAIN" "$SRC_MAIN"/dto "$SRC_MAIN"/client "$SRC_MAIN"/config "$SRC_MAIN"/notify "$SRC_MAIN"/vault "$SRC_MAIN"/otp
mkdir -p "$SRC_TEST" "$SRC_TEST"/vault "$SRC_TEST"/notify "$SRC_TEST"/otp
mkdir -p "$RES_MAIN" "$RES_TEST"
mkdir -p "$BASE/manifests/openshift" "$BASE/docker" "$BASE/scripts"

# -----------------------------
# pom.xml (Spring Boot + Vault + Redis + Mail + Tests)
# -----------------------------
cat > "$BASE/pom.xml" <<EOF
<project xmlns="http://maven.apache.org/POM/4.0.0" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
  xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
  <modelVersion>4.0.0</modelVersion>

  <groupId>${GROUP_ID}</groupId>
  <artifactId>${ARTIFACT_ID}</artifactId>
  <version>0.1.0</version>
  <name>${NAME}</name>
  <description>OTP registration service (SMS local via SMSEAGLE, Email for foreign) with Vault Transit HMAC + Redis OTP store</description>

  <properties>
    <java.version>${JAVA_VER}</java.version>
    <maven.compiler.release>${JAVA_VER}</maven.compiler.release>
    <spring-boot.version>${BOOT_VER}</spring-boot.version>
    <spring-cloud.version>${CLOUD_VER}</spring-cloud.version>
  </properties>

  <dependencyManagement>
    <dependencies>
      <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-dependencies</artifactId>
        <version>\${spring-boot.version}</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
      <dependency>
        <groupId>org.springframework.cloud</groupId>
        <artifactId>spring-cloud-dependencies</artifactId>
        <version>\${spring-cloud.version}</version>
        <type>pom</type>
        <scope>import</scope>
      </dependency>
    </dependencies>
  </dependencyManagement>

  <dependencies>
    <!-- Web + Validation -->
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-validation</artifactId>
    </dependency>

    <!-- Redis -->
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-data-redis</artifactId>
    </dependency>

    <!-- Email -->
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-mail</artifactId>
    </dependency>

    <!-- Vault Config (TOKEN en docker, KUBERNETES en prod OpenShift) -->
    <dependency>
      <groupId>org.springframework.cloud</groupId>
      <artifactId>spring-cloud-starter-vault-config</artifactId>
    </dependency>

    <!-- Actuator (health/readiness) -->
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-actuator</artifactId>
    </dependency>

    <!-- Tests -->
    <dependency>
      <groupId>org.springframework.boot</groupId>
      <artifactId>spring-boot-starter-test</artifactId>
      <scope>test</scope>
    </dependency>
  </dependencies>

  <build>
    <plugins>
      <plugin>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-maven-plugin</artifactId>
        <executions>
          <execution>
            <goals>
              <goal>repackage</goal>
            </goals>
          </execution>
        </executions>
      </plugin>

      <plugin>
        <artifactId>maven-compiler-plugin</artifactId>
        <configuration>
          <compilerArgs>
            <arg>-parameters</arg>
          </compilerArgs>
        </configuration>
      </plugin>

      <plugin>
        <groupId>org.apache.maven.plugins</groupId>
        <artifactId>maven-surefire-plugin</artifactId>
        <configuration>
          <useModulePath>false</useModulePath>
        </configuration>
      </plugin>
    </plugins>
  </build>
</project>
EOF

# -----------------------------
# application.yml (base neutre) + profils
# -----------------------------
cat > "$RES_MAIN/application.yml" <<EOF
server:
  port: ${PORT}

spring:
  application:
    name: ${NAME}

  data:
    redis:
      host: \${REDIS_HOST:redis}
      port: \${REDIS_PORT:6379}

  mail:
    host: \${SMTP_HOST:}
    port: \${SMTP_PORT:587}
    username: \${SMTP_USER:}
    password: \${SMTP_PASS:}
    properties:
      mail.smtp.auth: true
      mail.smtp.starttls.enable: true
# Vault OFF par défaut (activé via profils / VAULT_ENABLED)      
  cloud:
    vault:
      enabled: \${VAULT_ENABLED:false}

# OTP store: memory|redis (réutilise tes @ConditionalOnProperty(name="otp.store"...))
otp:
  store: \${OTP_STORE:memory}


management:
  endpoints:
    web:
      exposure:
        include: health,info
  endpoint:
    health:
      probes:
        enabled: true
  health:
    vault:
      enabled: \${VAULT_ENABLED:false}

app:
  otp:
    ttl-seconds: \${OTP_TTL_SECONDS:300}
    max-attempts: \${OTP_MAX_ATTEMPTS:5}
    lock-seconds: \${OTP_LOCK_SECONDS:1800}
  locale:
    local-country-code: \${LOCAL_COUNTRY_CODE:+221}

  # Vault Transit HMAC
  vault:
    transit-key: \${VAULT_TRANSIT_KEY:otp-hmac}

  # SMSEAGLE (Basic Auth)
  smseagle:
    base-url: \${SMSEAGLE_BASE_URL:https://smseagle.local}
    username: \${SMSEAGLE_USER:}
    password: \${SMSEAGLE_PASS:}
    sms-path: \${SMSEAGLE_SMS_PATH:/api/v2/messages/sms}
EOF

# Profils
cat > "$RES_MAIN/application-dev.yml" <<EOF
otp:
  store: memory
spring:
  cloud:
    vault:
      enabled: false
logging:
  level:
    root: INFO
    ${PKG}: DEBUG
EOF

cat > "$RES_MAIN/application-test.yml" <<EOF
otp:
  store: memory
spring:
  cloud:
    vault:
      enabled: false
EOF

cat > "$RES_MAIN/application-docker.yml" <<EOF
otp:
  store: redis
spring:
  cloud:
    vault:
      enabled: \${VAULT_ENABLED:false}
      uri: \${VAULT_URI:http://vault:8200}
      authentication: TOKEN
      token: \${VAULT_TOKEN:}
EOF

cat > "$RES_MAIN/application-kubernetes.yml" <<EOF
otp:
  store: redis
spring:
  cloud:
    vault:
      enabled: true
      # Si Vault est dans le namespace "vault":
      uri: \${VAULT_URI:http://vault.vault.svc:8200}
      # Si Vault est dans le même namespace que l'app, override VAULT_URI à "http://vault:8200"
      authentication: KUBERNETES
      kubernetes:
        role: \${VAULT_K8S_ROLE:${NAME}}
        kubernetes-path: \${VAULT_K8S_MOUNT:kubernetes}
      kv:
        enabled: true
        backend: secret
        default-context: ${NAME}
EOF

cat > "$RES_MAIN/application-qualif.yml" <<EOF
spring:
  profiles:
    include: kubernetes
EOF

cat > "$RES_MAIN/application-preprod.yml" <<EOF
spring:
  profiles:
    include: kubernetes
EOF

cat > "$RES_MAIN/application-prod.yml" <<EOF
spring:
  profiles:
    include: kubernetes
EOF

# -----------------------------
# Dockerfile (multi-stage, OpenShift-friendly)
# -----------------------------
cat > "$BASE/docker/Dockerfile" <<'EOF'
# syntax=docker/dockerfile:1

FROM maven:3.9-eclipse-temurin-21 AS build
WORKDIR /src
COPY pom.xml .
RUN mvn -q -e -DskipTests dependency:go-offline
COPY src ./src
RUN mvn -q -e -DskipTests package

FROM eclipse-temurin:21-jre
WORKDIR /app
# OpenShift best practice: run as non-root (OpenShift injecte un UID arbitraire)
RUN addgroup --system app && adduser --system --ingroup app app
COPY --from=build /src/target/*.jar /app/app.jar
EXPOSE 8080
ENV JAVA_OPTS=""
USER app
ENTRYPOINT ["sh","-c","java $JAVA_OPTS -jar /app/app.jar"]
EOF

# -----------------------------
# OpenShift manifests (kustomize)
# -----------------------------
cat > "$BASE/manifests/openshift/kustomization.yaml" <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: ${K8S_NS}
resources:
  - serviceaccount.yaml
  - deployment.yaml
  - service.yaml
  - route.yaml
  - configmap.yaml
  - secret.yaml
EOF

cat > "$BASE/manifests/openshift/serviceaccount.yaml" <<EOF
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${NAME}-sa
EOF

cat > "$BASE/manifests/openshift/configmap.yaml" <<EOF
apiVersion: v1
kind: ConfigMap
metadata:
  name: ${NAME}-config
data:
  REDIS_HOST: "redis"
  REDIS_PORT: "6379"
  LOCAL_COUNTRY_CODE: "+221"
  OTP_TTL_SECONDS: "300"
  OTP_MAX_ATTEMPTS: "5"
  OTP_LOCK_SECONDS: "1800"
  VAULT_TRANSIT_KEY: "otp-hmac"
  SMSEAGLE_BASE_URL: "https://smseagle.local"
  SMSEAGLE_SMS_PATH: "/api/v2/messages/sms"
  # SMTP_HOST, SMTP_PORT peuvent être mis ici si non sensibles
EOF

# Secret OpenShift (SANS VAULT_TOKEN en prod “propre”)
cat > "$BASE/manifests/openshift/secret.yaml" <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ${NAME}-secret
type: Opaque
stringData:
  SMSEAGLE_USER: "CHANGE_ME"
  SMSEAGLE_PASS: "CHANGE_ME"
  SMTP_USER: "CHANGE_ME"
  SMTP_PASS: "CHANGE_ME"
EOF

cat > "$BASE/manifests/openshift/deployment.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${NAME}
spec:
  replicas: 2
  selector:
    matchLabels:
      app: ${NAME}
  template:
    metadata:
      labels:
        app: ${NAME}
    spec:
      serviceAccountName: ${NAME}-sa
      containers:
        - name: ${NAME}
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 8080
          env:
            # Profil prod (inclut kubernetes -> Vault K8S auth)
            - name: SPRING_PROFILES_ACTIVE
              value: "prod"
            - name: VAULT_ENABLED
              value: "true"
            - name: OTP_STORE
              value: "redis"

            # Vault (Kubernetes auth)
            - name: VAULT_URI
              value: "http://vault.vault.svc:8200"
            - name: VAULT_K8S_ROLE
              value: "${NAME}"
            - name: VAULT_K8S_MOUNT
              value: "kubernetes"

          envFrom:
            - configMapRef:
                name: ${NAME}-config
            - secretRef:
                name: ${NAME}-secret
          readinessProbe:
            httpGet:
              path: /actuator/health/readiness
              port: 8080
            initialDelaySeconds: 10
            periodSeconds: 10
          livenessProbe:
            httpGet:
              path: /actuator/health/liveness
              port: 8080
            initialDelaySeconds: 20
            periodSeconds: 20
          resources:
            requests:
              cpu: "100m"
              memory: "256Mi"
            limits:
              cpu: "500m"
              memory: "512Mi"
EOF

cat > "$BASE/manifests/openshift/service.yaml" <<EOF
apiVersion: v1
kind: Service
metadata:
  name: ${NAME}
spec:
  selector:
    app: ${NAME}
  ports:
    - name: http
      port: 80
      targetPort: 8080
EOF

cat > "$BASE/manifests/openshift/route.yaml" <<EOF
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: ${NAME}
spec:
  to:
    kind: Service
    name: ${NAME}
  port:
    targetPort: http
  tls:
    termination: edge
EOF
if [[ -n "$ROUTE_HOST" ]]; then
  sed -i "s/spec:/spec:\n  host: ${ROUTE_HOST}/" "$BASE/manifests/openshift/route.yaml"
fi

# -----------------------------
# Java sources
# -----------------------------
cat > "${SRC_MAIN}/OtpAuthServiceApplication.java" <<EOF
package ${PKG};

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(AppProps.class)
public class OtpAuthServiceApplication {
  public static void main(String[] args) {
    SpringApplication.run(OtpAuthServiceApplication.class, args);
  }
}
EOF

cat > "${SRC_MAIN}/AppProps.java" <<EOF
package ${PKG};

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "app")
public record AppProps(
    Otp otp,
    Locale locale,
    Vault vault,
    Smseagle smseagle
) {
  public long otpTtlSeconds() { return otp.ttlSeconds(); }
  public int maxAttempts() { return otp.maxAttempts(); }
  public long lockSeconds() { return otp.lockSeconds(); }
  public String localCountryCode() { return locale.localCountryCode(); }

  public String vaultTransitKey() { return vault.transitKey(); }

  public String smseagleBaseUrl() { return smseagle.baseUrl(); }
  public String smseagleUsername() { return smseagle.username(); }
  public String smseaglePassword() { return smseagle.password(); }
  public String smseagleSmsPath() { return smseagle.smsPath(); }

  public record Otp(long ttlSeconds, int maxAttempts, long lockSeconds) {}
  public record Locale(String localCountryCode) {}
  public record Vault(String transitKey) {}
  public record Smseagle(String baseUrl, String username, String password, String smsPath) {}
}
EOF

cat > "${SRC_MAIN}/Channel.java" <<EOF
package ${PKG};

public enum Channel { SMS, EMAIL }
EOF

cat > "${SRC_MAIN}/Destination.java" <<EOF
package ${PKG};

public record Destination(Channel channel, String value) {}
EOF

cat > "${SRC_MAIN}/dto/RegisterStartRequest.java" <<EOF
package ${PKG}.dto;

import jakarta.validation.constraints.Email;

public record RegisterStartRequest(
    String phone,
    @Email String email
) {}
EOF

cat > "${SRC_MAIN}/dto/RegisterStartResponse.java" <<EOF
package ${PKG}.dto;

import ${PKG}.Channel;

public record RegisterStartResponse(
    String challengeId,
    Channel channel,
    String maskedDestination,
    long expiresInSeconds
) {}
EOF

cat > "${SRC_MAIN}/dto/VerifyOtpRequest.java" <<EOF
package ${PKG}.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record VerifyOtpRequest(
    @NotBlank String challengeId,
    @NotBlank @Pattern(regexp="\\\\d{6}") String code
) {}
EOF

cat > "${SRC_MAIN}/dto/VerifyOtpResponse.java" <<EOF
package ${PKG}.dto;

public record VerifyOtpResponse(boolean verified, String next) {}
EOF

cat > "${SRC_MAIN}/AuthController.java" <<EOF
package ${PKG};

import ${PKG}.dto.RegisterStartRequest;
import ${PKG}.dto.RegisterStartResponse;
import ${PKG}.dto.VerifyOtpRequest;
import ${PKG}.dto.VerifyOtpResponse;

import jakarta.validation.Valid;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth/register")
public class AuthController {

  private final OtpOrchestratorService orchestrator;

  public AuthController(OtpOrchestratorService orchestrator) {
    this.orchestrator = orchestrator;
  }

  @PostMapping("/start")
  public RegisterStartResponse start(@Valid @RequestBody RegisterStartRequest req) {
    return orchestrator.startChallenge(req);
  }

  @PostMapping("/verify")
  public VerifyOtpResponse verify(@Valid @RequestBody VerifyOtpRequest req) {
    boolean ok = orchestrator.verify(req.challengeId(), req.code());
    return new VerifyOtpResponse(ok, ok ? "CREATE_ACCOUNT" : "RETRY");
  }
}
EOF

# Notify interfaces + impl
cat > "${SRC_MAIN}/notify/SmsSender.java" <<EOF
package ${PKG}.notify;

public interface SmsSender {
  void send(String phoneE164, String message);
}
EOF

cat > "${SRC_MAIN}/notify/EmailSender.java" <<EOF
package ${PKG}.notify;

public interface EmailSender {
  void send(String to, String subject, String body);
}
EOF

cat > "${SRC_MAIN}/notify/SmtpEmailSender.java" <<EOF
package ${PKG}.notify;

import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Service;

@Service
public class SmtpEmailSender implements EmailSender {
  private final JavaMailSender mailSender;

  public SmtpEmailSender(JavaMailSender mailSender) {
    this.mailSender = mailSender;
  }

  @Override
  public void send(String to, String subject, String body) {
    SimpleMailMessage msg = new SimpleMailMessage();
    msg.setTo(to);
    msg.setSubject(subject);
    msg.setText(body);
    mailSender.send(msg);
  }
}
EOF

# SMSEAGLE BasicAuth client (RestClient)
cat > "${SRC_MAIN}/notify/SmseagleSmsSender.java" <<EOF
package ${PKG}.notify;

import ${PKG}.AppProps;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.Map;

@Service
public class SmseagleSmsSender implements SmsSender {

  // pas final -> testable via ReflectionTestUtils
  private RestClient client;
  private final AppProps props;

  public SmseagleSmsSender(AppProps props) {
    this.props = props;
    this.client = RestClient.builder()
        .baseUrl(props.smseagleBaseUrl())
        .defaultHeaders(h -> {
          h.setBasicAuth(props.smseagleUsername(), props.smseaglePassword());
          h.setContentType(MediaType.APPLICATION_JSON);
        })
        .build();
  }

  @Override
  public void send(String phoneE164, String message) {
    client.post()
        .uri(props.smseagleSmsPath())
        .body(Map.of("to", phoneE164, "text", message))
        .retrieve()
        .toBodilessEntity();
  }
}
EOF

# MacService interface + impls (Vault / Local)
cat > "${SRC_MAIN}/vault/MacService.java" <<EOF
package ${PKG}.vault;

public interface MacService {
  String hmac(String challengeId, String destination, String code);
}
EOF

cat > "${SRC_MAIN}/vault/VaultMacService.java" <<EOF
package ${PKG}.vault;

import ${PKG}.AppProps;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@Service
@ConditionalOnProperty(name = "spring.cloud.vault.enabled", havingValue = "true")
public class VaultMacService implements MacService {

  private final VaultTemplate vault;
  private final AppProps props;

  public VaultMacService(VaultTemplate vault, AppProps props) {
    this.vault = vault;
    this.props = props;
  }

  @Override
  public String hmac(String challengeId, String destination, String code) {
    String msg = challengeId + ":" + destination + ":" + code;
    String inputB64 = Base64.getEncoder().encodeToString(msg.getBytes(StandardCharsets.UTF_8));

    Map<String, Object> req = Map.of(
        "input", inputB64,
        "algorithm", "sha2-256"
    );

    VaultResponse resp = vault.write("transit/hmac/" + props.vaultTransitKey(), req);
    if (resp == null || resp.getData() == null) {
      throw new IllegalStateException("Vault transit response empty");
    }

    Object h = resp.getData().get("hmac");
    if (h == null) throw new IllegalStateException("Vault transit response missing hmac");
    return h.toString();
  }
}
EOF

cat > "${SRC_MAIN}/vault/LocalMacService.java" <<EOF
package ${PKG}.vault;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

@Service
@ConditionalOnProperty(name = "spring.cloud.vault.enabled", havingValue = "false", matchIfMissing = true)
public class LocalMacService implements MacService {

  @Override
  public String hmac(String challengeId, String destination, String code) {
    return "LOCAL(" + challengeId + ":" + destination + ":" + code + ")";
  }
}
EOF


# OTP store abstraction + Redis impl + InMemory
cat > "${SRC_MAIN}/otp/OtpStore.java" <<EOF
package ${PKG}.otp;

import ${PKG}.Channel;

import java.util.Optional;

public interface OtpStore {
  void put(String challengeId, String destination, Channel channel, String codeMac, long ttlSeconds);
  Optional<OtpRecord> get(String challengeId);
  void incrementAttempts(String challengeId);
  void lock(String challengeId, long lockUntilEpochSec, long ttlSeconds);
  void delete(String challengeId);

  record OtpRecord(String destination, Channel channel, String codeMac, int attempts, Long lockedUntilEpochSec) {}
}
EOF

cat > "${SRC_MAIN}/otp/RedisOtpStore.java" <<EOF
package ${PKG}.otp;

import ${PKG}.Channel;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Component;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import java.time.Duration;
import java.util.Map;
import java.util.Optional;

@Component("redisOtpStore")
@ConditionalOnProperty(name = "otp.store", havingValue = "redis")
public class RedisOtpStore implements OtpStore {

  private final StringRedisTemplate redis;

  public RedisOtpStore(StringRedisTemplate redis) {
    this.redis = redis;
  }

  private String key(String challengeId) { return "otp:ch:" + challengeId; }

  @Override
  public void put(String challengeId, String destination, Channel channel, String codeMac, long ttlSeconds) {
    String k = key(challengeId);
    redis.opsForHash().put(k, "dest", destination);
    redis.opsForHash().put(k, "channel", channel.name());
    redis.opsForHash().put(k, "code_mac", codeMac);
    redis.opsForHash().put(k, "attempts", "0");
    redis.expire(k, Duration.ofSeconds(ttlSeconds));
  }

  @Override
  public Optional<OtpRecord> get(String challengeId) {
    String k = key(challengeId);
    Map<Object, Object> m = redis.opsForHash().entries(k);
    if (m == null || m.isEmpty()) return Optional.empty();

    String dest = (String) m.get("dest");
    String channel = (String) m.get("channel");
    String codeMac = (String) m.get("code_mac");
    int attempts = Integer.parseInt((String) m.getOrDefault("attempts", "0"));
    String lockedUntil = (String) m.get("locked_until");

    return Optional.of(new OtpRecord(
        dest,
        Channel.valueOf(channel),
        codeMac,
        attempts,
        lockedUntil == null ? null : Long.parseLong(lockedUntil)
    ));
  }

  @Override
  public void incrementAttempts(String challengeId) {
    String k = key(challengeId);
    String cur = (String) redis.opsForHash().get(k, "attempts");
    int v = cur == null ? 0 : Integer.parseInt(cur);
    redis.opsForHash().put(k, "attempts", Integer.toString(v + 1));
  }

  @Override
  public void lock(String challengeId, long lockUntilEpochSec, long ttlSeconds) {
    String k = key(challengeId);
    redis.opsForHash().put(k, "locked_until", Long.toString(lockUntilEpochSec));
    redis.expire(k, Duration.ofSeconds(ttlSeconds));
  }

  @Override
  public void delete(String challengeId) {
    redis.delete(key(challengeId));
  }
}
EOF

cat > "${SRC_MAIN}/otp/InMemoryOtpStore.java" <<EOF
package ${PKG}.otp;

import ${PKG}.Channel;
import org.springframework.stereotype.Component;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Component("inMemoryOtpStore")
@ConditionalOnProperty(name = "otp.store", havingValue = "memory", matchIfMissing = true)
public class InMemoryOtpStore implements OtpStore {

  private static class Entry {
    String dest;
    Channel channel;
    String mac;
    int attempts;
    Long lockedUntil;
    long expiresAt;
  }

  private final Map<String, Entry> map = new ConcurrentHashMap<>();

  @Override
  public void put(String challengeId, String destination, Channel channel, String codeMac, long ttlSeconds) {
    Entry e = new Entry();
    e.dest = destination;
    e.channel = channel;
    e.mac = codeMac;
    e.attempts = 0;
    e.lockedUntil = null;
    e.expiresAt = Instant.now().getEpochSecond() + ttlSeconds;
    map.put(challengeId, e);
  }

  @Override
  public Optional<OtpRecord> get(String challengeId) {
    Entry e = map.get(challengeId);
    if (e == null) return Optional.empty();
    long now = Instant.now().getEpochSecond();
    if (now >= e.expiresAt) { map.remove(challengeId); return Optional.empty(); }
    return Optional.of(new OtpRecord(e.dest, e.channel, e.mac, e.attempts, e.lockedUntil));
  }

  @Override
  public void incrementAttempts(String challengeId) {
    Entry e = map.get(challengeId);
    if (e != null) e.attempts++;
  }

  @Override
  public void lock(String challengeId, long lockUntilEpochSec, long ttlSeconds) {
    Entry e = map.get(challengeId);
    if (e != null) {
      e.lockedUntil = lockUntilEpochSec;
      e.expiresAt = Instant.now().getEpochSecond() + ttlSeconds;
    }
  }

  @Override
  public void delete(String challengeId) {
    map.remove(challengeId);
  }
}
EOF

# OTP Service
cat > "${SRC_MAIN}/OtpService.java" <<EOF
package ${PKG};

import ${PKG}.otp.OtpStore;
import ${PKG}.otp.OtpStore.OtpRecord;
import ${PKG}.vault.VaultTransitMacService;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

@Service
public class OtpService {

  private final SecureRandom random = new SecureRandom();
  private final OtpStore store;
  private final VaultTransitMacService mac;
  private final AppProps props;

  public OtpService(OtpStore store, VaultTransitMacService mac, AppProps props) {
    this.store = store;
    this.mac = mac;
    this.props = props;
  }

  public OtpChallenge create(Destination dest) {
    String challengeId = UUID.randomUUID().toString();
    String code = String.format("%06d", random.nextInt(1_000_000));
    String codeMac = mac.hmac(challengeId, dest.value(), code);

    store.put(challengeId, dest.value(), dest.channel(), codeMac, props.otpTtlSeconds());
    return new OtpChallenge(challengeId, code);
  }

  public boolean verify(String challengeId, String code) {
    var opt = store.get(challengeId);
    if (opt.isEmpty()) return false;

    OtpRecord r = opt.get();
    long now = Instant.now().getEpochSecond();

    if (r.lockedUntilEpochSec() != null && now < r.lockedUntilEpochSec()) return false;

    if (r.attempts() >= props.maxAttempts()) {
      store.lock(challengeId, now + props.lockSeconds(), Math.max(props.lockSeconds(), props.otpTtlSeconds()));
      return false;
    }

    String actual = mac.hmac(challengeId, r.destination(), code);
    boolean ok = constantTimeEquals(r.codeMac(), actual);

    if (ok) {
      store.delete(challengeId);
      return true;
    }

    store.incrementAttempts(challengeId);

    var r2 = store.get(challengeId).orElse(r);
    if (r2.attempts() >= props.maxAttempts()) {
      store.lock(challengeId, now + props.lockSeconds(), Math.max(props.lockSeconds(), props.otpTtlSeconds()));
    }

    return false;
  }

  private boolean constantTimeEquals(String a, String b) {
    if (a == null || b == null) return false;
    if (a.length() != b.length()) return false;
    int r = 0;
    for (int i = 0; i < a.length(); i++) r |= a.charAt(i) ^ b.charAt(i);
    return r == 0;
  }

  public record OtpChallenge(String challengeId, String code) {}
}
EOF

# Orchestrator
cat > "${SRC_MAIN}/OtpOrchestratorService.java" <<EOF
package ${PKG};

import ${PKG}.dto.RegisterStartRequest;
import ${PKG}.dto.RegisterStartResponse;
import ${PKG}.notify.EmailSender;
import ${PKG}.notify.SmsSender;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;

@Service
public class OtpOrchestratorService {

  private final OtpService otpService;
  private final SmsSender smsSender;
  private final EmailSender emailSender;
  private final AppProps props;

  public OtpOrchestratorService(OtpService otpService, SmsSender smsSender, EmailSender emailSender, AppProps props) {
    this.otpService = otpService;
    this.smsSender = smsSender;
    this.emailSender = emailSender;
    this.props = props;
  }

  public RegisterStartResponse startChallenge(RegisterStartRequest req) {
    Destination dest = decide(req);

    var ch = otpService.create(dest);

    String msg = "Votre code OTP est: " + ch.code() + " (valable " + (props.otpTtlSeconds()/60) + " min)";
    if (dest.channel() == Channel.SMS) {
      smsSender.send(dest.value(), msg);
    } else {
      emailSender.send(dest.value(), "Votre code de vérification", msg);
    }

    return new RegisterStartResponse(ch.challengeId(), dest.channel(), mask(dest), props.otpTtlSeconds());
  }

  public boolean verify(String challengeId, String code) {
    return otpService.verify(challengeId, code);
  }

  private Destination decide(RegisterStartRequest req) {
    if (StringUtils.hasText(req.phone())) {
      String p = normalizePhone(req.phone());
      if (p.startsWith(props.localCountryCode())) {
        return new Destination(Channel.SMS, p);
      }
    }
    if (StringUtils.hasText(req.email())) {
      return new Destination(Channel.EMAIL, normalizeEmail(req.email()));
    }
    throw new IllegalArgumentException("phone ou email requis");
  }

  private String normalizePhone(String phone) {
    return phone.replaceAll("[\\\n\\\r\\\t\\\s\\\-()]", "");
  }

  private String normalizeEmail(String email) {
    return email.trim().toLowerCase();
  }

  private String mask(Destination dest) {
    String v = dest.value();
    if (dest.channel() == Channel.EMAIL) {
      int at = v.indexOf("@");
      if (at <= 1) return "***" + v.substring(at);
      return v.substring(0, 1) + "***" + v.substring(at);
    }
    if (v.length() <= 4) return "****";
    return v.substring(0, Math.min(6, v.length()-2)) + "****" + v.substring(v.length()-2);
  }
}
EOF

# -----------------------------
# Tests unitaires (adaptés VaultTemplate)
# -----------------------------
cat > "${SRC_TEST}/vault/VaultTransitMacServiceTest.java" <<EOF
package ${PKG}.vault;

import heritage.africa.otp.AppProps;
import org.junit.jupiter.api.Test;
import org.springframework.vault.core.VaultTemplate;
import org.springframework.vault.support.VaultResponse;


import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

public class VaultTransitMacServiceTest {

  @Test
  void hmac_callsVaultTransitAndReturnsHmac() {
    AppProps props = new AppProps(
        new AppProps.Otp(300,5,1800),
        new AppProps.Locale("+221"),
        new AppProps.Vault("otp-hmac"),
        new AppProps.Smseagle("https://smseagle.local","u","p","/api/v2/messages/sms")
    );

    VaultResponse vr = new VaultResponse();
    vr.setData(Map.of("hmac", "vault:v1:abc"));
    
    VaultTemplate vault = mock(VaultTemplate.class);
    when(vault.write(eq("transit/hmac/otp-hmac"), any(Map.class))).thenReturn(vr);

    VaultTransitMacService svc = new VaultTransitMacService(vault, props);

    String h = svc.hmac("cid","+221771234567","123456");
    assertThat(h).isEqualTo("vault:v1:abc");

    verify(vault, times(1)).write(eq("transit/hmac/otp-hmac"), any(Map.class));
  }
}
EOF

cat > "${SRC_TEST}/notify/SmseagleSmsSenderTest.java" <<EOF
package ${PKG}.notify;

import ${PKG}.AppProps;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestTemplate;
import org.springframework.test.web.client.MockRestServiceServer;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

public class SmseagleSmsSenderTest {

  @Test
  void send_usesBasicAuthHeader() {
    AppProps props = new AppProps(
        new AppProps.Otp(300,5,1800),
        new AppProps.Locale("+221"),
        new AppProps.Vault("otp-hmac"),
        new AppProps.Smseagle("http://smseagle.local","user","pass","/api/v2/messages/sms")
    );

    SmseagleSmsSender sender = new SmseagleSmsSender(props);

    RestTemplate rt = new RestTemplate();
    MockRestServiceServer server = MockRestServiceServer.bindTo(rt).build();

    var testClient = org.springframework.web.client.RestClient.builder()
        .baseUrl("http://smseagle.local")
        .requestFactory(new org.springframework.http.client.ClientHttpRequestFactory() {
          @Override public org.springframework.http.client.ClientHttpRequest createRequest(java.net.URI uri, org.springframework.http.HttpMethod httpMethod) throws java.io.IOException {
            return rt.getRequestFactory().createRequest(uri, httpMethod);
          }
        })
        .defaultHeaders(h -> {
          h.setBasicAuth("user","pass");
          h.setContentType(MediaType.APPLICATION_JSON);
        })
        .build();

    ReflectionTestUtils.setField(sender, "client", testClient);

    String basic = "Basic " + Base64.getEncoder().encodeToString("user:pass".getBytes(StandardCharsets.UTF_8));

    server.expect(requestTo("http://smseagle.local/api/v2/messages/sms"))
        .andExpect(method(org.springframework.http.HttpMethod.POST))
        .andExpect(header("Authorization", basic))
        .andRespond(withSuccess("{}", MediaType.APPLICATION_JSON));

    sender.send("+221771234567", "Hello");
    server.verify();
  }
}
EOF

cat > "${SRC_TEST}/OtpServiceTest.java" <<EOF
package ${PKG};
import heritage.africa.otp.otp.InMemoryOtpStore;
import heritage.africa.otp.vault.VaultTransitMacService;
import org.junit.jupiter.api.Test;
import org.springframework.vault.core.VaultTemplate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

public class OtpServiceTest {

  @Test
  void create_then_verify_success() {
    AppProps props = new AppProps(
        new AppProps.Otp(300,5,1800),
        new AppProps.Locale("+221"),
        new AppProps.Vault("otp-hmac"),
        new AppProps.Smseagle("http://x","u","p","/api/v2/messages/sms")
    );

    // Fake MAC déterministe (mock VaultTransitMacService au lieu d'appeler Vault)
    VaultTransitMacService mac = mock(VaultTransitMacService.class);
    when(mac.hmac(anyString(), anyString(), anyString())).thenAnswer(inv ->
        "MAC(" + inv.getArgument(0) + "," + inv.getArgument(1) + "," + inv.getArgument(2) + ")"
    );

    var store = new InMemoryOtpStore();
    var svc = new OtpService(store, mac, props);

    var ch = svc.create(new Destination(Channel.SMS, "+221771234567"));
    // on “recalcule” le même MAC attendu
    when(mac.hmac(eq(ch.challengeId()), eq("+221771234567"), eq(ch.code()))).thenReturn("MAC(" + ch.challengeId() + ",+221771234567," + ch.code() + ")");

    assertThat(svc.verify(ch.challengeId(), ch.code())).isTrue();
    assertThat(svc.verify(ch.challengeId(), ch.code())).isFalse(); // one-time
  }

  @Test
  void verify_fails_and_locks_after_max_attempts() {
    AppProps props = new AppProps(
        new AppProps.Otp(300,2,60),
        new AppProps.Locale("+221"),
        new AppProps.Vault("otp-hmac"),
        new AppProps.Smseagle("http://x","u","p","/api/v2/messages/sms")
    );
  
    VaultTransitMacService mac = mock(VaultTransitMacService.class);
    when(mac.hmac(anyString(), anyString(), anyString())).thenAnswer(inv ->
        "MAC(" + inv.getArgument(0) + "," + inv.getArgument(1) + "," + inv.getArgument(2) + ")"
    );
  
    var store = new InMemoryOtpStore();
    var svc = new OtpService(store, mac, props);
  
    var ch = svc.create(new Destination(Channel.EMAIL, "user@example.com"));
  
    assertThat(svc.verify(ch.challengeId(), "000000")).isFalse();
    assertThat(svc.verify(ch.challengeId(), "111111")).isFalse(); // atteint max attempts -> lock
    assertThat(svc.verify(ch.challengeId(), ch.code())).isFalse(); // locked
  }

}
EOF

# -----------------------------
# README + scripts
# -----------------------------
cat > "$BASE/README.md" <<EOF
# ${NAME}

Microservice OTP d'inscription:
- Locaux (indicatif \`+221\`) : OTP par SMS via **SMSEAGLE** (Basic Auth user/pass)
- Étrangers : OTP par **Email** (SMTP)
- Stockage OTP : **Redis** (TTL) ou **InMemory** (dev/test)
- HMAC OTP : **Vault Transit** (\`transit/hmac/{key}\`) — secret HMAC ne sort pas de Vault
- Prod OpenShift “propre” : **Vault Kubernetes Auth** (pas de token statique)

## Profils
- dev : Vault OFF, store memory
- test : Vault OFF, store memory
- docker : store redis, Vault TOKEN optionnel via VAULT_ENABLED/VAULT_TOKEN
- kubernetes : Vault ON (KUBERNETES auth), store redis
- qualif/preprod/prod : incluent kubernetes

## API
- POST \`/auth/register/start\`
- POST \`/auth/register/verify\`
- Health: \`/actuator/health/liveness\` et \`/actuator/health/readiness\`

## Build & Test
\`\`\`bash
mvn test
mvn package
\`\`\`

## Local (dev)
\`\`\`bash
SPRING_PROFILES_ACTIVE=dev mvn spring-boot:run
\`\`\`

## Docker (profil docker)
\`\`\`bash
docker build -f docker/Dockerfile -t ${IMAGE} .
docker run --rm -p 8080:8080 \\
  -e SPRING_PROFILES_ACTIVE=docker \\
  -e OTP_STORE=redis \\
  -e REDIS_HOST=redis \\
  ${IMAGE}
\`\`\`

## OpenShift (kustomize)
\`\`\`bash
oc new-project ${K8S_NS} || true
oc apply -k manifests/openshift
\`\`\`

### Vault côté OpenShift (rappel)
Le rôle Vault Kubernetes doit binder:
- ServiceAccount: \`${NAME}-sa\`
- Namespace: \`${K8S_NS}\`
EOF

cat > "$BASE/scripts/dev-redis-vault.sh" <<'EOF'
#!/usr/bin/env bash
set -e
# Helper local : redis + vault (dev token) pour tests manuels
docker network create otp-net >/dev/null 2>&1 || true

docker run -d --name otp-redis --network otp-net -p 6379:6379 redis:7-alpine >/dev/null 2>&1 || true

docker run -d --name otp-vault --network otp-net -p 8200:8200 \
  -e 'VAULT_DEV_ROOT_TOKEN_ID=devtoken' \
  -e 'VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200' \
  hashicorp/vault:1.16 >/dev/null 2>&1 || true

echo "Vault token: devtoken"
echo "Enable transit & create key:"
echo "  export VAULT_ADDR=http://127.0.0.1:8200 VAULT_TOKEN=devtoken"
echo "  vault secrets enable transit"
echo "  vault write -f transit/keys/otp-hmac"
EOF
chmod +x "$BASE/scripts/dev-redis-vault.sh"

# -----------------------------
# Git ignore
# -----------------------------
cat > "$BASE/.gitignore" <<'EOF'
/target
/.idea
/*.iml
/.vscode
*.log
EOF

log "✅ Projet généré: $BASE"
log "Prochaines commandes:"
echo "  cd \"$BASE\""
echo "  mvn test"
echo "  docker build -f docker/Dockerfile -t ${IMAGE} ."
echo "  oc new-project ${K8S_NS} || true"
echo "  oc apply -k manifests/openshift"
