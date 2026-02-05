#!/usr/bin/env bash
# generate-otp-auth-service.sh
# Génère un microservice Spring Boot "OTP Auth" prod-ready (Redis OTP store, Vault Transit HMAC, SMSEAGLE BasicAuth, Email OTP),
# avec tests unitaires, Dockerfile, manifests OpenShift/K8s, et une structure prête à évoluer en microservices.
#
# Usage:
#   ./generate-otp-auth-service.sh --name otp-auth-service --groupId heritage.africa --artifactId otp-auth-service --package heritage.africa.otp \
#     --java 21 --boot 3.3.5 --cloud 2023.0.4 --out ./go-gainde-otp
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
K8S_NS="otp"
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
      sed -n '1,80p' "$0"; exit 0;;
    *) die "Argument inconnu: $1";;
  esac
done

need mkdir
need cat
need sed
need tr

BASE="${OUT_DIR%/}/${ARTIFACT_ID}"
SRC_MAIN="$BASE/src/main/java/$(echo "$PKG" | tr '.' '/')"
SRC_TEST="$BASE/src/test/java/$(echo "$PKG" | tr '.' '/')"
RES_MAIN="$BASE/src/main/resources"
RES_TEST="$BASE/src/test/resources"

if [[ -e "$BASE" ]]; then
  die "Le dossier existe déjà: $BASE (supprime-le ou change --artifactId/--out)"
fi

log "Création du projet: $BASE"
mkdir -p "$SRC_MAIN" "$SRC_MAIN"/dto "$SRC_MAIN"/client "$SRC_MAIN"/config "$SRC_TEST" "$RES_MAIN" "$RES_TEST"
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

    <!-- Vault Config (for env + token) -->
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
# application.yml
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

  cloud:
    vault:
      uri: \${VAULT_URI:http://vault:8200}
      authentication: TOKEN
      token: \${VAULT_TOKEN:}
      kv:
        enabled: true
        backend: secret
        default-context: ${NAME}

management:
  endpoints:
    web:
      exposure:
        include: health,info
  endpoint:
    health:
      probes:
        enabled: true

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
    # Endpoint à ajuster selon ton firmware/API; un seul endroit à modifier
    sms-path: \${SMSEAGLE_SMS_PATH:/api/v2/messages/sms}

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
# K8s / OpenShift manifests (Deployment, Service, Route, Config/Secret placeholders)
# -----------------------------
cat > "$BASE/manifests/openshift/kustomization.yaml" <<EOF
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: ${K8S_NS}
resources:
  - deployment.yaml
  - service.yaml
  - route.yaml
  - configmap.yaml
  - secret.yaml
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
  VAULT_URI: "http://vault:8200"
  VAULT_TRANSIT_KEY: "otp-hmac"
  SMSEAGLE_BASE_URL: "https://smseagle.local"
  SMSEAGLE_SMS_PATH: "/api/v2/messages/sms"
  # SMTP_HOST, SMTP_PORT peuvent aussi être mis ici si non sensibles
EOF

cat > "$BASE/manifests/openshift/secret.yaml" <<EOF
apiVersion: v1
kind: Secret
metadata:
  name: ${NAME}-secret
type: Opaque
stringData:
  VAULT_TOKEN: "CHANGE_ME"
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
      containers:
        - name: ${NAME}
          image: ${IMAGE}
          imagePullPolicy: IfNotPresent
          ports:
            - containerPort: 8080
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

# Route (OpenShift)
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
  # inject host
  sed -i "s/spec:/spec:\n  host: ${ROUTE_HOST}/" "$BASE/manifests/openshift/route.yaml"
fi

# -----------------------------
# Java sources
# -----------------------------
APP_CLASS="${SRC_MAIN}/OtpAuthServiceApplication.java"
cat > "$APP_CLASS" <<EOF
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

# DTOs + enums
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

mkdir -p "${SRC_MAIN}/dto"

# Controller
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

# Senders
mkdir -p "${SRC_MAIN}/notify"
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

  private final RestClient client;
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
    // Ajuste le payload si ton SMSEAGLE attend d'autres champs.
    // L'important: BasicAuth + POST JSON, un seul endroit (smsPath) à adapter.
    client.post()
        .uri(props.smseagleSmsPath())
        .body(Map.of("to", phoneE164, "text", message))
        .retrieve()
        .toBodilessEntity();
  }
}
EOF

# Vault Transit HMAC service
mkdir -p "${SRC_MAIN}/vault"
cat > "${SRC_MAIN}/vault/VaultTransitMacService.java" <<EOF
package ${PKG}.vault;

import ${PKG}.AppProps;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@Service
public class VaultTransitMacService {

  private final RestClient vaultClient;
  private final AppProps props;

  public VaultTransitMacService(AppProps props) {
    this.props = props;
    this.vaultClient = RestClient.builder()
        .baseUrl(System.getenv().getOrDefault("VAULT_URI", "http://vault:8200"))
        .defaultHeaders(h -> {
          String token = System.getenv().getOrDefault("VAULT_TOKEN", "");
          h.set("X-Vault-Token", token);
          h.setContentType(MediaType.APPLICATION_JSON);
        })
        .build();
  }

  public String hmac(String challengeId, String destination, String code) {
    String msg = challengeId + ":" + destination + ":" + code;
    String inputB64 = Base64.getEncoder().encodeToString(msg.getBytes(StandardCharsets.UTF_8));

    Map<String, Object> req = Map.of(
        "input", inputB64,
        "algorithm", "sha2-256"
    );

    Map resp = vaultClient.post()
        .uri("/v1/transit/hmac/{key}", props.vaultTransitKey())
        .body(req)
        .retrieve()
        .body(Map.class);

    Map data = (Map) resp.get("data");
    return (String) data.get("hmac"); // ex: vault:v1:...
  }
}
EOF

# OTP store abstraction + Redis impl (plus InMemory for tests)
mkdir -p "${SRC_MAIN}/otp"
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

    // re-check after increment
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
# Tests unitaires (Vault Transit + SMSEAGLE BasicAuth + OTP verify)
# - On teste VaultTransitMacService via MockRestServiceServer
# - On teste SmseagleSmsSender via MockRestServiceServer (BasicAuth header)
# - On teste OtpService via InMemoryOtpStore (vrai flux, sans Redis)
# -----------------------------
mkdir -p "${SRC_TEST}/vault" "${SRC_TEST}/notify" "${SRC_TEST}/otp"

cat > "${SRC_TEST}/vault/VaultTransitMacServiceTest.java" <<EOF
package ${PKG}.vault;

import ${PKG}.AppProps;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;
import org.springframework.test.web.client.MockRestServiceServer;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

public class VaultTransitMacServiceTest {

  @Test
  void hmac_callsVaultTransitAndReturnsHmac() {
    AppProps props = new AppProps(
        new AppProps.Otp(300,5,1800),
        new AppProps.Locale("+221"),
        new AppProps.Vault("otp-hmac"),
        new AppProps.Smseagle("https://smseagle.local","u","p","/api/v2/messages/sms")
    );

    // Construire un RestClient basé sur RestTemplate pour MockRestServiceServer
    RestTemplate rt = new RestTemplate();
    MockRestServiceServer server = MockRestServiceServer.bindTo(rt).build();

    // On remplace le vaultClient interne via reflection (test-friendly)
    VaultTransitMacService svc = new VaultTransitMacService(props);
    RestClient testClient = RestClient.builder()
        .requestFactory(new org.springframework.http.client.ClientHttpRequestFactory() {
          @Override public org.springframework.http.client.ClientHttpRequest createRequest(java.net.URI uri, org.springframework.http.HttpMethod httpMethod) throws java.io.IOException {
            return rt.getRequestFactory().createRequest(uri, httpMethod);
          }
        })
        .baseUrl("http://vault:8200")
        .defaultHeaders(h -> {
          h.set("X-Vault-Token", "t");
          h.setContentType(MediaType.APPLICATION_JSON);
        })
        .build();
    ReflectionTestUtils.setField(svc, "vaultClient", testClient);

    server.expect(requestTo("http://vault:8200/v1/transit/hmac/otp-hmac"))
        .andExpect(method(org.springframework.http.HttpMethod.POST))
        .andExpect(header("X-Vault-Token", "t"))
        .andRespond(withSuccess("{\\"data\\":{\\"hmac\\":\\"vault:v1:abc\\"}}", MediaType.APPLICATION_JSON));

    String h = svc.hmac("cid","+221771234567","123456");
    assertThat(h).isEqualTo("vault:v1:abc");
    server.verify();
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

    // Injecter un RestClient basé RestTemplate mockable
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

import ${PKG}.otp.InMemoryOtpStore;
import ${PKG}.vault.VaultTransitMacService;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

public class OtpServiceTest {

  @Test
  void create_then_verify_success() {
    AppProps props = new AppProps(
        new AppProps.Otp(300,5,1800),
        new AppProps.Locale("+221"),
        new AppProps.Vault("otp-hmac"),
        new AppProps.Smseagle("http://x","u","p","/api/v2/messages/sms")
    );

    // Fake Vault MAC (déterministe) pour test unitaire pur
    VaultTransitMacService mac = new VaultTransitMacService(props) {
      @Override public String hmac(String challengeId, String destination, String code) {
        return "MAC(" + challengeId + "," + destination + "," + code + ")";
      }
    };

    var store = new InMemoryOtpStore();
    var svc = new OtpService(store, mac, props);

    var ch = svc.create(new Destination(Channel.SMS, "+221771234567"));

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

    VaultTransitMacService mac = new VaultTransitMacService(props) {
      @Override public String hmac(String challengeId, String destination, String code) {
        return "MAC(" + challengeId + "," + destination + "," + code + ")";
      }
    };

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
- Locaux (préfixe ${K8S_NS} / indicatif \`+221\`) : OTP par SMS via **SMSEAGLE** (Basic Auth user/pass)
- Étrangers : OTP par **Email** (SMTP)
- Stockage OTP : **Redis** (TTL)
- HMAC OTP : **Vault Transit** (\`transit/hmac/{key}\`) (le secret ne sort pas de Vault)
- Prêt OpenShift: Dockerfile non-root + manifests (Deployment/Service/Route)

## API
- POST \`/auth/register/start\`
- POST \`/auth/register/verify\`
- Health: \`/actuator/health/liveness\` et \`/actuator/health/readiness\`

## Build & Test
\`\`\`bash
mvn test
mvn package
\`\`\`

## Docker
\`\`\`bash
docker build -f docker/Dockerfile -t ${IMAGE} .
docker run --rm -p 8080:8080 -e VAULT_TOKEN="s.xxxxx" -e VAULT_URI="http://vault:8200" ${IMAGE}

\`\`\`

## OpenShift (kustomize)
\`\`\`bash
oc new-project ${K8S_NS} || true
oc apply -k manifests/openshift
\`\`\`

> Ajuster \`app.smseagle.sms-path\` selon ton firmware/API SMSEAGLE.
EOF

cat > "$BASE/scripts/dev-redis-vault.sh" <<'EOF'
#!/usr/bin/env bash
set -e
# Petit helper local (dev) : redis + vault (token simple)
# Nécessite docker/podman.
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
echo "  oc apply -k manifests/openshift"

