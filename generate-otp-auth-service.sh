#!/usr/bin/env bash
# generate-otp-auth-service.sh
# Version complète avec docker-compose, scripts et tests corrigés

set -euo pipefail

# Configuration par défaut
NAME="otp-auth-service"
GROUP_ID="heritage.africa"
ARTIFACT_ID="otp-auth-service"
PKG="heritage.africa.otp"
JAVA_VER="21"
BOOT_VER="3.2.5"
CLOUD_VER="2023.0.1"
OUT_DIR="."
PORT="8080"
K8S_NS="otp-system"
IMAGE="otp-auth-service:latest"

# Couleurs pour les logs
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
log_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Traitement des arguments
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
    -h|--help)
      echo "Usage: $0 [options]"
      exit 0;;
    *) log_error "Argument inconnu: $1"; exit 1;;
  esac
done

BASE="${OUT_DIR%/}/${ARTIFACT_ID}"
SRC_MAIN="$BASE/src/main/java/$(echo "$PKG" | tr '.' '/')"
SRC_TEST="$BASE/src/test/java/$(echo "$PKG" | tr '.' '/')"
RES_MAIN="$BASE/src/main/resources"
RES_TEST="$BASE/src/test/resources"

# Création de la structure
log_info "Création de la structure du projet..."
mkdir -p "$SRC_MAIN"/{dto,client,config,notify,vault,otp}
mkdir -p "$SRC_TEST"/{vault,notify,otp}
mkdir -p "$RES_MAIN" "$RES_TEST"
mkdir -p "$BASE"/{docker,docker/vault,scripts,k8s/base,k8s/overlays/{dev,prod}}

# ============================================
# 1. Fichiers Maven (pom.xml)
# ============================================
log_info "Génération du pom.xml..."
cat > "$BASE/pom.xml" <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 
         https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>

    <groupId>GROUP_ID_PLACEHOLDER</groupId>
    <artifactId>ARTIFACT_ID_PLACEHOLDER</artifactId>
    <version>1.0.0</version>
    <name>NAME_PLACEHOLDER</name>
    <description>OTP Authentication Service with Vault Integration</description>

    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>BOOT_VER_PLACEHOLDER</version>
        <relativePath/>
    </parent>

    <properties>
        <java.version>JAVA_VER_PLACEHOLDER</java.version>
        <maven.compiler.source>${java.version}</maven.compiler.source>
        <maven.compiler.target>${java.version}</maven.compiler.target>
        <project.build.sourceEncoding>UTF-8</project.build.sourceEncoding>
        <testcontainers.version>1.19.3</testcontainers.version>
    </properties>

    <dependencies>
        <!-- Spring Boot Starters -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-web</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-validation</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-data-redis</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-mail</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-configuration-processor</artifactId>
            <optional>true</optional>
        </dependency>

        <!-- Test Dependencies -->
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.testcontainers</groupId>
            <artifactId>testcontainers</artifactId>
            <version>${testcontainers.version}</version>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.testcontainers</groupId>
            <artifactId>junit-jupiter</artifactId>
            <version>${testcontainers.version}</version>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
            <plugin>
                <groupId>org.apache.maven.plugins</groupId>
                <artifactId>maven-compiler-plugin</artifactId>
                <configuration>
                    <parameters>true</parameters>
                </configuration>
            </plugin>
        </plugins>
    </build>
</project>
EOF

# Remplacer les placeholders dans pom.xml
sed -i "s/GROUP_ID_PLACEHOLDER/${GROUP_ID}/g" "$BASE/pom.xml"
sed -i "s/ARTIFACT_ID_PLACEHOLDER/${ARTIFACT_ID}/g" "$BASE/pom.xml"
sed -i "s/NAME_PLACEHOLDER/${NAME}/g" "$BASE/pom.xml"
sed -i "s/JAVA_VER_PLACEHOLDER/${JAVA_VER}/g" "$BASE/pom.xml"
sed -i "s/BOOT_VER_PLACEHOLDER/${BOOT_VER}/g" "$BASE/pom.xml"

# ============================================
# 2. Configuration Spring Boot
# ============================================
log_info "Génération des fichiers de configuration..."

# Application principale
cat > "$RES_MAIN/application.yml" <<EOF
spring:
  application:
    name: ${NAME}
  profiles:
    active: \${SPRING_PROFILES_ACTIVE:dev}

server:
  port: ${PORT}
  error:
    include-message: always
    include-binding-errors: always

management:
  endpoints:
    web:
      exposure:
        include: health,info,metrics,prometheus
  endpoint:
    health:
      show-details: always
      probes:
        enabled: true

vault:
  enabled: \${VAULT_ENABLED:false}

app:
  otp:
    ttl-seconds: \${OTP_TTL:300}
    length: \${OTP_LENGTH:6}
    max-attempts: \${OTP_MAX_ATTEMPTS:3}
    lock-minutes: \${OTP_LOCK_MINUTES:30}
  locale:
    local-country-code: \${LOCAL_COUNTRY_CODE:+221}
  vault:
    transit-key: \${VAULT_TRANSIT_KEY:otp-hmac}
  smseagle:
    base-url: \${SMSEAGLE_URL:http://smseagle:8080}
    username: \${SMSEAGLE_USERNAME:admin}
    password: \${SMSEAGLE_PASSWORD:admin}
EOF

# Profil dev
cat > "$RES_MAIN/application-dev.yml" <<EOF
spring:
  data:
    redis:
      host: \${REDIS_HOST:localhost}
      port: \${REDIS_PORT:6379}
  mail:
    host: \${SMTP_HOST:localhost}
    port: \${SMTP_PORT:1025}

vault:
  enabled: false

logging:
  level:
    ${PKG}: DEBUG

otp:
  store: memory
EOF

# Profil docker
cat > "$RES_MAIN/application-docker.yml" <<EOF
spring:
  data:
    redis:
      host: redis
      port: 6379
  mail:
    host: mailhog
    port: 1025

vault:
  enabled: true

logging:
  level:
    ${PKG}: INFO

otp:
  store: redis

management:
  health:
    vault:
      enabled: true
EOF

# ============================================
# 3. Code Java
# ============================================
log_info "Génération du code Java..."

# Application principale
cat > "${SRC_MAIN}/OtpAuthApplication.java" <<EOF
package ${PKG};

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;

@SpringBootApplication
@EnableConfigurationProperties(AppProps.class)
public class OtpAuthApplication {
    public static void main(String[] args) {
        SpringApplication.run(OtpAuthApplication.class, args);
    }
}
EOF

# AppProps
cat > "${SRC_MAIN}/AppProps.java" <<EOF
package ${PKG};

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties(prefix = "app")
public record AppProps(
    Otp otp,
    Locale locale,
    Vault vault,
    Smseagle smseagle
) {
    public record Otp(
        @DefaultValue("300") long ttlSeconds,
        @DefaultValue("6") int length,
        @DefaultValue("3") int maxAttempts,
        @DefaultValue("30") long lockMinutes
    ) {}
    
    public record Locale(
        @DefaultValue("+221") String localCountryCode
    ) {}
    
    public record Vault(
        @DefaultValue("otp-hmac") String transitKey
    ) {}
    
    public record Smseagle(
        String baseUrl,
        String username,
        String password
    ) {}
}
EOF

# Enums
cat > "${SRC_MAIN}/Channel.java" <<EOF
package ${PKG};

public enum Channel {
    SMS, EMAIL
}
EOF

# DTOs
cat > "${SRC_MAIN}/dto/OtpRequest.java" <<EOF
package ${PKG}.dto;

import jakarta.validation.constraints.Pattern;
import jakarta.validation.constraints.Email;

public record OtpRequest(
    @Pattern(regexp = "^\\\\+?[0-9]{10,15}\$", message = "Numéro de téléphone invalide")
    String phone,
    
    @Email(message = "Email invalide")
    String email
) {}
EOF

cat > "${SRC_MAIN}/dto/OtpResponse.java" <<EOF
package ${PKG}.dto;

import ${PKG}.Channel;

public record OtpResponse(
    String challengeId,
    Channel channel,
    String maskedDestination,
    long expiresInSeconds
) {}
EOF

cat > "${SRC_MAIN}/dto/VerifyRequest.java" <<EOF
package ${PKG}.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;

public record VerifyRequest(
    @NotBlank String challengeId,
    @NotBlank @Pattern(regexp = "^[0-9]{6}\$") String code
) {}
EOF

cat > "${SRC_MAIN}/dto/VerifyResponse.java" <<EOF
package ${PKG}.dto;

public record VerifyResponse(
    boolean verified,
    String message
) {}
EOF

# Controller
cat > "${SRC_MAIN}/OtpController.java" <<EOF
package ${PKG};

import ${PKG}.dto.OtpRequest;
import ${PKG}.dto.OtpResponse;
import ${PKG}.dto.VerifyRequest;
import ${PKG}.dto.VerifyResponse;
import jakarta.validation.Valid;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/auth/register")
public class OtpController {

    private final OtpOrchestrator orchestrator;

    public OtpController(OtpOrchestrator orchestrator) {
        this.orchestrator = orchestrator;
    }

    @PostMapping("/start")
    public ResponseEntity<OtpResponse> start(@Valid @RequestBody OtpRequest request) {
        OtpResponse response = orchestrator.startChallenge(request);
        return ResponseEntity.ok(response);
    }

    @PostMapping("/verify")
    public ResponseEntity<VerifyResponse> verify(@Valid @RequestBody VerifyRequest request) {
        boolean verified = orchestrator.verifyChallenge(request.challengeId(), request.code());
        String message = verified ? "Code validé avec succès" : "Code invalide ou expiré";
        return ResponseEntity.ok(new VerifyResponse(verified, message));
    }
}
EOF

# ============================================
# Interface MacService et implémentations
# ============================================

# Interface MacService
cat > "${SRC_MAIN}/vault/MacService.java" <<EOF
package ${PKG}.vault;

public interface MacService {
    String hmac(String challengeId, String destination, String code);
}
EOF

# Implémentation locale (sans Vault)
cat > "${SRC_MAIN}/vault/LocalMacService.java" <<EOF
package ${PKG}.vault;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Service;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Service
@ConditionalOnProperty(name = "vault.enabled", havingValue = "false", matchIfMissing = true)
public class LocalMacService implements MacService {

    private final byte[] secret;

    public LocalMacService() {
        // Secret DEV uniquement (ne pas utiliser en prod)
        String s = System.getenv().getOrDefault("LOCAL_HMAC_SECRET", "dev-local-secret-change-me");
        this.secret = s.getBytes(StandardCharsets.UTF_8);
    }

    @Override
    public String hmac(String challengeId, String destination, String code) {
        try {
            String msg = challengeId + ":" + destination + ":" + code;
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret, "HmacSHA256"));
            byte[] out = mac.doFinal(msg.getBytes(StandardCharsets.UTF_8));
            return "local:v1:" + Base64.getEncoder().encodeToString(out);
        } catch (Exception e) {
            throw new IllegalStateException("Local HMAC failed", e);
        }
    }
}
EOF

# Implémentation Vault (via API REST)
cat > "${SRC_MAIN}/vault/VaultTransitMacService.java" <<EOF
package ${PKG}.vault;

import heritage.africa.otp.AppProps;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;

@Service
@ConditionalOnProperty(name = "vault.enabled", havingValue = "true")
public class VaultTransitMacService implements MacService {

    private final RestClient vaultClient;
    private final AppProps props;

    public VaultTransitMacService(AppProps props) {
        this.props = props;

        String vaultUri = System.getenv().getOrDefault("VAULT_URI", "http://vault:8200");
        String token = System.getenv().getOrDefault("VAULT_TOKEN", "");
        
        RestClient.Builder builder = RestClient.builder()
            .baseUrl(vaultUri)
            .defaultHeaders(h -> {
                h.setContentType(MediaType.APPLICATION_JSON);
            });
        
        // N'ajouter le token que s'il est present
        if (!token.isBlank()) {
            builder = builder.defaultHeaders(h -> h.set("X-Vault-Token", token));
        }

        this.vaultClient = builder.build();
    }

    @Override
    @SuppressWarnings("unchecked")
    public String hmac(String challengeId, String destination, String code) {
        String msg = challengeId + ":" + destination + ":" + code;
        String inputB64 = Base64.getEncoder().encodeToString(msg.getBytes(StandardCharsets.UTF_8));

        Map<String, Object> req = Map.of(
            "input", inputB64,
            "algorithm", "sha2-256"
        );

        Map<String, Object> resp = vaultClient.post()
            .uri("/v1/transit/hmac/{key}", props.vault().transitKey())
            .body(req)
            .retrieve()
            .body(Map.class);

        if (resp == null || resp.get("data") == null) {
            throw new IllegalStateException("Vault transit response empty");
        }

        Map<String, Object> data = (Map<String, Object>) resp.get("data");
        Object h = data.get("hmac");
        if (h == null) {
            throw new IllegalStateException("Vault transit response missing hmac");
        }
        return h.toString();
    }
}
EOF

# ============================================
# Service OTP
# ============================================
cat > "${SRC_MAIN}/OtpService.java" <<EOF
package ${PKG};

import ${PKG}.otp.OtpStore;
import ${PKG}.vault.MacService;
import org.springframework.stereotype.Service;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.UUID;

@Service
public class OtpService {

    private final SecureRandom random = new SecureRandom();
    private final OtpStore otpStore;
    private final MacService macService;
    private final AppProps properties;

    public OtpService(OtpStore otpStore, MacService macService, AppProps properties) {
        this.otpStore = otpStore;
        this.macService = macService;
        this.properties = properties;
    }

    public OtpChallenge createChallenge(String destination, Channel channel) {
        String challengeId = UUID.randomUUID().toString();
        String code = generateCode();
        String hmac = macService.hmac(challengeId, destination, code);
        
        otpStore.save(challengeId, destination, channel, hmac, properties.otp().ttlSeconds());
        
        return new OtpChallenge(challengeId, code);
    }

    public boolean verifyChallenge(String challengeId, String code) {
        var record = otpStore.find(challengeId);
        if (record.isEmpty()) {
            return false;
        }

        var otpRecord = record.get();
        
        if (otpRecord.lockedUntil() != null && 
            Instant.now().isBefore(otpRecord.lockedUntil())) {
            return false;
        }

        if (otpRecord.attempts() >= properties.otp().maxAttempts()) {
            Instant lockUntil = Instant.now().plusSeconds(properties.otp().lockMinutes() * 60);
            otpStore.lock(challengeId, lockUntil);
            return false;
        }

        String expectedHmac = macService.hmac(
            challengeId, 
            otpRecord.destination(), 
            code
        );

        boolean isValid = constantTimeEquals(expectedHmac, otpRecord.hmac());

        if (isValid) {
            otpStore.delete(challengeId);
            return true;
        } else {
            otpStore.incrementAttempts(challengeId);
            return false;
        }
    }

    private String generateCode() {
        int code = random.nextInt((int) Math.pow(10, properties.otp().length()));
        return String.format("%0" + properties.otp().length() + "d", code);
    }

    private boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) return false;
        if (a.length() != b.length()) return false;
        
        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }
        return result == 0;
    }

    public record OtpChallenge(String challengeId, String code) {}
}
EOF

# ============================================
# Store interfaces et implémentations
# ============================================
cat > "${SRC_MAIN}/otp/OtpStore.java" <<EOF
package ${PKG}.otp;

import ${PKG}.Channel;
import java.time.Instant;
import java.util.Optional;

public interface OtpStore {
    void save(String challengeId, String destination, Channel channel, String hmac, long ttlSeconds);
    Optional<OtpRecord> find(String challengeId);
    void incrementAttempts(String challengeId);
    void lock(String challengeId, Instant lockUntil);
    void delete(String challengeId);

    record OtpRecord(
        String challengeId,
        String destination,
        Channel channel,
        String hmac,
        int attempts,
        Instant lockedUntil,
        Instant expiresAt
    ) {}
}
EOF

cat > "${SRC_MAIN}/otp/RedisOtpStore.java" <<EOF
package ${PKG}.otp;

import ${PKG}.Channel;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Repository;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;

import java.time.Instant;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

@Repository
@ConditionalOnProperty(name = "otp.store", havingValue = "redis")
public class RedisOtpStore implements OtpStore {

    private final StringRedisTemplate redis;
    private static final String KEY_PREFIX = "otp:";

    public RedisOtpStore(StringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public void save(String challengeId, String destination, Channel channel, String hmac, long ttlSeconds) {
        String key = KEY_PREFIX + challengeId;
        
        redis.opsForHash().put(key, "destination", destination);
        redis.opsForHash().put(key, "channel", channel.name());
        redis.opsForHash().put(key, "hmac", hmac);
        redis.opsForHash().put(key, "attempts", "0");
        redis.expire(key, ttlSeconds, TimeUnit.SECONDS);
    }

    @Override
    public Optional<OtpRecord> find(String challengeId) {
        String key = KEY_PREFIX + challengeId;
        var entries = redis.opsForHash().entries(key);
        
        if (entries.isEmpty()) {
            return Optional.empty();
        }

        String destination = (String) entries.get("destination");
        Channel channel = Channel.valueOf((String) entries.get("channel"));
        String hmac = (String) entries.get("hmac");
        int attempts = Integer.parseInt((String) entries.getOrDefault("attempts", "0"));
        
        String lockedUntilStr = (String) entries.get("lockedUntil");
        Instant lockedUntil = lockedUntilStr != null ? Instant.parse(lockedUntilStr) : null;
        
        Long ttl = redis.getExpire(key, TimeUnit.SECONDS);
        Instant expiresAt = Instant.now().plusSeconds(ttl != null ? ttl : 0);

        return Optional.of(new OtpRecord(
            challengeId, destination, channel, hmac, attempts, lockedUntil, expiresAt
        ));
    }

    @Override
    public void incrementAttempts(String challengeId) {
        String key = KEY_PREFIX + challengeId;
        redis.opsForHash().increment(key, "attempts", 1);
    }

    @Override
    public void lock(String challengeId, Instant lockUntil) {
        String key = KEY_PREFIX + challengeId;
        redis.opsForHash().put(key, "lockedUntil", lockUntil.toString());
    }

    @Override
    public void delete(String challengeId) {
        redis.delete(KEY_PREFIX + challengeId);
    }
}
EOF

cat > "${SRC_MAIN}/otp/InMemoryOtpStore.java" <<EOF
package ${PKG}.otp;

import ${PKG}.Channel;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.stereotype.Repository;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Repository
@ConditionalOnProperty(name = "otp.store", havingValue = "memory", matchIfMissing = true)
public class InMemoryOtpStore implements OtpStore {

    private final Map<String, OtpRecord> store = new ConcurrentHashMap<>();

    @Override
    public void save(String challengeId, String destination, Channel channel, String hmac, long ttlSeconds) {
        OtpRecord record = new OtpRecord(
            challengeId,
            destination,
            channel,
            hmac,
            0,
            null,
            Instant.now().plusSeconds(ttlSeconds)
        );
        store.put(challengeId, record);
    }

    @Override
    public Optional<OtpRecord> find(String challengeId) {
        OtpRecord record = store.get(challengeId);
        if (record == null || Instant.now().isAfter(record.expiresAt())) {
            store.remove(challengeId);
            return Optional.empty();
        }
        return Optional.of(record);
    }

    @Override
    public void incrementAttempts(String challengeId) {
        store.computeIfPresent(challengeId, (k, v) -> new OtpRecord(
            v.challengeId(),
            v.destination(),
            v.channel(),
            v.hmac(),
            v.attempts() + 1,
            v.lockedUntil(),
            v.expiresAt()
        ));
    }

    @Override
    public void lock(String challengeId, Instant lockUntil) {
        store.computeIfPresent(challengeId, (k, v) -> new OtpRecord(
            v.challengeId(),
            v.destination(),
            v.channel(),
            v.hmac(),
            v.attempts(),
            lockUntil,
            v.expiresAt()
        ));
    }

    @Override
    public void delete(String challengeId) {
        store.remove(challengeId);
    }
}
EOF

# ============================================
# Orchestrator
# ============================================
cat > "${SRC_MAIN}/OtpOrchestrator.java" <<EOF
package ${PKG};

import ${PKG}.dto.OtpRequest;
import ${PKG}.dto.OtpResponse;
import ${PKG}.notify.EmailSender;
import ${PKG}.notify.SmsSender;
import org.springframework.stereotype.Service;

@Service
public class OtpOrchestrator {

    private final OtpService otpService;
    private final SmsSender smsSender;
    private final EmailSender emailSender;
    private final AppProps props;

    public OtpOrchestrator(
            OtpService otpService,
            SmsSender smsSender,
            EmailSender emailSender,
            AppProps props) {
        this.otpService = otpService;
        this.smsSender = smsSender;
        this.emailSender = emailSender;
        this.props = props;
    }

    public OtpResponse startChallenge(OtpRequest request) {
        Destination destination = determineDestination(request);
        OtpService.OtpChallenge challenge = otpService.createChallenge(
            destination.value(), 
            destination.channel()
        );

        String message = String.format(
            "Votre code de vérification est: %s (valable %d minutes)",
            challenge.code(),
            props.otp().ttlSeconds() / 60
        );

        if (destination.channel() == Channel.SMS) {
            smsSender.send(destination.value(), message);
        } else {
            emailSender.send(destination.value(), "Code de vérification", message);
        }

        return new OtpResponse(
            challenge.challengeId(),
            destination.channel(),
            maskDestination(destination),
            props.otp().ttlSeconds()
        );
    }

    public boolean verifyChallenge(String challengeId, String code) {
        return otpService.verifyChallenge(challengeId, code);
    }

    private Destination determineDestination(OtpRequest request) {
        if (request.phone() != null && !request.phone().isEmpty()) {
            String phone = normalizePhone(request.phone());
            if (phone.startsWith(props.locale().localCountryCode())) {
                return new Destination(Channel.SMS, phone);
            }
        }
        if (request.email() != null && !request.email().isEmpty()) {
            return new Destination(Channel.EMAIL, normalizeEmail(request.email()));
        }
        throw new IllegalArgumentException("Aucune destination valide fournie");
    }

    private String normalizePhone(String phone) {
        return phone.replaceAll("[^0-9+]", "");
    }

    private String normalizeEmail(String email) {
        return email.trim().toLowerCase();
    }

    private String maskDestination(Destination dest) {
        String value = dest.value();
        if (dest.channel() == Channel.EMAIL) {
            int atIndex = value.indexOf('@');
            if (atIndex > 1) {
                return value.charAt(0) + "***" + value.substring(atIndex - 1);
            }
            return "***" + value.substring(atIndex);
        } else {
            if (value.length() <= 6) return "****";
            return value.substring(0, 4) + "****" + value.substring(value.length() - 2);
        }
    }

    private record Destination(Channel channel, String value) {}
}
EOF

# ============================================
# Notifications
# ============================================
cat > "${SRC_MAIN}/notify/SmsSender.java" <<EOF
package ${PKG}.notify;

public interface SmsSender {
    void send(String phoneNumber, String message);
}
EOF

cat > "${SRC_MAIN}/notify/EmailSender.java" <<EOF
package ${PKG}.notify;

public interface EmailSender {
    void send(String to, String subject, String body);
}
EOF

cat > "${SRC_MAIN}/notify/SmseagleSender.java" <<EOF
package ${PKG}.notify;

import ${PKG}.AppProps;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestClient;

import java.util.Base64;
import java.util.Map;

@Service
public class SmseagleSender implements SmsSender {

    private final RestClient restClient;

    public SmseagleSender(AppProps props) {
        String auth = props.smseagle().username() + ":" + props.smseagle().password();
        String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
        
        this.restClient = RestClient.builder()
            .baseUrl(props.smseagle().baseUrl())
            .defaultHeader(HttpHeaders.AUTHORIZATION, "Basic " + encodedAuth)
            .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
            .build();
    }

    @Override
    public void send(String phoneNumber, String message) {
        Map<String, Object> request = Map.of(
            "to", phoneNumber,
            "message", message
        );

        restClient.post()
            .uri("/send")
            .body(request)
            .retrieve()
            .toBodilessEntity();
    }
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
        SimpleMailMessage message = new SimpleMailMessage();
        message.setTo(to);
        message.setSubject(subject);
        message.setText(body);
        mailSender.send(message);
    }
}
EOF

# ============================================
# 4. Tests
# ============================================
log_info "Génération des tests..."

# Test VaultTransitMacService
cat > "${SRC_TEST}/vault/VaultTransitMacServiceTest.java" <<EOF
package ${PKG}.vault;

import ${PKG}.AppProps;
import org.junit.jupiter.api.Test;
import org.springframework.http.MediaType;
import org.springframework.test.util.ReflectionTestUtils;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;
import org.springframework.test.web.client.MockRestServiceServer;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.client.match.MockRestRequestMatchers.*;
import static org.springframework.test.web.client.response.MockRestResponseCreators.withSuccess;

public class VaultTransitMacServiceTest {

  @Test
  void hmac_callsVaultTransitAndReturnsHmac() {
    // Utiliser des proprietes systeme pour le test
    System.setProperty("VAULT_URI", "http://vault:8200");
    System.setProperty("VAULT_TOKEN", "test-token");
    
    try {
      AppProps props = new AppProps(
          new AppProps.Otp(300, 6, 3, 30),
          new AppProps.Locale("+221"),
          new AppProps.Vault("otp-hmac"),
          new AppProps.Smseagle("https://smseagle.local", "u", "p")
      );

      // Construire un RestClient base sur RestTemplate pour MockRestServiceServer
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
            h.set("X-Vault-Token", "test-token");
            h.setContentType(MediaType.APPLICATION_JSON);
          })
          .build();
      ReflectionTestUtils.setField(svc, "vaultClient", testClient);

      server.expect(requestTo("http://vault:8200/v1/transit/hmac/otp-hmac"))
          .andExpect(method(org.springframework.http.HttpMethod.POST))
          .andExpect(header("X-Vault-Token", "test-token"))
          .andRespond(withSuccess("{\"data\":{\"hmac\":\"vault:v1:abc\"}}", MediaType.APPLICATION_JSON));

      String h = svc.hmac("cid","+221771234567","123456");
      assertThat(h).isEqualTo("vault:v1:abc");
      server.verify();
      
    } finally {
      // Nettoyer les proprietes systeme
      System.clearProperty("VAULT_URI");
      System.clearProperty("VAULT_TOKEN");
    }
  }
}
EOF

# Test LocalMacService
cat > "${SRC_TEST}/vault/LocalMacServiceTest.java" <<EOF
package ${PKG}.vault;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class LocalMacServiceTest {

    private LocalMacService localMacService;

    @BeforeEach
    void setUp() {
        localMacService = new LocalMacService();
    }

    @Test
    void hmac_ShouldReturnConsistentResult() {
        // Given
        String challengeId = "test-challenge";
        String destination = "+33612345678";
        String code = "123456";

        // When
        String result1 = localMacService.hmac(challengeId, destination, code);
        String result2 = localMacService.hmac(challengeId, destination, code);

        // Then
        assertThat(result1).isNotNull().startsWith("local:v1:");
        assertThat(result2).isEqualTo(result1);
    }

    @Test
    void hmac_ShouldReturnDifferentResultsForDifferentInputs() {
        // Given
        String challengeId = "test-challenge";
        String destination = "+33612345678";
        String code1 = "123456";
        String code2 = "654321";

        // When
        String result1 = localMacService.hmac(challengeId, destination, code1);
        String result2 = localMacService.hmac(challengeId, destination, code2);

        // Then
        assertThat(result1).isNotEqualTo(result2);
    }
}
EOF

# Test OtpService
cat > "${SRC_TEST}/otp/OtpServiceTest.java" <<EOF
package ${PKG}.otp;

import ${PKG}.Channel;
import ${PKG}.OtpService;
import ${PKG}.AppProps;
import ${PKG}.vault.LocalMacService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;

@ExtendWith(MockitoExtension.class)
class OtpServiceTest {

    private OtpService otpService;
    private InMemoryOtpStore otpStore;

    @BeforeEach
    void setUp() {
        AppProps.Otp otpProps = new AppProps.Otp(300, 6, 3, 30);
        AppProps.Locale localeProps = new AppProps.Locale("+221");
        AppProps.Vault vaultProps = new AppProps.Vault("otp-hmac");
        AppProps.Smseagle smseagleProps = new AppProps.Smseagle("http://localhost", "user", "pass");
        AppProps props = new AppProps(otpProps, localeProps, vaultProps, smseagleProps);
        
        otpStore = new InMemoryOtpStore();
        otpService = new OtpService(otpStore, new LocalMacService(), props);
    }

    @Test
    void createAndVerifyChallenge() {
        String destination = "+33612345678";
        Channel channel = Channel.SMS;

        var challenge = otpService.createChallenge(destination, channel);

        assertThat(challenge.challengeId()).isNotNull();
        assertThat(challenge.code()).hasSize(6);

        boolean verified = otpService.verifyChallenge(challenge.challengeId(), challenge.code());
        assertThat(verified).isTrue();

        boolean verifiedAgain = otpService.verifyChallenge(challenge.challengeId(), challenge.code());
        assertThat(verifiedAgain).isFalse();
    }

    @Test
    void maxAttemptsShouldLock() {
        String destination = "test@example.com";
        Channel channel = Channel.EMAIL;
        var challenge = otpService.createChallenge(destination, channel);

        for (int i = 0; i < 3; i++) {
            boolean verified = otpService.verifyChallenge(challenge.challengeId(), "000000");
            assertThat(verified).isFalse();
        }

        boolean verified = otpService.verifyChallenge(challenge.challengeId(), challenge.code());
        assertThat(verified).isFalse();
    }
}
EOF

# Test OtpOrchestrator
cat > "${SRC_TEST}/OtpOrchestratorTest.java" <<EOF
package ${PKG};

import ${PKG}.dto.OtpRequest;
import ${PKG}.dto.OtpResponse;
import ${PKG}.notify.EmailSender;
import ${PKG}.notify.SmsSender;
import ${PKG}.otp.InMemoryOtpStore;
import ${PKG}.otp.OtpStore;
import ${PKG}.vault.LocalMacService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class OtpOrchestratorTest {

    @Mock
    private SmsSender smsSender;
    
    @Mock
    private EmailSender emailSender;

    private OtpOrchestrator orchestrator;

    @BeforeEach
    void setUp() {
        AppProps.Otp otpProps = new AppProps.Otp(300, 6, 3, 30);
        AppProps.Locale localeProps = new AppProps.Locale("+221");
        AppProps.Vault vaultProps = new AppProps.Vault("otp-hmac");
        AppProps.Smseagle smseagleProps = new AppProps.Smseagle("http://localhost", "user", "pass");
        AppProps props = new AppProps(otpProps, localeProps, vaultProps, smseagleProps);
        
        OtpStore otpStore = new InMemoryOtpStore();
        OtpService otpService = new OtpService(otpStore, new LocalMacService(), props);
        
        orchestrator = new OtpOrchestrator(otpService, smsSender, emailSender, props);
    }

    @Test
    void startChallengeWithLocalPhoneShouldUseSms() {
        OtpRequest request = new OtpRequest("+221771234567", null);

        OtpResponse response = orchestrator.startChallenge(request);

        assertThat(response.channel()).isEqualTo(Channel.SMS);
        assertThat(response.maskedDestination()).contains("****");
        verify(smsSender, times(1)).send(anyString(), anyString());
        verify(emailSender, never()).send(anyString(), anyString(), anyString());
    }

    @Test
    void startChallengeWithInternationalPhoneAndEmailShouldUseEmail() {
        OtpRequest request = new OtpRequest("+1234567890", "test@example.com");

        OtpResponse response = orchestrator.startChallenge(request);

        assertThat(response.channel()).isEqualTo(Channel.EMAIL);
        assertThat(response.maskedDestination()).contains("***");
        verify(emailSender, times(1)).send(anyString(), anyString(), anyString());
        verify(smsSender, never()).send(anyString(), anyString());
    }
}
EOF

# ============================================
# 5. Docker Compose et scripts
# ============================================
log_info "Génération des fichiers Docker et scripts..."

# Dockerfile
cat > "$BASE/docker/Dockerfile" <<'EOF'
# syntax=docker/dockerfile:1
ARG JAVA_VERSION=21

# Build stage
FROM maven:3.9-eclipse-temurin-${JAVA_VERSION} AS build
WORKDIR /build

# Copie des fichiers Maven
COPY pom.xml .
RUN mvn dependency:go-offline -B

# Copie et compilation du code source
COPY src ./src
RUN mvn clean package -DskipTests

# Runtime stage
FROM eclipse-temurin:${JAVA_VERSION}-jre-alpine

# Installation des outils de monitoring
RUN apk add --no-cache curl

# Création d'un utilisateur non-root
RUN addgroup -S spring && adduser -S spring -G spring

WORKDIR /app

# Copie du JAR depuis l'étape de build
COPY --from=build /build/target/*.jar app.jar

# Configuration des permissions
RUN chown -R spring:spring /app

USER spring:spring

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=30s --retries=3 \
  CMD curl -f http://localhost:8080/actuator/health || exit 1

EXPOSE 8080

ENV JAVA_OPTS="-Xms256m -Xmx512m -XX:+UseG1GC"

ENTRYPOINT ["sh", "-c", "java $JAVA_OPTS -jar /app/app.jar"]
EOF

# Script d'initialisation Vault
cat > "$BASE/docker/vault/init-vault.sh" <<'EOF'
#!/bin/sh
set -e

echo "⏳ Attente que Vault soit prêt..."
sleep 5

echo "🔧 Configuration de Vault..."

# Activer le moteur Transit
vault secrets enable transit || echo "Transit déjà activé"

# Créer la clé HMAC pour OTP
vault write -f transit/keys/otp-hmac || echo "Clé otp-hmac existe déjà"

echo "✅ Vault configuré avec succès !"

# Tester la configuration
echo "🧪 Test de la clé HMAC..."
vault write transit/hmac/otp-hmac input=$(echo -n "test" | base64)

echo "🎉 Initialisation terminée !"
EOF
chmod +x "$BASE/docker/vault/init-vault.sh"

# Docker Compose
cat > "$BASE/docker-compose.yml" <<'EOF'
services:
  app:
    build:
      context: .
      dockerfile: docker/Dockerfile
    container_name: otp-auth-service
    ports:
      - "8080:8080"
    environment:
      - SPRING_PROFILES_ACTIVE=docker
      - VAULT_TOKEN=dev-token
      - VAULT_URI=http://vault:8200
      - LOCAL_COUNTRY_CODE=+221
      - SMSEAGLE_URL=http://smseagle:8080
      - SMSEAGLE_USERNAME=admin
      - SMSEAGLE_PASSWORD=admin
      - SMSEAGLE_SMS_PATH=/send
      - JAVA_OPTS=-Xms256m -Xmx512m
    depends_on:
      redis:
        condition: service_healthy
      vault:
        condition: service_started
      vault-setup:
        condition: service_completed_successfully
      mailhog:
        condition: service_started
      smseagle:
        condition: service_started
    networks:
      - otp-network
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/actuator/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 40s

  redis:
    image: redis:7-alpine
    container_name: otp-redis
    ports:
      - "6379:6379"
    networks:
      - otp-network
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 5s
      retries: 5
    volumes:
      - redis-data:/data

  vault:
    image: hashicorp/vault:1.15
    container_name: otp-vault
    cap_add:
      - IPC_LOCK
    environment:
      - VAULT_DEV_ROOT_TOKEN_ID=dev-token
      - VAULT_DEV_LISTEN_ADDRESS=0.0.0.0:8200
    ports:
      - "8200:8200"
    networks:
      - otp-network
    

  vault-setup:
    image: hashicorp/vault:1.15
    container_name: otp-vault-setup
    depends_on:
      vault:
        condition: service_started
    environment:
      - VAULT_ADDR=http://vault:8200
      - VAULT_TOKEN=dev-token
    networks:
      - otp-network
    
    volumes:
      - ./docker/vault/init-vault.sh:/init-vault.sh
    entrypoint: ["/bin/sh", "/init-vault.sh"]

  mailhog:
    image: mailhog/mailhog
    container_name: otp-mailhog
    ports:
      - "8025:8025"
      - "1025:1025"
    networks:
      - otp-network
      

  smseagle:
    image: hashicorp/http-echo:1.0.0
    container_name: otp-smseagle-mock
    command:
      - "-listen=:8080"
      - "-status-code=200"
      - "-text={\"status\":\"sent\"}"
    ports:
      - "8081:8080"
    networks:
      - otp-network


networks:
  otp-network:
    driver: bridge

volumes:
  redis-data:
EOF

# 1. Créer les manifests de base
cat > "$BASE/k8s/base/namespace.yaml" <<'EOF'
apiVersion: v1
kind: Namespace
metadata:
  name: otp-system
EOF

cat > "$BASE/k8s/base/configmap.yaml" <<'EOF'
apiVersion: v1
kind: ConfigMap
metadata:
  name: otp-config
  namespace: otp-system
data:
  LOCAL_COUNTRY_CODE: "+221"
  OTP_TTL: "300"
  OTP_LENGTH: "6"
  OTP_MAX_ATTEMPTS: "3"
  OTP_LOCK_MINUTES: "30"
  REDIS_HOST: "redis"
  REDIS_PORT: "6379"
  SMSEAGLE_URL: "http://smseagle:8080"
  SMSEAGLE_USERNAME: "admin"
  SMSEAGLE_SMS_PATH: "/send"
  VAULT_URI: "http://vault:8200"
  SPRING_PROFILES_ACTIVE: "kubernetes"
  JAVA_OPTS: "-Xms256m -Xmx512m"
EOF

cat > "$BASE/k8s/base/secret.yaml" <<'EOF'
apiVersion: v1
kind: Secret
metadata:
  name: otp-secrets
  namespace: otp-system
type: Opaque
stringData:
  SMSEAGLE_PASSWORD: "admin"
  VAULT_TOKEN: "dev-token"
EOF

cat > "$BASE/k8s/base/deployment.yaml" <<'EOF'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: otp-auth-service
  namespace: otp-system
  labels:
    app: otp-auth-service
    version: v1
spec:
  replicas: 2
  selector:
    matchLabels:
      app: otp-auth-service
  template:
    metadata:
      labels:
        app: otp-auth-service
        version: v1
      annotations:
        prometheus.io/scrape: "true"
        prometheus.io/port: "8080"
        prometheus.io/path: "/actuator/prometheus"
    spec:
      containers:
      - name: app
        image: otp-auth-service:latest
        imagePullPolicy: IfNotPresent
        ports:
        - containerPort: 8080
          name: http
        env:
        - name: VAULT_TOKEN
          valueFrom:
            secretKeyRef:
              name: otp-secrets
              key: VAULT_TOKEN
        envFrom:
        - configMapRef:
            name: otp-config
        - secretRef:
            name: otp-secrets
        resources:
          requests:
            memory: "256Mi"
            cpu: "100m"
          limits:
            memory: "512Mi"
            cpu: "500m"
        livenessProbe:
          httpGet:
            path: /actuator/health/liveness
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /actuator/health/readiness
            port: 8080
          initialDelaySeconds: 20
          periodSeconds: 5
        volumeMounts:
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: tmp
        emptyDir: {}
EOF

cat > "$BASE/k8s/base/service.yaml" <<'EOF'
apiVersion: v1
kind: Service
metadata:
  name: otp-auth-service
  namespace: otp-system
  labels:
    app: otp-auth-service
spec:
  selector:
    app: otp-auth-service
  ports:
  - port: 8080
    targetPort: 8080
    name: http
  type: ClusterIP
EOF

cat > "$BASE/k8s/base/serviceaccount.yaml" <<'EOF'
apiVersion: v1
kind: ServiceAccount
metadata:
  name: otp-sa
  namespace: otp-system
EOF

cat > "$BASE/k8s/base/kustomization.yaml" <<'EOF'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
namespace: otp-system
resources:
  - namespace.yaml
  - configmap.yaml
  - secret.yaml
  - deployment.yaml
  - service.yaml
  - serviceaccount.yaml
commonLabels:
  app: otp-auth-service
  managed-by: kustomize
EOF

# 2. Overlay pour développement
cat > "$BASE/k8s/overlays/dev/kustomization.yaml" <<'EOF'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
namespace: otp-dev
patches:
  - target:
      kind: Deployment
      name: otp-auth-service
    patch: |-
      - op: replace
        path: /spec/replicas
        value: 1
      - op: replace
        path: /spec/template/spec/containers/0/image
        value: otp-auth-service:dev
      - op: replace
        path: /spec/template/spec/containers/0/imagePullPolicy
        value: Always
EOF

cat > "$BASE/k8s/overlays/dev/route.yaml" <<'EOF'
apiVersion: route.openshift.io/v1
kind: Route
metadata:
  name: otp-auth-service
  namespace: otp-dev
spec:
  to:
    kind: Service
    name: otp-auth-service
  port:
    targetPort: http
  tls:
    termination: edge
EOF

# 3. Overlay pour production
cat > "$BASE/k8s/overlays/prod/kustomization.yaml" <<'EOF'
apiVersion: kustomize.config.k8s.io/v1beta1
kind: Kustomization
resources:
  - ../../base
namespace: otp-prod
patches:
  - target:
      kind: Deployment
      name: otp-auth-service
    patch: |-
      - op: replace
        path: /spec/replicas
        value: 3
      - op: replace
        path: /spec/template/spec/containers/0/resources/requests/memory
        value: "512Mi"
      - op: replace
        path: /spec/template/spec/containers/0/resources/requests/cpu
        value: "200m"
      - op: replace
        path: /spec/template/spec/containers/0/resources/limits/memory
        value: "1Gi"
      - op: replace
        path: /spec/template/spec/containers/0/resources/limits/cpu
        value: "1000m"
EOF

cat > "$BASE/k8s/overlays/prod/hpa.yaml" <<'EOF'
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: otp-auth-service
  namespace: otp-prod
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: otp-auth-service
  minReplicas: 2
  maxReplicas: 10
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: 70
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
EOF

cat > "$BASE/k8s/overlays/prod/pdb.yaml" <<'EOF'
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: otp-auth-service
  namespace: otp-prod
spec:
  minAvailable: 2
  selector:
    matchLabels:
      app: otp-auth-service
EOF


# Scripts utilitaires
cat > "$BASE/scripts/start-dev.sh" <<'EOF'
#!/bin/bash
set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}🚀 Démarrage de l'environnement de développement OTP${NC}"

# Nettoyage des anciens conteneurs
echo -e "${YELLOW}🧹 Nettoyage des anciens conteneurs...${NC}"
docker-compose down -v --remove-orphans 2>/dev/null || true

# Compilation du projet
echo -e "${YELLOW}📦 Compilation du projet...${NC}"
mvn clean package -DskipTests

# Démarrage des services
echo -e "${YELLOW}🐳 Démarrage des services Docker...${NC}"
docker-compose up -d --build

# Attente que tout soit prêt
echo -e "${YELLOW}⏳ Attente du démarrage des services...${NC}"
sleep 10

# Affichage des logs
echo -e "${GREEN}✅ Services démarrés !${NC}"
echo -e "${BLUE}📝 Logs de l'application:${NC}"
docker-compose logs -f app
EOF
chmod +x "$BASE/scripts/start-dev.sh"

cat > "$BASE/scripts/test-api.sh" <<'EOF'
#!/bin/bash
set -e

BASE_URL="http://localhost:8080"
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo "🧪 Test de l'API OTP"

# 1. Demander un OTP pour un numéro local
echo -e "\n📱 Test SMS local (+221):"
RESPONSE=$(curl -s -X POST $BASE_URL/auth/register/start \
  -H "Content-Type: application/json" \
  -d '{"phone":"+221771234567","email":""}')
echo "$RESPONSE" | python3 -m json.tool 2>/dev/null || echo "$RESPONSE"

# Extraire challengeId
CHALLENGE_ID=$(echo "$RESPONSE" | grep -o '"challengeId":"[^"]*' | cut -d'"' -f4)

if [ -n "$CHALLENGE_ID" ]; then
  echo -e "\n🔑 Test de vérification (mauvais code):"
  curl -s -X POST $BASE_URL/auth/register/verify \
    -H "Content-Type: application/json" \
    -d "{\"challengeId\":\"$CHALLENGE_ID\",\"code\":\"000000\"}" | python3 -m json.tool 2>/dev/null || echo "Pas de JSON"
fi

# 2. Test email pour international
echo -e "\n📧 Test Email (international):"
curl -s -X POST $BASE_URL/auth/register/start \
  -H "Content-Type: application/json" \
  -d '{"phone":"+1234567890","email":"test@example.com"}' | python3 -m json.tool 2>/dev/null || echo "Pas de JSON"

echo -e "\n📊 Health check:"
curl -s $BASE_URL/actuator/health | python3 -m json.tool 2>/dev/null || echo "Pas de JSON"
EOF
chmod +x "$BASE/scripts/test-api.sh"

cat > "$BASE/scripts/check-vault.sh" <<'EOF'
#!/bin/bash
set -e

VAULT_ADDR="http://localhost:8200"
VAULT_TOKEN="dev-token"

echo "🔍 Vérification de Vault..."

# Test de connexion
if curl -s -H "X-Vault-Token: $VAULT_TOKEN" $VAULT_ADDR/v1/sys/health | grep -q "initialized"; then
    echo "✅ Vault est opérationnel"
else
    echo "❌ Vault n'est pas accessible"
    exit 1
fi

# Test de la clé HMAC
echo "🧪 Test de la clé HMAC..."
RESULT=$(curl -s -H "X-Vault-Token: $VAULT_TOKEN" \
    -X POST -d '{"input":"'$(echo -n "test" | base64)'"}' \
    $VAULT_ADDR/v1/transit/hmac/otp-hmac)

if echo "$RESULT" | grep -q "hmac"; then
    echo "✅ Clé HMAC fonctionnelle"
else
    echo "❌ Problème avec la clé HMAC"
    exit 1
fi

echo "🎉 Vault est prêt !"
EOF
chmod +x "$BASE/scripts/check-vault.sh"

# 4. Script de déploiement
cat > "$BASE/scripts/deploy-k8s.sh" <<'EOF'
#!/bin/bash
set -e

ENV=${1:-dev}
NAMESPACE="otp-${ENV}"

echo "🚀 Déploiement sur Kubernetes/OpenShift (environnement: $ENV)..."

# Vérifier si on est sur OpenShift
if command -v oc &> /dev/null; then
    echo "📌 OpenShift détecté"
    CMD="oc"
else
    echo "📌 Kubernetes détecté"
    CMD="kubectl"
fi

# Appliquer les manifests
echo "📦 Application des manifests..."
$CMD apply -k ${BASE}/k8s/overlays/${ENV}

# Attendre le déploiement
echo "⏳ Attente du déploiement..."
$CMD rollout status deployment/otp-auth-service -n ${NAMESPACE} --timeout=300s

# Afficher les endpoints
if [ "$ENV" = "dev" ] && [ "$CMD" = "oc" ]; then
    ROUTE=$($CMD get route otp-auth-service -n ${NAMESPACE} -o jsonpath='{.spec.host}')
    echo "🌐 Route: https://${ROUTE}"
fi

echo "✅ Déploiement terminé !"
EOF

chmod +x "$BASE/scripts/deploy-k8s.sh"

# 5. Script de test après déploiement
cat > "$BASE/scripts/test-k8s.sh" <<'EOF'
#!/bin/bash
set -e

ENV=${1:-dev}
NAMESPACE="otp-${ENV}"

echo "🧪 Test du service déployé sur $ENV..."

# Récupérer l'URL
if command -v oc &> /dev/null; then
    URL="https://$(oc get route otp-auth-service -n ${NAMESPACE} -o jsonpath='{.spec.host}')"
else
    # Pour Kubernetes, utiliser le port-forward
    echo "📌 Utilisation du port-forward..."
    kubectl port-forward -n ${NAMESPACE} svc/otp-auth-service 8080:8080 &
    PF_PID=$!
    sleep 3
    URL="http://localhost:8080"
fi

# Tester l'API
echo "📱 Test de l'API..."

# 1. Health check
echo -n "Health check: "
curl -s ${URL}/actuator/health | jq .status

# 2. Demander un OTP
echo "Demande d'OTP:"
RESPONSE=$(curl -s -X POST ${URL}/auth/register/start \
  -H "Content-Type: application/json" \
  -d '{"phone":"+221771234567"}')
echo $RESPONSE | jq .

CHALLENGE_ID=$(echo $RESPONSE | jq -r .challengeId)

# 3. Vérifier l'OTP (code factice pour test)
echo "Vérification d'OTP:"
curl -s -X POST ${URL}/auth/register/verify \
  -H "Content-Type: application/json" \
  -d "{\"challengeId\":\"$CHALLENGE_ID\",\"code\":\"123456\"}" | jq .

# Nettoyer le port-forward si nécessaire
if [ -n "${PF_PID:-}" ]; then
    kill $PF_PID 2>/dev/null || true
fi

echo "✅ Test terminé !"
EOF
chmod +x "$BASE/scripts/test-k8s.sh"

# README
cat > "$BASE/README.md" <<'EOF'
# OTP Auth Service

Service d'authentification par OTP avec Vault et SMSEAGLE.

## Architecture

- **Backend**: Spring Boot 3.2.5
- **Stockage OTP**: Redis
- **HMAC**: Vault Transit (via API REST)
- **Notifications**: SMSEAGLE (SMS) / SMTP (Email)

## Prérequis

- Java 21
- Docker & Docker Compose
- Maven

## Démarrage rapide

```bash
# Démarrer tous les services
./scripts/start-dev.sh

# Tester l'API
./scripts/test-api.sh

# Vérifier Vault
./scripts/check-vault.sh

## Déploiement Kubernetes/OpenShift

### Prérequis
- kubectl ou oc (OpenShift CLI)
- Accès à un cluster Kubernetes/OpenShift

### Déploiement

```bash
# Déploiement en développement
./scripts/deploy-k8s.sh dev

# Déploiement en production
./scripts/deploy-k8s.sh prod
```

EOF
