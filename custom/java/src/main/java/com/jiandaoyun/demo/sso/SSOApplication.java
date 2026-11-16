package com.jiandaoyun.demo.sso;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTVerificationException;
import com.auth0.jwt.interfaces.DecodedJWT;
import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.CacheControl;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.util.MultiValueMap;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.util.UriComponentsBuilder;

import javax.validation.constraints.NotBlank;
import java.net.URI;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

@Configuration
@ConfigurationProperties(prefix = "sso")
@NoArgsConstructor
@AllArgsConstructor
@Validated
class SSOConfig {
    @Getter @Setter @NotBlank private String acs;
    @Getter @Setter @NotBlank private String logoutReturnUrl;
    @Getter @Setter @NotBlank private String issuer;
    @Getter @Setter @NotBlank private String username;
    @Getter @Setter @NotBlank private String secret;
    @Getter @Setter @NotBlank private String algorithm = "HS256";
}

@Service
@NoArgsConstructor
@AllArgsConstructor
class SSOService {
    private static final String SP_ISSUER = "com.jiandaoyun";
    private static final long CLOCK_TOLERANCE_SECONDS = 3600;

    @Getter @Setter @Autowired private SSOConfig ssoConfig;

    // 演示用的 IdP 会话记录，进程重启后清空。
    private final ConcurrentMap<String, String> sessions = new ConcurrentHashMap<>();

    private Algorithm hmacAlgorithm(String name) {
        if (name == null) {
            throw new IllegalArgumentException("Missing JWT algorithm.");
        }
        String secret = ssoConfig.getSecret();
        return switch (name) {
            case "HS256" -> Algorithm.HMAC256(secret);
            case "HS384" -> Algorithm.HMAC384(secret);
            case "HS512" -> Algorithm.HMAC512(secret);
            default -> throw new IllegalArgumentException("Unsupported JWT algorithm.");
        };
    }

    private DecodedJWT verifyRequest(String request, String type) {
        DecodedJWT decoded = JWT.decode(request);
        JWTVerifier verifier = JWT.require(hmacAlgorithm(decoded.getAlgorithm()))
            .withIssuer(SP_ISSUER)
            // 简道云中未配置 Issuer URL 时，注释以下一行
            .withAudience(ssoConfig.getIssuer())
            .withClaim("type", type)
            .acceptLeeway(CLOCK_TOLERANCE_SECONDS)
            .ignoreIssuedAt()
            .build();
        return verifier.verify(decoded);
    }

    public String getResponse(String request) {
        verifyRequest(request, "sso_req");
        String sessionId = UUID.randomUUID().toString();
        String username = ssoConfig.getUsername();
        Instant now = Instant.now();
        String response = JWT.create()
            .withClaim("type", "sso_res")
            .withClaim("username", username)
            // 简道云中未配置 Issuer URL 时，注释以下一行
            .withIssuer(ssoConfig.getIssuer())
            .withAudience(SP_ISSUER)
            .withIssuedAt(Date.from(now))
            .withExpiresAt(Date.from(now.plus(1, ChronoUnit.HOURS)))
            .withJWTId(sessionId)
            .sign(hmacAlgorithm(ssoConfig.getAlgorithm()));
        sessions.put(sessionId, username.trim());
        return response;
    }

    public void logout(String request) {
        DecodedJWT decoded = verifyRequest(request, "slo_req");
        if (decoded.getExpiresAt() == null) {
            throw new IllegalArgumentException("Missing expiration.");
        }
        String index = decoded.getClaim("index").asString();
        if (index == null) {
            return;
        }
        String nameId = decoded.getClaim("nameId").asString();
        // 已清理或进程重启过时，不会影响其他会话。
        sessions.computeIfPresent(index, (key, username) -> {
            if (!username.equals(nameId)) {
                throw new IllegalArgumentException("Session member does not match.");
            }
            return null;
        });
    }
}

@Controller
@NoArgsConstructor
@AllArgsConstructor
class SSOController {
    @Getter @Setter @Autowired private SSOConfig ssoConfig;
    @Getter @Setter @Autowired private SSOService ssoService;

    @GetMapping("/sso")
    ResponseEntity<String> authn(
        @RequestParam(name = "request", defaultValue = "") String request,
        @RequestParam(name = "state", defaultValue = "") String state
    ) {
        try {
            String response = ssoService.getResponse(request);
            URI callback = UriComponentsBuilder.fromUriString(ssoConfig.getAcs())
                .queryParam("response", "{response}")
                .queryParam("state", "{state}")
                .encode()
                .buildAndExpand(response, state)
                .toUri();
            return ResponseEntity.status(HttpStatus.FOUND).location(callback).build();
        } catch (JWTVerificationException | IllegalArgumentException exception) {
            return ResponseEntity.badRequest().body("Bad Request.");
        }
    }

    @GetMapping("/logout")
    ResponseEntity<String> logout(@RequestParam MultiValueMap<String, String> query) {
        List<String> requests = query.get("request");
        try {
            if (requests == null || requests.size() != 1) {
                throw new IllegalArgumentException("Expected one logout request.");
            }
            ssoService.logout(requests.get(0));
        } catch (JWTVerificationException | IllegalArgumentException exception) {
            return invalidLogout("无效的单点登出请求。");
        }

        List<String> redirects = query.get("redirect_uri");
        try {
            if (redirects != null && redirects.size() != 1) {
                throw new IllegalArgumentException("Expected one redirect URI.");
            }
            URI target = URI.create(redirects == null ? ssoConfig.getLogoutReturnUrl() : redirects.get(0));
            String scheme = target.getScheme();
            if ((!"http".equalsIgnoreCase(scheme) && !"https".equalsIgnoreCase(scheme))
                    || target.getHost() == null || target.getRawUserInfo() != null) {
                throw new IllegalArgumentException("Invalid redirect URI.");
            }
            return ResponseEntity.status(HttpStatus.SEE_OTHER).cacheControl(CacheControl.noStore())
                .location(target).build();
        } catch (IllegalArgumentException exception) {
            return invalidLogout("无效的登出返回地址。");
        }
    }

    private ResponseEntity<String> invalidLogout(String message) {
        return ResponseEntity.badRequest().cacheControl(CacheControl.noStore()).body(message);
    }
}

@SpringBootApplication
public class SSOApplication {
    public static void main(String[] args) {
        SpringApplication.run(SSOApplication.class, args);
    }
}
