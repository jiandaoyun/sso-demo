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

import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotBlank;
import java.io.IOException;
import java.net.URI;
import java.util.Calendar;
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
    @Getter @Setter private String logoutReturnUrl;
    @Getter @Setter @NotBlank private String issuer;
    @Getter @Setter @NotBlank private String username;
    @Getter @Setter @NotBlank private String secret;
}

@Service
@NoArgsConstructor
@AllArgsConstructor
class SSOService {
    @Getter @Setter @Autowired private SSOConfig ssoConfig;

    // 演示用的 IdP 会话记录，进程重启后清空。
    private final ConcurrentMap<String, String> sessions = new ConcurrentHashMap<>();

    private DecodedJWT verifyRequest(String request, Algorithm algorithm) {
        JWTVerifier verifier = JWT.require(algorithm)
            .withIssuer("com.jiandaoyun")
            // 简道云中未配置 Issuer URL 时，注释以下一行
            .withAudience(this.ssoConfig.getIssuer())
            .build();
        return verifier.verify(request);
    }

    public String getResponse(String request) {
        // 与简道云中配置的 认证加密算法 保持一致
        Algorithm algorithm = Algorithm.HMAC256(this.ssoConfig.getSecret());
        DecodedJWT decoded = verifyRequest(request, algorithm);
        if (!"sso_req".equals(decoded.getClaim("type").asString())) {
            return "";
        }
        String sessionId = UUID.randomUUID().toString();
        String username = this.ssoConfig.getUsername();
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.add(Calendar.HOUR_OF_DAY, 1);
        String response = JWT.create()
            .withClaim("type", "sso_res")
            .withClaim("username", username)
            // 简道云中未配置 Issuer URL 时，注释以下一行
            .withIssuer(this.ssoConfig.getIssuer())
            .withAudience("com.jiandaoyun")
            .withExpiresAt(calendar.getTime())
            // 简道云将 jti 记录为会话索引，并在单点登出时传回。
            .withJWTId(sessionId)
            .sign(algorithm);
        sessions.put(sessionId, username.trim());
        return response;
    }

    public void logout(String request) {
        // 校验登出请求。
        Algorithm algorithm = Algorithm.HMAC256(this.ssoConfig.getSecret());
        DecodedJWT decoded = verifyRequest(request, algorithm);
        if (!"slo_req".equals(decoded.getClaim("type").asString())) {
            throw new IllegalArgumentException("Wrong request type.");
        }
        String index = decoded.getClaim("index").asString();
        if (index == null) {
            return;
        }
        String nameId = decoded.getClaim("nameId").asString();
        // 清除会话。
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
    void authn(
        @RequestParam(name = "request", defaultValue = "") String request,
        @RequestParam(name = "state", defaultValue = "") String state,
        HttpServletResponse httpServletResponse
    ) throws IOException {
        String response = this.ssoService.getResponse(request);
        httpServletResponse.sendRedirect(
            String.format(
                "%s?response=%s&state=%s",
                this.ssoConfig.getAcs(), response, state
            )
        );
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

        // 示例只做 URL 基本校验。redirect_uri 不在 JWT 签名范围内。
        // 实际接入时只跳转到预先配置的可信地址，避免开放重定向。详见 custom/README.md 的「跳转校验提醒」。
        List<String> redirects = query.get("redirect_uri");
        try {
            if (redirects != null && redirects.size() != 1) {
                throw new IllegalArgumentException("Expected one redirect URI.");
            }
            String redirectUri = redirects == null ? ssoConfig.getLogoutReturnUrl() : redirects.get(0);
            if (redirectUri == null) {
                throw new IllegalArgumentException("Missing redirect URI.");
            }
            URI target = URI.create(redirectUri);
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
