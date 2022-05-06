package com.jiandaoyun.demo.sso;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
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
import org.springframework.stereotype.Controller;
import org.springframework.stereotype.Service;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletResponse;
import javax.validation.constraints.NotBlank;
import java.io.IOException;
import java.util.Calendar;
import java.util.Date;

@Configuration
@ConfigurationProperties(prefix = "sso")
@NoArgsConstructor
@AllArgsConstructor
@Validated
class SSOConfig {
    @Getter @Setter @NotBlank private String acs;
    @Getter @Setter @NotBlank private String issuer;
    @Getter @Setter @NotBlank private String username;
    @Getter @Setter @NotBlank private String secret;
}

@Service
@NoArgsConstructor
@AllArgsConstructor
class SSOService {
    @Getter @Setter @Autowired private SSOConfig ssoConfig;

    public String getResponse(String request) {
        Algorithm algorithm = Algorithm.HMAC256(this.ssoConfig.getSecret());
        JWTVerifier verifier = JWT.require(algorithm)
            .withIssuer("com.jiandaoyun")
            .withAudience(this.ssoConfig.getIssuer())
            .build();
        DecodedJWT decoded = verifier.verify(request);
        if (!"sso_req".equals(decoded.getClaim("type").asString())) {
            return "";
        }
        Calendar calendar = Calendar.getInstance();
        calendar.setTime(new Date());
        calendar.add(Calendar.HOUR_OF_DAY, 1);
        return JWT.create()
            .withClaim("type", "sso_res")
            .withClaim("username", this.ssoConfig.getUsername())
            .withIssuer(this.ssoConfig.getIssuer())
            .withAudience("com.jiandaoyun")
            .withExpiresAt(calendar.getTime())
            .sign(algorithm);
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
}

@SpringBootApplication
public class SSOApplication {
    public static void main(String[] args) {
        SpringApplication.run(SSOApplication.class, args);
    }
}
