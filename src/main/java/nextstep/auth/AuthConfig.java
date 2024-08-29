package nextstep.auth;

import nextstep.auth.application.JwtTokenProvider;
import nextstep.auth.application.OAuthService;
import nextstep.auth.domain.OAuthProvider;
import nextstep.auth.ui.AuthenticationPrincipalArgumentResolver;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;

@Configuration
public class AuthConfig implements WebMvcConfigurer {
    private JwtTokenProvider jwtTokenProvider;

    public AuthConfig(JwtTokenProvider jwtTokenProvider) {
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public void addArgumentResolvers(List argumentResolvers) {
        argumentResolvers.add(new AuthenticationPrincipalArgumentResolver(jwtTokenProvider));
    }

    /**
     * OAuthService 구현체들을 Map 형태로 제공하는 빈 등록
     * @param oAuthServices
     * @return
     */
    @Bean
    public Map<OAuthProvider, OAuthService> oAuthServices(List<OAuthService> oAuthServices) {
        return oAuthServices.stream()
                .collect(Collectors.toMap(OAuthService::getImplementsProvider, Function.identity()));
    }
}
