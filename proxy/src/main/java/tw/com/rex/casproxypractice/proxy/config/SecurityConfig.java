package tw.com.rex.casproxypractice.proxy.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import reactor.core.publisher.Mono;

@Configuration
public class SecurityConfig {

    @Autowired
    private CustomAuthenticationManager authenticationManager;
    @Autowired
    private CustomServerSecurityContextRepository securityContextRepository;

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http.exceptionHandling()
                   .authenticationEntryPoint((swe, e) ->
                                                     Mono.fromRunnable(() -> swe.getResponse()
                                                                                .setStatusCode(HttpStatus.UNAUTHORIZED))
                   )
                   .accessDeniedHandler((swe, e) ->
                                                Mono.fromRunnable(() -> swe.getResponse()
                                                                           .setStatusCode(HttpStatus.FORBIDDEN))
                   )
                   .and()
                   .cors()
                   .disable()
                   .csrf()
                   .disable()
                   .formLogin()
                   .disable()
                   .httpBasic()
                   .disable()
                   .authenticationManager(authenticationManager)
                   .securityContextRepository(securityContextRepository)
                   .authorizeExchange(e -> e.anyExchange().authenticated())
                   .build();
    }

}
