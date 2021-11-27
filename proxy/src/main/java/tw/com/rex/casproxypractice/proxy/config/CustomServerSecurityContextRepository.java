package tw.com.rex.casproxypractice.proxy.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.web.server.context.ServerSecurityContextRepository;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

@Component
public class CustomServerSecurityContextRepository implements ServerSecurityContextRepository {

    @Autowired
    private CustomAuthenticationManager authenticationManager;

    @Override
    public Mono<Void> save(ServerWebExchange serverWebExchange, SecurityContext securityContext) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

    @Override
    public Mono<SecurityContext> load(ServerWebExchange serverWebExchange) {
        Authentication auth = new UsernamePasswordAuthenticationToken("", "");
        SecurityContext securityContext = new SecurityContext() {
            @Override
            public Authentication getAuthentication() {
                return authenticationManager.authenticate(auth).block();
            }

            @Override
            public void setAuthentication(Authentication authentication) {

            }
        };
        return Mono.justOrEmpty(securityContext);
    }

}
