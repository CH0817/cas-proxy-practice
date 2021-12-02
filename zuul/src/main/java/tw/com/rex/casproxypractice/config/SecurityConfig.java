package tw.com.rex.casproxypractice.config;

import com.sun.xml.internal.bind.v2.TODO;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorage;
import org.jasig.cas.client.proxy.ProxyGrantingTicketStorageImpl;
import org.jasig.cas.client.session.SingleSignOutFilter;
import org.jasig.cas.client.validation.Cas20ProxyTicketValidator;
import org.jasig.cas.client.validation.TicketValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.cas.ServiceProperties;
import org.springframework.security.cas.authentication.CasAssertionAuthenticationToken;
import org.springframework.security.cas.authentication.CasAuthenticationProvider;
import org.springframework.security.cas.web.CasAuthenticationEntryPoint;
import org.springframework.security.cas.web.CasAuthenticationFilter;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.AuthenticationUserDetailsService;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import javax.servlet.Filter;
import java.util.Arrays;
import java.util.Collections;

@RequiredArgsConstructor
@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    @NonNull
    private AuthenticationUserDetailsService<CasAssertionAuthenticationToken> userDetailsService;
    @Value("${server.port}")
    private String port;
    @Value("${server.servlet.context-path}")
    private String contextPath;

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(casAuthenticationProvider());
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
            .cors().configurationSource(corsConfigurationSource()).and()
            .authorizeRequests().antMatchers("/actuator/prometheus").permitAll().and()
            .authorizeRequests().anyRequest().authenticated().and()
            .exceptionHandling().authenticationEntryPoint(casAuthenticationEntryPoint()).and()
            .addFilter(casAuthenticationFilter())
            .addFilterBefore(casLogoutFilter(), LogoutFilter.class)
            .addFilterBefore(singleSignOutFilter(), CasAuthenticationFilter.class);
    }

    @Override
    public void configure(WebSecurity web) {
        web.ignoring().antMatchers("/js/**", "webjars/**");
    }

    private CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // 允許跨域請求的 client url
        configuration.setAllowedOrigins(Arrays.asList("http://localhost:8110",
                                                      "http://localhost:8120",
                                                      "http://localhost:8200",
                                                      "http://localhost:8300"));
        // 允許跨域請求的 method
        configuration.setAllowedMethods(Collections.singletonList("*"));
        // 允許跨域請求的 header
        configuration.setAllowedHeaders(Collections.singletonList("*"));
        // 是否允許請求帶有驗證訊息
        configuration.setAllowCredentials(true);
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }

    // @Bean
    // public AuthenticationProvider casAuthenticationProvider() {
    //     CasAuthenticationProvider provider = new CasAuthenticationProvider();
    //     provider.setAuthenticationUserDetailsService(userDetailsService);
    //     provider.setServiceProperties(serviceProperties());
    //     provider.setTicketValidator(ticketValidator());
    //     provider.setKey("SPRING_BOOT_TEMPLATE_KEY");
    //     return provider;
    // }

    @Bean
    public ServiceProperties serviceProperties() {
        ServiceProperties properties = new ServiceProperties();
        // APP 本身的 CAS login URL，/login/cas 是預設值，可參考 CasAuthenticationFilter
        properties.setService("http://localhost:" + port + contextPath + "/login/cas");
        properties.setSendRenew(false);
        return properties;
    }

    // @Bean
    // public TicketValidator ticketValidator() {
    //     // CAS server URL
    //     return new Cas20ProxyTicketValidator("http://localhost:8080/cas");
    // }

    @Bean
    public AuthenticationEntryPoint casAuthenticationEntryPoint() {
        CasAuthenticationEntryPoint entryPoint = new CasAuthenticationEntryPoint();
        // CAS login URL
        entryPoint.setLoginUrl("http://localhost:8080/cas/login");
        entryPoint.setServiceProperties(serviceProperties());
        return entryPoint;
    }

    @Bean
    public Filter casAuthenticationFilter() throws Exception {
        CasAuthenticationFilter filter = new CasAuthenticationFilter();
        filter.setAuthenticationManager(authenticationManager());
        filter.setAuthenticationManager(new ProviderManager(casAuthenticationProvider()));
        // TODO
        filter.setProxyGrantingTicketStorage(proxyGrantingTicketStorage());
        // TODO
        filter.setProxyReceptorUrl("");
        return filter;
    }

    @Bean
    public LogoutFilter casLogoutFilter() {
        // CAS logout，service 參數是 CAS 成功登出後要轉跳的 URL
        return new LogoutFilter("http://localhost:8080/cas/logout?service=http://localhost:" + port + contextPath,
                                new SecurityContextLogoutHandler());
    }

    @Bean
    public SingleSignOutFilter singleSignOutFilter() {
        SingleSignOutFilter filter = new SingleSignOutFilter();
        filter.setIgnoreInitConfiguration(true);
        return filter;
    }

    // TODO
    @Bean
    public ProxyGrantingTicketStorage proxyGrantingTicketStorage() {
        return new ProxyGrantingTicketStorageImpl();
    }

    @Bean
    public AuthenticationProvider casAuthenticationProvider(){
        return new CasAuthenticationProvider();
    }

    public TicketValidator casTicketValidator(){
        Cas20ProxyTicketValidator ticketValidator = new Cas20ProxyTicketValidator("http://localhost:8080/cas");
        // TODO
        ticketValidator.setProxyCallbackUrl("");
        ticketValidator.setProxyGrantingTicketStorage(proxyGrantingTicketStorage());
        return ticketValidator;
    }

}
