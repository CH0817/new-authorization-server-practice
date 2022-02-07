package tw.com.rex.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import static org.springframework.security.config.Customizer.withDefaults;

@EnableWebSecurity
public class SecurityConfig {

    @Bean
    SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http.headers().frameOptions().sameOrigin().and()
            .csrf().ignoringAntMatchers("/h2-console/**").and()
            .authorizeRequests().antMatchers("/h2-console/**").permitAll().and()
            .authorizeRequests().anyRequest().authenticated().and()
            .formLogin(withDefaults());
        return http.build();
    }

    @Bean
    UserDetailsService users() {
        UserDetails user = User.withDefaultPasswordEncoder()
                               .username("rex")
                               .password("1")
                               .roles("USER")
                               .build();
        return new InMemoryUserDetailsManager(user);
    }

}
