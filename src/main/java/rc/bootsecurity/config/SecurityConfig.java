package rc.bootsecurity.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import rc.bootsecurity.services.UserPrincipalDetailService;

@Configuration
@EnableWebSecurity
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    private final UserPrincipalDetailService userPrincipalDetailService;

    public SecurityConfig(UserPrincipalDetailService userPrincipalDetailService) {
        this.userPrincipalDetailService = userPrincipalDetailService;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) {
        auth.authenticationProvider(daoAuthenticationProvider());

        // for inmemory authentication (no need for database for storing users)
//        auth
//                .inMemoryAuthentication()
//                .withUser("admin")
//                .password(passwordEncoder().encode("admin"))
//                // .roles("ADMIN")  // in case role should be used with authorities , it should be defined within authorities method using 'ROLE_' prefix
//                .authorities("ACCESS_TEST1", "ACCESS_TEST2", "ROLE_ADMIN")
//                .and()
//                .withUser("kshitiz")
//                .password(passwordEncoder().encode("kshitiz"))
//                .roles("USER")
//                .and()
//                .withUser("manager")
//                .password(passwordEncoder().encode("manager"))
//                // .roles("MANAGER")
//                .authorities("ACCESS_TEST1", "ROLE_MANAGER");
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                //  .anyRequest().authenticated() // any request is available for authenticated user
                .antMatchers("/h2-console/*").permitAll()
                .antMatchers("/index.html").permitAll()
                .antMatchers("/profile/*").authenticated()
                .antMatchers("/admin/*").hasRole("ADMIN")
                .antMatchers("/management/*").hasAnyRole("ADMIN", "MANAGER")
                .antMatchers("/api/public/test1").hasAuthority("ACCESS_TEST1")
                .antMatchers("/api/public/test2").hasAuthority("ACCESS_TEST2")
                .antMatchers("/api/public/users").hasRole("ADMIN")
                .and()
                .httpBasic();

        //To enable access to the H2 database console under Spring Security you need to change three things
        //Allow all access to the url path /h2-console/*.
        //Disable CRSF (Cross-Site Request Forgery). By default, Spring Security will protect against CRSF attacks.
        //Since the H2 database console runs inside a frame, you need to enable this in in Spring Security.
        //Disable X-Frame-Options in Spring Security
        http.csrf().disable();
        http.headers().frameOptions().disable();
    }

    @Bean
    DaoAuthenticationProvider daoAuthenticationProvider() {
        DaoAuthenticationProvider daoAuthenticationProvider = new DaoAuthenticationProvider();
        daoAuthenticationProvider.setPasswordEncoder(passwordEncoder());
        daoAuthenticationProvider.setUserDetailsService(this.userPrincipalDetailService);
        return daoAuthenticationProvider;
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
