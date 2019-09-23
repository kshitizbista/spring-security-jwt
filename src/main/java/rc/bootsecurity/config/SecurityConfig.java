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
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
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
                .formLogin()
                .loginProcessingUrl("/signin") // if method not used, the post action of form login should contain "/login" (default) url.
                .loginPage("/login").permitAll()  // redirects to "/login" url
                .usernameParameter("txtUsername") // if method not used, form control should be "username" (default).
                .passwordParameter("txtPassword") // if method not used, form control should be "password" (default).
                .and()
                .logout()
                .logoutRequestMatcher(new AntPathRequestMatcher("/logout"))
                .logoutSuccessUrl("/login")
                .and()
                .rememberMe()
                .rememberMeParameter("checkRememberMe") // if method not used, form control should be "remember-me" (default).
                .tokenValiditySeconds(2592000) //cookie expires after 30 days
                .key("unique") // if method not used, defaults t]is randomly generated value
                .userDetailsService(this.userPrincipalDetailService); // used to look up the UserDetails when a remember me token is valid


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
