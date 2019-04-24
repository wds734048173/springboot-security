package org.lanqiao.springbootsecurity.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

public class SecurityConfig extends WebSecurityConfigurerAdapter {
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        //权限判断
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/*").hasRole("VIP1")
                .antMatchers("/level2/*").hasRole("VIP2")
                .antMatchers("/level3/*").hasRole("VIP3");
        //用户认证
        http.formLogin();
    }

    @Autowired
    public void configureGlobal(AuthenticationManagerBuilder auth) throws Exception {
        auth
                .inMemoryAuthentication()
                .withUser("admin1").password("123456").roles("VIP1","VIP2")
                .and()
                .withUser("admin2").password("123456").roles("VIP2","VIP3")
                .and()
                .withUser("admin3").password("123456").roles("VIP3","VIP1");
    }

}
