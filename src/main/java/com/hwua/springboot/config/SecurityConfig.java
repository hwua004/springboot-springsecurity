package com.hwua.springboot.config;

import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;

@EnableWebSecurity
public class SecurityConfig  extends WebSecurityConfigurerAdapter {
    //指定权限规则
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.authorizeRequests().antMatchers("/").permitAll()
                .antMatchers("/level1/**").hasRole("VIP1")
                .antMatchers("/level2/**").hasRole("VIP2")
                .antMatchers("/level3/**").hasRole("VIP3");
        //在没有登录的情况下，访问某一个被保护的资源，就会跳向登录页面
        //loginPage可以定制自己的登录页
        http.formLogin().loginPage("/userlogin").usernameParameter("uname")
        .passwordParameter("pwd").loginProcessingUrl("/uulogin");
        //设置退出选项
        http.logout().logoutSuccessUrl("/");
    }
    //


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser("admin").password("123456").roles("VIP1","VIP2","VIP3")
                .and().withUser("zhangsan").password("123456").roles("VIP1","VIP2")
                .and().withUser("lisi").password("123456").roles("VIP2","VIP3");
    }
}
