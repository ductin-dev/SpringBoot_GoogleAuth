package stackjava.com.sbgoogle.controller;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.servlet.http.HttpServletRequest;

import org.apache.http.client.ClientProtocolException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import stackjava.com.sbgoogle.common.GooglePojo;
import stackjava.com.sbgoogle.common.GoogleUtils;

@Controller
public class BaseController {

    @Autowired
    private GoogleUtils googleUtils;

    @RequestMapping(value = {"/", "/login"})
    public String login() {
        return "login";
    }

    @RequestMapping("/login-google")
    public String loginGoogle(HttpServletRequest request) throws ClientProtocolException, IOException {
        String code = request.getParameter("code");

        if (code == null || code.isEmpty()) {
            return "redirect:/login?google=error";
        }

        String accessToken = googleUtils.getToken(code);

        GooglePojo googlePojo = googleUtils.getUserInfo(accessToken);
        UserDetails userDetail = googleUtils.buildUser(googlePojo);

        //GMAIL ADMIN
        if (googlePojo.getEmail().equals("doanductin8122000@gmail.com")) {
            UserDetails userDetailAdmin = new UserDetails() {
                @Override
                public Collection<? extends GrantedAuthority> getAuthorities() {
                    List<GrantedAuthority> list = new ArrayList<>();
                    list.add(new SimpleGrantedAuthority("ROLE_ADMIN"));
                    return list;
                }

                @Override
                public String getPassword() {
                    return userDetail.getPassword();
                }

                @Override
                public String getUsername() {
                    return userDetail.getUsername();
                }

                @Override
                public boolean isAccountNonExpired() {
                    return userDetail.isAccountNonExpired();
                }

                @Override
                public boolean isAccountNonLocked() {
                    return userDetail.isAccountNonLocked();
                }

                @Override
                public boolean isCredentialsNonExpired() {
                    return userDetail.isCredentialsNonExpired();
                }

                @Override
                public boolean isEnabled() {
                    return userDetail.isEnabled();
                }
            };
            UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetailAdmin, null,
                    userDetailAdmin.getAuthorities());
            authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            return "redirect:/user";
        }

        //NON-ADMIN
        UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(userDetail, null,
                userDetail.getAuthorities());
        authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        return "redirect:/user";
    }

    @RequestMapping("/user")
    public String user() {
        return "user";
    }

    @RequestMapping("/admin")
    public String admin() {
        return "admin";
    }

}
