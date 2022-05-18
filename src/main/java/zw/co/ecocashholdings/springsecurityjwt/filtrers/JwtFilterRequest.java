package zw.co.ecocashholdings.springsecurityjwt.filtrers;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import zw.co.ecocashholdings.springsecurityjwt.JwtUtil;
import zw.co.ecocashholdings.springsecurityjwt.MyUserServiceDetails;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Component
public class JwtFilterRequest extends OncePerRequestFilter {
    @Autowired
    private MyUserServiceDetails myUserServiceDetails;

    @Autowired
    private JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authorizatioHeader = request.getHeader("Authorization");
    String username=null;
    String jwt=null;

    if(authorizatioHeader!=null && authorizatioHeader.startsWith("Bearer ")){
        jwt=authorizatioHeader.substring(7);
        username=jwtUtil.extractUserName(jwt);
    }

    if(username!=null && SecurityContextHolder.getContext().getAuthentication()==null){
        UserDetails userDetails=this.myUserServiceDetails.loadUserByUsername(username);
        if(jwtUtil.validateToken(jwt,userDetails)){
            UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken=new UsernamePasswordAuthenticationToken(
                    userDetails,null,userDetails.getAuthorities()
            );
            usernamePasswordAuthenticationToken
                    .setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
            SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        }
    }
        filterChain.doFilter(request,response);
    }
}
