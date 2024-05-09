package com.ibm.security.appscan.altoromutual.filter;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import com.ibm.security.appscan.altoromutual.model.User;
import com.ibm.security.appscan.altoromutual.model.User.Role;
import com.ibm.security.appscan.altoromutual.util.ServletUtil;

import java.io.IOException;

/**d
 * This filter class controls access to administrator sections of the application  
 */
public class AdminFilter implements Filter {

	public void init(FilterConfig arg0) throws ServletException {
		// do nothing
	}

	public void doFilter(ServletRequest req, ServletResponse resp, FilterChain chain) throws IOException, ServletException {
		if (req instanceof HttpServletRequest){
			HttpServletRequest request = (HttpServletRequest)req;
			HttpServletResponse response = (HttpServletResponse)resp;

			Object user = request.getSession().getAttribute(ServletUtil.SESSION_ATTR_USER);

			// Check if the user is logged in and is an admin
			if (user != null && user instanceof User && ((User) user).getRole() == Role.Admin) {
				chain.doFilter(req, resp); // Allow access to admin page
			} else {
				// Redirect unauthorized users to an error page or login page
				response.sendRedirect(request.getContextPath() + "/error.jsp");
			}
		}
	}

	public void destroy() {
		// do nothing
	}
}
