/**
*
* Crowd username-password authentication plugin for Graylog
*
* Copyright (C) 2018 University Of Helsinki (The National Library Of Finland)
*
* This file is part of graylog-plugin-auth-crowd-userpass
*
* graylog-plugin-auth-crowd-userpass program is free software: you can redistribute it and/or modify
* it under the terms of the GNU General Public License as
* published by the Free Software Foundation, either version 3 of the
* License, or (at your option) any later version.
*
* graylog-plugin-auth-crowd-userpass is distributed in the hope that it will be useful,
* but WITHOUT ANY WARRANTY; without even the implied warranty of
* MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
* GNU General Public License for more details.
*
* You should have received a copy of the GNU eneral Public License
* along with this program.  If not, see <http://www.gnu.org/licenses/>.
*
*/
package org.graylog.plugins.auth.crowd.userpass;

import com.google.common.annotations.VisibleForTesting;
import com.google.common.base.Joiner;
import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authc.SimpleAccount;
import org.apache.shiro.authc.credential.AllowAllCredentialsMatcher;
import org.apache.shiro.realm.AuthenticatingRealm;
import org.graylog2.database.NotFoundException;
import org.graylog2.plugin.cluster.ClusterConfigService;
import org.graylog2.plugin.database.ValidationException;
import org.graylog2.plugin.database.users.User;
import org.graylog2.security.realm.LdapUserAuthenticator;
import org.graylog2.shared.security.ShiroSecurityContext;
import org.graylog2.shared.users.Role;
import org.graylog2.shared.users.UserService;
import org.graylog2.users.RoleService;
import org.graylog2.users.RoleImpl;
import org.graylog2.utilities.IpSubnet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.annotation.Nullable;
import javax.inject.Inject;
import javax.inject.Named;
import javax.ws.rs.core.MultivaluedMap;
import java.net.UnknownHostException;
import java.util.Collections;
import java.util.Optional;
import java.util.HashSet;
import java.util.Set;
import java.util.Map;
import java.io.IOException;

public class CrowdAuthRealm extends AuthenticatingRealm {
  private static final Logger LOG = LoggerFactory.getLogger(CrowdAuthRealm.class);

  public static final String NAME = "crowd-userpass";

  private final UserService userService;
  private final ClusterConfigService clusterConfigService;
  private final RoleService roleService;

  @Inject
  public CrowdAuthRealm(UserService userService,
  ClusterConfigService clusterConfigService,
  RoleService roleService) {
    this.userService = userService;
    this.clusterConfigService = clusterConfigService;
    this.roleService = roleService;
    setCredentialsMatcher(new AllowAllCredentialsMatcher());
    setCachingEnabled(false);
  }

  @Override
  protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
    UsernamePasswordToken credentialsToken = (UsernamePasswordToken) token;
    final CrowdAuthConfig config = clusterConfigService.getOrDefault(
    CrowdAuthConfig.class,
    CrowdAuthConfig.defaultConfig());

    final CrowdApi crowdApi = new CrowdApi(
      config.apiUrl(),
      config.applicationName(),
      config.applicationPassword(),
      config.apiVerifyCert()
    );

    try {
      Map<String, String> userDetails = crowdApi.authenticateUser(credentialsToken.getUsername(), new String(credentialsToken.getPassword()));
      User user = userService.load(credentialsToken.getUsername());

      if (user == null) {
        if (config.autoCreateUser()) {
          user = userService.create();
          user.setName(credentialsToken.getUsername());
          user.setExternal(true);
          user.setPermissions(Collections.emptyList());
          user.setPassword("dummy password");
          user.setFullName(userDetails.get("display-name"));
          user.setEmail(userDetails.get("email"));
        }
      }

      if (user == null) {
        LOG.trace(
        "No user named {} found and automatic user creation is disabled",
        credentialsToken.getUsername()
        );
        return null;
      } else {
        if (config.autoCreateRole()) {
          Set<String> roleIds = new HashSet<String>();
          Set<String> groups = crowdApi.getUserGroups(credentialsToken.getUsername());

          for (String group : groups) {
            Role role;

            if (roleService.exists(group)) {
              role = roleService.load(group);
            } else {
              Set<String> permissions = new HashSet<String>(1);
              role = new RoleImpl();

              permissions.add("reader");

              role.setName(group);
              role.setPermissions(permissions);
              roleService.save(role);
            }

            roleIds.add(role.getId());
          }

          user.setRoleIds(roleIds);
        }

        userService.save(user);
        ShiroSecurityContext.requestSessionCreation(true);
        return new SimpleAccount(user.getName(), null, "crowd");
      }
    } catch (CrowdApiException e) {
      LOG.error(
      "Crowd API call failed: {}",
      e.getMessage()
      );
      return null;
    } catch (NotFoundException e) {
      LOG.error("Role not found: {}", e.getMessage());
      return null;
    } catch (ValidationException e) {
      LOG.error("Validation failed {}", e.toString());
      return null;
    } catch (IOException e) {
      LOG.error("I/O error: {}", e.getMessage());
      return null;
    }
  }

  private Optional<String> headerValue(MultivaluedMap<String, String> headers, @Nullable String headerName) {
    if (headerName == null) {
      return Optional.empty();
    }
    return Optional.ofNullable(headers.getFirst(headerName.toLowerCase()));
  }

}
